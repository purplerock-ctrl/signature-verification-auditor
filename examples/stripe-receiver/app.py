"""A small Stripe webhook receiver with two endpoints, for auditing with sigaudit.

    POST /webhook        verifies with Stripe's official library (correct)
    POST /webhook-naive  hand-written verification with two common mistakes

Run it:
    export STRIPE_WEBHOOK_SECRET=whsec_local_example_secret
    python app.py

It listens on 127.0.0.1:4242 only. (Port 5000 is avoided because macOS uses
it for AirPlay Receiver.) See README.md in this folder for the walkthrough.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from typing import Any

import stripe
from flask import Flask, Response, jsonify, request

DEFAULT_SECRET = "whsec_local_example_secret"  # noqa: S105 - local example only

log = logging.getLogger("receiver")


def handle_event(event: dict[str, Any], endpoint: str) -> None:
    """Stand-in for your business logic (fulfil an order, mark an invoice paid...).

    In a real app, reaching this function is what makes a forged event
    dangerous. Here it only logs, so you can find sigaudit's requests by
    searching the output for "evt_sigaudit_".
    """
    log.warning("[%s] PROCESSED event %s (type %s)", endpoint, event.get("id"), event.get("type"))


def create_app(secret: str) -> Flask:
    app = Flask(__name__)

    @app.post("/webhook")
    def webhook() -> tuple[Response, int]:
        """The correct way: let Stripe's library do all the checks."""
        payload = request.get_data()  # the raw bytes, exactly as received
        sig_header = request.headers.get("Stripe-Signature", "")
        try:
            # Checks the header format, the HMAC (constant-time) and the
            # timestamp tolerance (default 300 s). Raises on any problem.
            event = stripe.Webhook.construct_event(payload, sig_header, secret)
        except stripe.SignatureVerificationError:
            return jsonify(error="invalid signature"), 400
        except ValueError:
            return jsonify(error="invalid payload"), 400
        handle_event(event.to_dict(), "webhook")
        return jsonify(received=True), 200

    @app.post("/webhook-naive")
    def webhook_naive() -> tuple[Response, int]:
        """Hand-rolled verification, written the way it often is in real code.

        It looks reasonable and works for every genuine Stripe event, because
        genuine events are always correctly signed and fresh. sigaudit sends
        the requests that expose its two mistakes.
        """
        payload = request.get_data()
        sig_header = request.headers.get("Stripe-Signature")

        if sig_header:  # MISTAKE 1: no header (or an empty one) skips the check
            parts = dict(item.split("=", 1) for item in sig_header.split(","))
            signed = f"{parts['t']}.".encode() + payload
            expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, parts.get("v1", "")):
                return jsonify(error="invalid signature"), 400
            # MISTAKE 2: parts["t"] is signed, but never compared with the
            # current time, so an old captured event can be replayed forever.

        handle_event(json.loads(payload), "webhook-naive")
        return jsonify(received=True), 200

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    secret = os.environ.get("STRIPE_WEBHOOK_SECRET", DEFAULT_SECRET)
    if secret == DEFAULT_SECRET:
        log.warning("Using the built-in example secret (set STRIPE_WEBHOOK_SECRET to change it)")
    create_app(secret).run(host="127.0.0.1", port=4242)
