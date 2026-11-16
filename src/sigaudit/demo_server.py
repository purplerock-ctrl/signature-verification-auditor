"""A local webhook receiver with switchable, realistic verification bugs.

Used by the test suite and by ``sigaudit demo``. With no flaws it verifies
correctly; each :class:`Flaw` reproduces a mistake seen in real receivers.

The verification code here is written **independently** of
:mod:`sigaudit.signing`, directly against :mod:`hmac`. If it reused the
auditor's own signer, a signer bug would be invisible: both sides would be
wrong in the same way and still agree.

It binds to 127.0.0.1 only and is not meant to be exposed.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Any


class Scheme(StrEnum):
    """Which built-in profile the receiver speaks."""

    GENERIC = "generic-hmac-sha256"  # X-Signature: <hex sha256(body)>
    STRIPE = "stripe"  # Stripe-Signature: t=<ts>,v1=<hex sha256("ts.body")>


class Flaw(StrEnum):
    NO_VERIFICATION = "no-verification"
    SKIP_IF_MISSING = "skip-if-missing"
    FAIL_OPEN = "fail-open"
    LOG_ONLY = "log-only"
    NO_TIMESTAMP_CHECK = "no-timestamp-check"
    ACCEPT_SHA1 = "accept-sha1"


FLAW_DESCRIPTIONS: Mapping[Flaw, str] = {
    Flaw.NO_VERIFICATION: "Never checks the signature at all.",
    Flaw.SKIP_IF_MISSING: (
        "Treats a missing or empty signature as 'unsigned, allow' (if sig: verify)."
    ),
    Flaw.FAIL_OPEN: "Catches parsing/decoding errors during verification and lets the request in.",
    Flaw.LOG_ONLY: "Verifies, but only logs mismatches ('monitor mode' left switched on).",
    Flaw.NO_TIMESTAMP_CHECK: "Checks the HMAC but never checks the timestamp's age.",
    Flaw.ACCEPT_SHA1: "Accepts HMAC-SHA1 as well as HMAC-SHA256 (algorithm agility).",
}


@dataclass(frozen=True)
class ReceiverConfig:
    secret: str
    scheme: Scheme = Scheme.STRIPE
    flaws: frozenset[Flaw] = frozenset()
    tolerance_seconds: int = 300
    path: str = "/webhook"
    accept_status: int = 200
    accept_body: str = '{"received": true}'
    reject_status: int = 400
    reject_body: str = '{"error": "invalid signature"}'
    clock: Callable[[], float] = field(default=time.time)


@dataclass(frozen=True)
class ReceivedRequest:
    path: str
    headers: dict[str, str]
    body: bytes
    accepted: bool


def _hmac(key: bytes, msg: bytes, name: str) -> bytes:
    return hmac.new(key, msg, getattr(hashlib, name)).digest()


def _matches(cfg: ReceiverConfig, provided: bytes, message: bytes) -> bool:
    key = cfg.secret.encode()
    if hmac.compare_digest(provided, _hmac(key, message, "sha256")):
        return True
    return Flaw.ACCEPT_SHA1 in cfg.flaws and hmac.compare_digest(
        provided, _hmac(key, message, "sha1")
    )


def _check_generic(cfg: ReceiverConfig, value: str, body: bytes) -> bool:
    return _matches(cfg, bytes.fromhex(value), body)  # ValueError on garbage


def _check_stripe(cfg: ReceiverConfig, value: str, body: bytes) -> bool:
    timestamp: int | None = None
    candidates: list[bytes] = []
    for item in value.split(","):
        key, sep, val = item.partition("=")
        if not sep:
            raise ValueError("malformed Stripe-Signature item")
        if key == "t":
            timestamp = int(val)
        elif key == "v1":
            candidates.append(bytes.fromhex(val))
    if timestamp is None or not candidates:
        raise ValueError("Stripe-Signature needs t= and v1=")
    message = f"{timestamp}.".encode() + body
    if not any(_matches(cfg, c, message) for c in candidates):
        return False
    if Flaw.NO_TIMESTAMP_CHECK in cfg.flaws:
        return True
    return abs(cfg.clock() - timestamp) <= cfg.tolerance_seconds


def verify(cfg: ReceiverConfig, headers: Mapping[str, str], body: bytes) -> bool:
    """Decide whether to accept a request, honouring the configured flaws."""
    flaws = cfg.flaws
    if Flaw.NO_VERIFICATION in flaws:
        return True
    header = "X-Signature" if cfg.scheme is Scheme.GENERIC else "Stripe-Signature"
    lowered = {k.lower(): v for k, v in headers.items()}
    value = lowered.get(header.lower())
    if value is None:
        return Flaw.SKIP_IF_MISSING in flaws
    if value == "" and Flaw.SKIP_IF_MISSING in flaws:
        return True
    try:
        if cfg.scheme is Scheme.GENERIC:
            ok = _check_generic(cfg, value, body)
        else:
            ok = _check_stripe(cfg, value, body)
    except ValueError:
        ok = Flaw.FAIL_OPEN in flaws
    return ok or Flaw.LOG_ONLY in flaws


class DemoReceiver:
    """Run a receiver on 127.0.0.1 in a background thread.

    >>> with DemoReceiver(ReceiverConfig(secret="s")) as rx:
    ...     rx.url  # doctest: +SKIP
    'http://127.0.0.1:54321/webhook'
    """

    def __init__(self, config: ReceiverConfig) -> None:
        self.config = config
        self.received: list[ReceivedRequest] = []
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                headers = dict(self.headers.items())
                if self.path != receiver.config.path:
                    self._reply(404, '{"error": "not found"}')
                    return
                accepted = verify(receiver.config, headers, body)
                with receiver._lock:
                    receiver.received.append(ReceivedRequest(self.path, headers, body, accepted))
                if accepted:
                    self._reply(receiver.config.accept_status, receiver.config.accept_body)
                else:
                    self._reply(receiver.config.reject_status, receiver.config.reject_body)

            def do_GET(self) -> None:
                self._reply(405, '{"error": "method not allowed"}')

            def _reply(self, status: int, body: str) -> None:
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:
                pass  # keep test and demo output clean

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host!s}:{port}{self.config.path}"

    def start(self) -> DemoReceiver:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> DemoReceiver:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()
