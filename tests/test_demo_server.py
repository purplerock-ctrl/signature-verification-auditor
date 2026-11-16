"""The receiver must be right before we trust it to grade the auditor."""

from __future__ import annotations

import hashlib
import hmac
import time

import httpx

from sigaudit.demo_server import Flaw, ReceiverConfig, Scheme, verify
from tests.conftest import SECRET, ReceiverFactory

BODY = b'{"id":"evt_1"}'


def stripe_header(ts: int, body: bytes = BODY, secret: str = SECRET, algo: str = "sha256") -> str:
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, algo).hexdigest()
    return f"t={ts},v1={sig}"


def cfg(**kw: object) -> ReceiverConfig:
    return ReceiverConfig(secret=SECRET, **kw)  # type: ignore[arg-type]


def test_correct_stripe_receiver() -> None:
    now = int(time.time())
    c = cfg()
    assert verify(c, {"Stripe-Signature": stripe_header(now)}, BODY)
    assert verify(c, {"stripe-signature": stripe_header(now)}, BODY)  # case-insensitive
    assert not verify(c, {}, BODY)
    assert not verify(c, {"Stripe-Signature": ""}, BODY)
    assert not verify(c, {"Stripe-Signature": "t=1,v1=zz"}, BODY)
    assert not verify(c, {"Stripe-Signature": stripe_header(now, secret="other")}, BODY)
    assert not verify(c, {"Stripe-Signature": stripe_header(now)}, BODY + b" ")
    assert not verify(c, {"Stripe-Signature": stripe_header(now - 3600)}, BODY)
    assert not verify(c, {"Stripe-Signature": stripe_header(now, algo="sha1")}, BODY)


def test_correct_generic_receiver() -> None:
    c = cfg(scheme=Scheme.GENERIC)
    good = hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest()
    assert verify(c, {"X-Signature": good}, BODY)
    assert not verify(c, {"X-Signature": good}, BODY + b"x")
    assert not verify(c, {"X-Signature": ""}, BODY)


def test_flaws_individually() -> None:
    now = int(time.time())
    assert verify(cfg(flaws=frozenset({Flaw.NO_VERIFICATION})), {}, BODY)
    assert verify(cfg(flaws=frozenset({Flaw.SKIP_IF_MISSING})), {}, BODY)
    assert verify(cfg(flaws=frozenset({Flaw.FAIL_OPEN})), {"Stripe-Signature": "t=1,v1=zz"}, BODY)
    assert verify(
        cfg(flaws=frozenset({Flaw.NO_TIMESTAMP_CHECK})),
        {"Stripe-Signature": stripe_header(now - 3600)},
        BODY,
    )
    assert verify(
        cfg(flaws=frozenset({Flaw.ACCEPT_SHA1})),
        {"Stripe-Signature": stripe_header(now, algo="sha1")},
        BODY,
    )
    log_only = cfg(flaws=frozenset({Flaw.LOG_ONLY}))
    assert verify(log_only, {"Stripe-Signature": "garbage"}, BODY)
    assert not verify(log_only, {}, BODY)  # header still required


def test_http_round_trip(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    now = int(time.time())
    ok = httpx.post(rx.url, content=BODY, headers={"Stripe-Signature": stripe_header(now)})
    bad = httpx.post(rx.url, content=BODY)
    assert ok.status_code == 200
    assert bad.status_code == 400
    assert [r.accepted for r in rx.received] == [True, False]
    assert httpx.post(rx.url.replace("/webhook", "/other"), content=BODY).status_code == 404
    assert httpx.get(rx.url).status_code == 405
