"""The audit cases: one deliberately bad request each, plus a valid control.

Every case starts from the same *valid* baseline (correct secret, fresh
timestamp, the configured payload) and breaks exactly one thing. So if a
case is accepted, the finding points at one specific mistake in the
receiver's verification logic.

Each request carries its own event ID. Otherwise an endpoint with
duplicate-event protection could reject, say, the replay case because it
had "already seen" the control event's ID, and hide a missing timestamp
check.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from sigaudit import __version__
from sigaudit.profiles import HashAlgorithm, ProviderProfile
from sigaudit.signing import Signer, format_header_value

#: Put this token anywhere in a custom payload file; each case replaces it with
#: a unique event ID so requests are traceable and never deduplicated.
EVENT_ID_TOKEN = "__SIGAUDIT_EVENT_ID__"  # noqa: S105 - a placeholder, not a password

MALFORMED_SIGNATURE = "!!sigaudit-malformed-signature!!"

#: Identifies the tool to the receiver (and its logs). Override with --header.
USER_AGENT = f"sigaudit/{__version__} (webhook signature verification auditor)"


class Expectation(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"


class Severity(StrEnum):
    """Impact if the case is (wrongly) accepted."""

    INFO = "info"  # control case
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class RequestSpec:
    """Exactly what goes on the wire. This is also what reports show."""

    method: str
    url: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class BuildContext:
    """Everything a case needs to build its request."""

    url: str
    signer: Signer
    now: int
    run_id: str
    replay_age_seconds: int
    wrong_key: bytes
    payload_template: bytes | None = None
    extra_headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def create(
        cls,
        *,
        url: str,
        signer: Signer,
        now: int,
        replay_age_seconds: int | None = None,
        payload_template: bytes | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> BuildContext:
        ts = signer.profile.timestamp
        if replay_age_seconds is None:
            # Comfortably outside the window: one hour past the tolerance.
            replay_age_seconds = (ts.tolerance_seconds if ts else 300) + 3600
        wrong_key = secrets.token_bytes(32)
        while wrong_key == signer.key:  # pragma: no cover - astronomically unlikely
            wrong_key = secrets.token_bytes(32)
        return cls(
            url=url,
            signer=signer,
            now=now,
            run_id=secrets.token_hex(4),
            replay_age_seconds=replay_age_seconds,
            wrong_key=wrong_key,
            payload_template=payload_template,
            extra_headers=MappingProxyType(dict(extra_headers or {})),
        )

    @property
    def profile(self) -> ProviderProfile:
        return self.signer.profile

    @property
    def fresh_timestamp(self) -> int | None:
        return self.now if self.profile.uses_timestamp else None

    def event_id(self, case_id: str) -> str:
        return f"evt_sigaudit_{self.run_id}_{case_id.replace('-', '_')}"

    def body_for(self, case_id: str) -> bytes:
        event_id = self.event_id(case_id)
        if self.payload_template is None:
            return default_payload(event_id, self.now)
        return self.payload_template.replace(EVENT_ID_TOKEN.encode(), event_id.encode())

    def request(self, signing_headers: Mapping[str, str], body: bytes) -> RequestSpec:
        headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": self.profile.content_type,
            **self.profile.extra_headers,
            **self.extra_headers,
            **signing_headers,
        }
        return RequestSpec(method="POST", url=self.url, headers=headers, body=body)


def default_payload(event_id: str, created: int) -> bytes:
    """A harmless, clearly labelled test event.

    If an endpoint is broken, the forged requests *will* be processed. The
    default payload is shaped like a typical event (so the receiver parses it)
    but is plainly a test, so it should not trigger real business logic.
    """
    event = {
        "id": event_id,
        "object": "event",
        "type": "sigaudit.test",
        "livemode": False,
        "created": created,
        "data": {
            "object": {
                "id": f"obj_{event_id}",
                "object": "sigaudit_test",
                "amount": 100,
                "currency": "usd",
                "description": (
                    "Synthetic test event sent by sigaudit, a webhook signature auditor. "
                    "Not a real transaction; safe to ignore."
                ),
            }
        },
    }
    return json.dumps(event, separators=(",", ":")).encode()


def tamper_body(body: bytes) -> bytes:
    """Return a modified body, as an attacker who captured a real event would.

    For a JSON object the change is meaningful (inflate ``data.object.amount``
    or add a field), which makes the finding easy to explain. For anything else
    a trailing newline is enough: it keeps JSON/form bodies parseable while
    changing the bytes, so a correct HMAC check must fail.
    """
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body + b"\n"
    if not isinstance(obj, dict):
        return body + b"\n"
    data = obj.get("data")
    target = data.get("object") if isinstance(data, dict) else None
    amount = target.get("amount") if isinstance(target, dict) else None
    if isinstance(target, dict) and isinstance(amount, int) and not isinstance(amount, bool):
        target["amount"] = amount * 1000 + 1
    else:
        obj["sigaudit_tampered"] = True
    tampered = json.dumps(obj, separators=(",", ":")).encode()
    return tampered if tampered != body else body + b"\n"


def swap_algorithm_label(fmt: str, old: HashAlgorithm, new: HashAlgorithm) -> str:
    """``sha256={signature}`` -> ``sha1={signature}``; formats without a label are unchanged."""

    def repl(m: re.Match[str]) -> str:
        return new.value.upper() if m.group(0).isupper() else new.value

    return re.sub(re.escape(old.value), repl, fmt, flags=re.IGNORECASE)


def alternate_algorithm(algorithm: HashAlgorithm) -> HashAlgorithm:
    return HashAlgorithm.SHA1 if algorithm is not HashAlgorithm.SHA1 else HashAlgorithm.SHA256


# ---------------------------------------------------------------------------
# Case builders
# ---------------------------------------------------------------------------


def _build_valid(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("valid")
    return ctx.request(ctx.signer.headers(body, ctx.fresh_timestamp), body)


def _build_missing(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("missing-signature")
    headers = ctx.signer.headers(body, ctx.fresh_timestamp)
    del headers[ctx.profile.signature_header]  # a separate timestamp header (if any) stays
    return ctx.request(headers, body)


def _build_empty(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("empty-signature")
    headers = ctx.signer.headers(body, ctx.fresh_timestamp)
    headers[ctx.profile.signature_header] = ""
    return ctx.request(headers, body)


def _build_malformed(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("malformed-signature")
    headers = ctx.signer.headers(body, ctx.fresh_timestamp)
    # Keep the header's *structure* (e.g. "t=...,v1=...") so we exercise the
    # comparison/decoding path, not just a format check.
    headers[ctx.profile.signature_header] = format_header_value(
        ctx.profile.signature_format, MALFORMED_SIGNATURE, ctx.fresh_timestamp
    )
    return ctx.request(headers, body)


def _build_wrong_secret(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("wrong-secret")
    return ctx.request(ctx.signer.headers(body, ctx.fresh_timestamp, key=ctx.wrong_key), body)


def _build_tampered(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("tampered-body")
    headers = ctx.signer.headers(body, ctx.fresh_timestamp)  # signed over the ORIGINAL
    return ctx.request(headers, tamper_body(body))


def _build_replay(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("replay-old-timestamp")
    old = ctx.now - ctx.replay_age_seconds
    return ctx.request(ctx.signer.headers(body, old), body)


def _build_wrong_algorithm(ctx: BuildContext) -> RequestSpec:
    body = ctx.body_for("wrong-algorithm")
    alt = alternate_algorithm(ctx.profile.algorithm)
    fmt = swap_algorithm_label(ctx.profile.signature_format, ctx.profile.algorithm, alt)
    headers = ctx.signer.headers(body, ctx.fresh_timestamp, algorithm=alt, signature_format=fmt)
    return ctx.request(headers, body)


# ---------------------------------------------------------------------------
# Case catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditCase:
    """One audit case. (Not called ``TestCase``: pytest would try to collect it.)"""

    id: str
    number: int
    title: str
    expectation: Expectation
    severity: Severity
    description: str  # what is sent
    risk: str  # one line: what an attacker gets if this is accepted
    fix: str  # one line: what the receiver should do instead
    build: Callable[[BuildContext], RequestSpec]
    requires_timestamp: bool = False


ALL_CASES: tuple[AuditCase, ...] = (
    AuditCase(
        id="valid",
        number=1,
        title="Valid signature (control)",
        expectation=Expectation.ACCEPT,
        severity=Severity.INFO,
        description="A correctly signed, fresh request using your secret.",
        risk=("Control case. If the endpoint rejects this, the other results cannot be trusted."),
        fix="Check the secret, the profile, and the accept/reject matchers.",
        build=_build_valid,
    ),
    AuditCase(
        id="missing-signature",
        number=2,
        title="No signature header",
        expectation=Expectation.REJECT,
        severity=Severity.CRITICAL,
        description="The signature header is omitted entirely.",
        risk=(
            "Anyone can forge events by leaving out the signature header; "
            "verification is effectively optional."
        ),
        fix="Reject any request without the signature header before processing it.",
        build=_build_missing,
    ),
    AuditCase(
        id="empty-signature",
        number=3,
        title="Empty signature value",
        expectation=Expectation.REJECT,
        severity=Severity.CRITICAL,
        description="The signature header is present but empty.",
        risk=(
            "An empty signature skips verification, typically code like "
            "`if sig: verify(sig)` treating empty as 'not provided'."
        ),
        fix="Treat an empty signature exactly like a wrong one: reject.",
        build=_build_empty,
    ),
    AuditCase(
        id="malformed-signature",
        number=4,
        title="Malformed signature",
        expectation=Expectation.REJECT,
        severity=Severity.CRITICAL,
        description="Correct header layout, but the signature is non-hex/base64 garbage.",
        risk=(
            "Unparseable signatures are accepted. Verification probably fails "
            "open when decoding raises an error."
        ),
        fix="Make every error path in verification end in rejection (fail closed).",
        build=_build_malformed,
    ),
    AuditCase(
        id="wrong-secret",
        number=5,
        title="Signed with the wrong secret",
        expectation=Expectation.REJECT,
        severity=Severity.CRITICAL,
        description="A well-formed signature computed with a random key instead of your secret.",
        risk=(
            "Signatures made with any key are accepted, so the endpoint is not "
            "checking the signature against its secret: anyone can forge events."
        ),
        fix=(
            "Recompute the HMAC with your secret and compare it to the received "
            "value with a constant-time comparison."
        ),
        build=_build_wrong_secret,
    ),
    AuditCase(
        id="tampered-body",
        number=6,
        title="Body modified after signing",
        expectation=Expectation.REJECT,
        severity=Severity.CRITICAL,
        description="A valid signature for the original body, sent with a modified body.",
        risk=(
            "A captured genuine event can be altered (amount, status, customer) "
            "and still be accepted: the signature does not cover the exact raw body."
        ),
        fix=(
            "Compute the HMAC over the raw request bytes as received, before any "
            "JSON parsing or re-serialisation."
        ),
        build=_build_tampered,
    ),
    AuditCase(
        id="replay-old-timestamp",
        number=7,
        title="Replay with an old timestamp",
        expectation=Expectation.REJECT,
        severity=Severity.HIGH,
        description="A correctly signed request whose signed timestamp is outside the tolerance.",
        risk=(
            "Old, genuinely signed events can be re-sent and accepted (e.g. a past "
            "'payment succeeded'), because timestamp tolerance is not enforced."
        ),
        fix=(
            "Reject events whose signed timestamp is older than the tolerance, and "
            "deduplicate by event ID."
        ),
        build=_build_replay,
        requires_timestamp=True,
    ),
    AuditCase(
        id="wrong-algorithm",
        number=8,
        title="Wrong hash algorithm",
        expectation=Expectation.REJECT,
        severity=Severity.MEDIUM,
        description=(
            "Signed with your secret but a different hash (SHA-1 instead of SHA-256), "
            "with any algorithm label in the header changed to match."
        ),
        risk=(
            "The endpoint lets the sender choose the algorithm (a downgrade risk), "
            "so the scheme is not pinned to what the provider specifies."
        ),
        fix="Hard-code the expected algorithm; never select it based on request data.",
        build=_build_wrong_algorithm,
    ),
)

CASES_BY_ID: Mapping[str, AuditCase] = MappingProxyType({c.id: c for c in ALL_CASES})


class CaseSelectionError(ValueError):
    pass


def select_cases(
    only: Iterable[str] | None = None, skip: Iterable[str] | None = None
) -> tuple[AuditCase, ...]:
    """Filter the catalogue by ID. The control case is always included."""
    only_set = set(only or ())
    skip_set = set(skip or ())
    unknown = sorted((only_set | skip_set) - set(CASES_BY_ID))
    if unknown:
        raise CaseSelectionError(
            f"unknown case id(s): {', '.join(unknown)}; valid: {', '.join(CASES_BY_ID)}"
        )
    if "valid" in skip_set:
        raise CaseSelectionError("the 'valid' control case cannot be skipped")
    return tuple(
        c
        for c in ALL_CASES
        if c.id == "valid" or ((not only_set or c.id in only_set) and c.id not in skip_set)
    )
