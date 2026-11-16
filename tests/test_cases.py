from __future__ import annotations

import json

import pytest

from sigaudit.cases import (
    ALL_CASES,
    CASES_BY_ID,
    EVENT_ID_TOKEN,
    MALFORMED_SIGNATURE,
    BuildContext,
    CaseSelectionError,
    Expectation,
    RequestSpec,
    alternate_algorithm,
    default_payload,
    select_cases,
    swap_algorithm_label,
    tamper_body,
)
from sigaudit.profiles import HashAlgorithm, load_builtin_profile
from sigaudit.signing import Signer

SECRET = "whsec_test_secret"
NOW = 1_700_000_000
URL = "https://staging.example.test/webhooks"


def ctx_for(profile_name: str, **kwargs: object) -> BuildContext:
    signer = Signer.from_secret(load_builtin_profile(profile_name), SECRET)
    return BuildContext.create(url=URL, signer=signer, now=NOW, **kwargs)  # type: ignore[arg-type]


def build(ctx: BuildContext, case_id: str) -> RequestSpec:
    return CASES_BY_ID[case_id].build(ctx)


def test_catalogue_shape() -> None:
    assert [c.number for c in ALL_CASES] == list(range(1, 9))
    assert len({c.id for c in ALL_CASES}) == 8
    assert [c.id for c in ALL_CASES if c.expectation is Expectation.ACCEPT] == ["valid"]
    for case in ALL_CASES:
        assert case.risk
        assert case.fix
        assert case.description


def test_valid_case_signs_exact_body_with_fresh_timestamp() -> None:
    ctx = ctx_for("stripe")
    req = build(ctx, "valid")
    expected_sig = ctx.signer.signature(req.body, NOW)
    assert req.headers["Stripe-Signature"] == f"t={NOW},v1={expected_sig}"
    assert req.headers["Content-Type"] == "application/json"
    assert req.method == "POST"
    assert req.url == URL


def test_event_ids_are_unique_per_case() -> None:
    ctx = ctx_for("stripe")
    ids = {json.loads(c.build(ctx).body)["id"] for c in ALL_CASES if c.id != "tampered-body"}
    assert len(ids) == len(ALL_CASES) - 1
    assert all(i.startswith(f"evt_sigaudit_{ctx.run_id}_") for i in ids)


@pytest.mark.parametrize("profile", ["stripe", "generic-hmac-sha256", "slack"])
def test_missing_signature_removes_only_the_signature_header(profile: str) -> None:
    ctx = ctx_for(profile)
    req = build(ctx, "missing-signature")
    assert ctx.profile.signature_header not in req.headers
    ts = ctx.profile.timestamp
    if ts is not None and ts.header:
        assert req.headers[ts.header] == str(NOW)


def test_empty_signature() -> None:
    ctx = ctx_for("github")
    assert build(ctx, "empty-signature").headers["X-Hub-Signature-256"] == ""


def test_malformed_keeps_header_structure() -> None:
    ctx = ctx_for("stripe")
    assert build(ctx, "malformed-signature").headers["Stripe-Signature"] == (
        f"t={NOW},v1={MALFORMED_SIGNATURE}"
    )


def test_wrong_secret_is_well_formed_but_different() -> None:
    ctx = ctx_for("generic-hmac-sha256")
    req = build(ctx, "wrong-secret")
    sig = req.headers["X-Signature"]
    assert len(sig) == 64
    int(sig, 16)  # valid hex
    assert sig != ctx.signer.signature(req.body, None)
    assert sig == ctx.signer.signature(req.body, None, key=ctx.wrong_key)


def test_tampered_body_carries_signature_of_original() -> None:
    ctx = ctx_for("stripe")
    req = build(ctx, "tampered-body")
    original = ctx.body_for("tampered-body")
    assert req.body != original
    assert json.loads(req.body)["data"]["object"]["amount"] != 100
    assert req.headers["Stripe-Signature"] == f"t={NOW},v1={ctx.signer.signature(original, NOW)}"


def test_replay_uses_old_but_validly_signed_timestamp() -> None:
    ctx = ctx_for("stripe")
    req = build(ctx, "replay-old-timestamp")
    old = NOW - (300 + 3600)
    assert req.headers["Stripe-Signature"] == f"t={old},v1={ctx.signer.signature(req.body, old)}"


def test_replay_age_is_configurable_and_slack_uses_its_header() -> None:
    ctx = ctx_for("slack", replay_age_seconds=900)
    req = build(ctx, "replay-old-timestamp")
    assert req.headers["X-Slack-Request-Timestamp"] == str(NOW - 900)


def test_wrong_algorithm_swaps_label_when_present() -> None:
    ctx = ctx_for("github")
    req = build(ctx, "wrong-algorithm")
    value = req.headers["X-Hub-Signature-256"]
    assert value.startswith("sha1=")
    assert value == "sha1=" + ctx.signer.signature(req.body, None, algorithm=HashAlgorithm.SHA1)
    assert len(value.removeprefix("sha1=")) == 40  # SHA-1 hex length


def test_wrong_algorithm_without_label() -> None:
    ctx = ctx_for("stripe")
    value = build(ctx, "wrong-algorithm").headers["Stripe-Signature"]
    assert value.startswith(f"t={NOW},v1=")
    assert len(value.split("v1=")[1]) == 40


def test_alternate_algorithm_and_label_swap() -> None:
    assert alternate_algorithm(HashAlgorithm.SHA256) is HashAlgorithm.SHA1
    assert alternate_algorithm(HashAlgorithm.SHA1) is HashAlgorithm.SHA256
    assert swap_algorithm_label("SHA256={signature}", HashAlgorithm.SHA256, HashAlgorithm.SHA1) == (
        "SHA1={signature}"
    )
    assert swap_algorithm_label("{signature}", HashAlgorithm.SHA256, HashAlgorithm.SHA1) == (
        "{signature}"
    )


def test_profile_and_user_extra_headers() -> None:
    ctx = ctx_for("github", extra_headers={"X-Bug-Bounty": "researcher"})
    req = build(ctx, "valid")
    assert req.headers["X-GitHub-Event"] == "ping"
    assert req.headers["X-Bug-Bounty"] == "researcher"


def test_custom_payload_event_id_token() -> None:
    template = b'{"id":"' + EVENT_ID_TOKEN.encode() + b'","type":"custom"}'
    ctx = ctx_for("generic-hmac-sha256", payload_template=template)
    assert json.loads(build(ctx, "valid").body)["id"] == ctx.event_id("valid")


def test_custom_payload_without_token_is_sent_verbatim() -> None:
    ctx = ctx_for("generic-hmac-sha256", payload_template=b"a=1&b=2")
    assert build(ctx, "valid").body == b"a=1&b=2"
    assert build(ctx, "tampered-body").body == b"a=1&b=2\n"


@pytest.mark.parametrize(
    ("body", "check"),
    [
        (default_payload("evt", 1), lambda b: json.loads(b)["data"]["object"]["amount"] == 100001),
        (b'{"x":1}', lambda b: json.loads(b)["sigaudit_tampered"] is True),
        (b"[1,2]", lambda b: b == b"[1,2]\n"),
        (b"\xff\xfe", lambda b: b == b"\xff\xfe\n"),
    ],
)
def test_tamper_body_variants(body: bytes, check: object) -> None:
    tampered = tamper_body(body)
    assert tampered != body
    assert check(tampered)  # type: ignore[operator]


def test_default_payload_is_clearly_a_test() -> None:
    event = json.loads(default_payload("evt_x", NOW))
    assert event["type"] == "sigaudit.test"
    assert event["livemode"] is False
    assert "safe to ignore" in event["data"]["object"]["description"]


def test_select_cases() -> None:
    assert len(select_cases()) == 8
    chosen = select_cases(only=["replay-old-timestamp"])
    assert [c.id for c in chosen] == ["valid", "replay-old-timestamp"]
    assert "wrong-algorithm" not in {c.id for c in select_cases(skip=["wrong-algorithm"])}
    with pytest.raises(CaseSelectionError, match="unknown"):
        select_cases(only=["nope"])
    with pytest.raises(CaseSelectionError, match="cannot be skipped"):
        select_cases(skip=["valid"])
