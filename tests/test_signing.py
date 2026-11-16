"""Signer tests against reference values computed independently with openssl.

Reproduce any expected value with, e.g.:

    printf '%s' '1700000000.{"id":"evt_1","amount":100}' \
        | openssl dgst -sha256 -hmac 'whsec_test_secret'
"""

from __future__ import annotations

import pytest

from sigaudit.profiles import (
    Encoding,
    HashAlgorithm,
    SecretEncoding,
    load_builtin_profile,
)
from sigaudit.signing import (
    Signer,
    SigningError,
    build_signed_message,
    compute_hmac,
    decode_secret,
    encode_signature,
    format_header_value,
)

SECRET = "whsec_test_secret"
BODY = b'{"id":"evt_1","amount":100}'
TS = 1700000000

# openssl reference values (see module docstring)
BODY_SHA256_HEX = "31eb9a14215a4bd7cb2713cb5faa40e4dcddae7f86b421c8fb12eba229987166"
BODY_SHA256_B64 = "MeuaFCFaS9fLJxPLX6pA5Nzdrn+GtCHI+xLroimYcWY="
BODY_SHA1_HEX = "55fc121162236b099cad949c6b0cc769aa2a3dc8"
BODY_SHA512_HEX = (
    "4e1714150f3d313a41b9cd8078535addc95d6e9e7a34d3ee5ffd9ce89ab7000c"
    "053e1d25bb7b9c51a923bc84701313a89ab38f4b9d2ec387d8a392b0698083ad"
)
STRIPE_HEX = "fdacc5f19d1cb4e5102485ae74ccedbf6acb39438796ed8cf7c32fcae3d2136b"
SLACK_HEX = "d53a64a7162943cc645a65e07361171ff1e6673fdb1393723c4cc11348ee31ce"


def test_rfc4231_test_case_2() -> None:
    # Published HMAC-SHA256 test vector: anchors compute_hmac to the standard.
    digest = compute_hmac(b"Jefe", b"what do ya want for nothing?", HashAlgorithm.SHA256)
    assert digest.hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        (HashAlgorithm.SHA256, BODY_SHA256_HEX),
        (HashAlgorithm.SHA1, BODY_SHA1_HEX),
        (HashAlgorithm.SHA512, BODY_SHA512_HEX),
    ],
)
def test_hmac_algorithms(algorithm: HashAlgorithm, expected: str) -> None:
    assert compute_hmac(SECRET.encode(), BODY, algorithm).hex() == expected


def test_base64_encoding() -> None:
    digest = compute_hmac(SECRET.encode(), BODY, HashAlgorithm.SHA256)
    assert encode_signature(digest, Encoding.BASE64) == BODY_SHA256_B64


@pytest.mark.parametrize(
    ("profile_name", "expected_headers"),
    [
        ("generic-hmac-sha256", {"X-Signature": BODY_SHA256_HEX}),
        ("github", {"X-Hub-Signature-256": f"sha256={BODY_SHA256_HEX}"}),
        ("shopify", {"X-Shopify-Hmac-Sha256": BODY_SHA256_B64}),
        ("stripe", {"Stripe-Signature": f"t={TS},v1={STRIPE_HEX}"}),
        (
            "slack",
            {"X-Slack-Signature": f"v0={SLACK_HEX}", "X-Slack-Request-Timestamp": str(TS)},
        ),
    ],
)
def test_builtin_profiles_produce_reference_headers(
    profile_name: str, expected_headers: dict[str, str]
) -> None:
    signer = Signer.from_secret(load_builtin_profile(profile_name), SECRET)
    assert signer.headers(BODY, TS) == expected_headers


def test_body_placeholders_are_not_substituted() -> None:
    # A body containing the literal text "{timestamp}" must be signed verbatim.
    body = b'{"note":"{timestamp} {body}"}'
    message = build_signed_message("{timestamp}.{body}", body, TS)
    assert message == b"1700000000." + body
    expected = "84f331994ea2752f1e491f821d59e764a583da723a9aebd9f28d0a3b8035e72d"
    signer = Signer.from_secret(load_builtin_profile("stripe"), SECRET)
    assert signer.signature(body, TS) == expected


def test_signed_message_requires_timestamp_when_template_uses_it() -> None:
    with pytest.raises(SigningError, match="needs a timestamp"):
        build_signed_message("{timestamp}.{body}", BODY, None)


def test_signed_message_requires_body_placeholder() -> None:
    with pytest.raises(SigningError):
        build_signed_message("{timestamp}", BODY, TS)


def test_format_header_value_inserts_signature_last() -> None:
    # Even a signature that looked like a placeholder would be inserted literally.
    assert format_header_value("t={timestamp},v1={signature}", "{timestamp}", 5) == (
        "t=5,v1={timestamp}"
    )


def test_hex_secret_decoding() -> None:
    key = decode_secret("00112233445566778899aabbccddeeff", SecretEncoding.HEX)
    assert compute_hmac(key, BODY, HashAlgorithm.SHA256).hex() == (
        "65f77b25b6b488e63ad619a6cad762c648c04bcd019508ea9b72a7b79ca75b77"
    )


def test_base64_secret_decoding() -> None:
    assert decode_secret("AAEC", SecretEncoding.BASE64) == b"\x00\x01\x02"


@pytest.mark.parametrize(
    ("secret", "encoding"),
    [("not-hex!", SecretEncoding.HEX), ("***", SecretEncoding.BASE64), ("", SecretEncoding.UTF8)],
)
def test_bad_secrets_raise_without_echoing_secret(secret: str, encoding: SecretEncoding) -> None:
    with pytest.raises(SigningError) as excinfo:
        decode_secret(secret, encoding)
    if secret:
        assert secret not in str(excinfo.value)


def test_overrides_for_negative_cases() -> None:
    signer = Signer.from_secret(load_builtin_profile("generic-hmac-sha256"), SECRET)
    assert signer.signature(BODY, None, algorithm=HashAlgorithm.SHA1) == BODY_SHA1_HEX
    assert signer.signature(BODY, None, key=b"other") != BODY_SHA256_HEX
