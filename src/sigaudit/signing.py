"""Signature construction: pure functions, no I/O.

This module is how the auditor produces a *correct* signature for the
control case, and deliberately wrong ones for the negative cases. If it were
wrong, every result would be wrong, so it is kept small and checked against
reference values computed independently with ``openssl`` (see tests).

The one rule that matters most here is **sign the exact bytes you send**.
The body is never parsed, re-serialised or passed through ``str.format``.
The template is split around ``{body}`` and the raw bytes are spliced in.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from dataclasses import dataclass

from sigaudit.profiles import (
    BODY,
    SIGNATURE,
    TIMESTAMP,
    Encoding,
    HashAlgorithm,
    ProviderProfile,
    SecretEncoding,
)


class SigningError(ValueError):
    """The inputs cannot produce a signature (bad secret encoding, missing timestamp)."""


def decode_secret(secret: str, encoding: SecretEncoding) -> bytes:
    """Turn the user-supplied secret string into HMAC key bytes."""
    if not secret:
        raise SigningError("the signing secret is empty")
    try:
        match encoding:
            case SecretEncoding.UTF8:
                return secret.encode("utf-8")
            case SecretEncoding.HEX:
                return bytes.fromhex(secret.strip())
            case SecretEncoding.BASE64:
                return base64.b64decode(secret.strip(), validate=True)
    except (ValueError, binascii.Error):
        # Never echo the secret back in an error message.
        raise SigningError(
            f"the signing secret is not valid {encoding.value} (as the profile requires)"
        ) from None
    raise SigningError(f"unsupported secret encoding {encoding!r}")  # pragma: no cover


def _render(fragment: str, timestamp: int | None) -> str:
    if TIMESTAMP in fragment:
        if timestamp is None:
            raise SigningError("this scheme needs a timestamp but none was given")
        fragment = fragment.replace(TIMESTAMP, str(timestamp))
    return fragment


def build_signed_message(template: str, body: bytes, timestamp: int | None) -> bytes:
    """Build the exact byte string that gets HMAC'd.

    ``"{timestamp}.{body}"`` with ``timestamp=1700000000`` and body ``b'{}'``
    gives ``b'1700000000.{}'``. Placeholders are only substituted in the
    *template*. A body that happens to contain the text ``{timestamp}`` is
    left untouched.
    """
    prefix, sep, suffix = template.partition(BODY)
    if not sep or BODY in suffix:
        raise SigningError(f"template must contain {BODY} exactly once: {template!r}")
    head = _render(prefix, timestamp).encode("utf-8")
    tail = _render(suffix, timestamp).encode("utf-8")
    return head + body + tail


def compute_hmac(key: bytes, message: bytes, algorithm: HashAlgorithm) -> bytes:
    return hmac.new(key, message, getattr(hashlib, algorithm.value)).digest()


def encode_signature(digest: bytes, encoding: Encoding) -> str:
    match encoding:
        case Encoding.HEX:
            return digest.hex()
        case Encoding.BASE64:
            return base64.b64encode(digest).decode("ascii")
    raise SigningError(f"unsupported signature encoding {encoding!r}")  # pragma: no cover


def format_header_value(fmt: str, signature: str, timestamp: int | None) -> str:
    """Lay out the signature header, e.g. ``t=1700000000,v1=<hex>``."""
    # Substitute the timestamp first; the signature is inserted last so its
    # content can never be mistaken for a placeholder.
    return _render(fmt, timestamp).replace(SIGNATURE, signature)


@dataclass(frozen=True, slots=True)
class Signer:
    """Signs bodies the way ``profile`` describes, with key ``key``.

    The keyword overrides on :meth:`signature` and :meth:`headers` exist for
    the negative test cases (wrong key, wrong algorithm). Normal callers never
    use them.
    """

    profile: ProviderProfile
    key: bytes

    @classmethod
    def from_secret(cls, profile: ProviderProfile, secret: str) -> Signer:
        return cls(profile=profile, key=decode_secret(secret, profile.secret_encoding))

    def signature(
        self,
        body: bytes,
        timestamp: int | None,
        *,
        key: bytes | None = None,
        algorithm: HashAlgorithm | None = None,
    ) -> str:
        message = build_signed_message(self.profile.signed_payload, body, timestamp)
        digest = compute_hmac(
            self.key if key is None else key, message, algorithm or self.profile.algorithm
        )
        return encode_signature(digest, self.profile.signature_encoding)

    def headers(
        self,
        body: bytes,
        timestamp: int | None,
        *,
        key: bytes | None = None,
        algorithm: HashAlgorithm | None = None,
        signature_format: str | None = None,
    ) -> dict[str, str]:
        """All signing-related headers for a request: signature (+ timestamp header)."""
        sig = self.signature(body, timestamp, key=key, algorithm=algorithm)
        fmt = signature_format or self.profile.signature_format
        headers = {self.profile.signature_header: format_header_value(fmt, sig, timestamp)}
        ts = self.profile.timestamp
        if ts is not None and ts.header is not None:
            if timestamp is None:
                raise SigningError("this scheme needs a timestamp but none was given")
            headers[ts.header] = str(timestamp)
        return headers
