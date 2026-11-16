"""Report rendering helpers shared by the JSON, Markdown and terminal outputs."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from urllib.parse import urlsplit

from sigaudit.cases import RequestSpec

REDACTED = "[REDACTED]"
BODY_LIMIT = 4096

_SENSITIVE_EXACT = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
_SENSITIVE_PARTS = ("token", "secret", "password", "api-key", "apikey", "x-auth")


def is_sensitive_header(name: str) -> bool:
    """Headers that may carry credentials. Signature headers are *not* sensitive:
    an HMAC over a synthetic test payload does not reveal the secret."""
    lowered = name.lower()
    return lowered in _SENSITIVE_EXACT or any(part in lowered for part in _SENSITIVE_PARTS)


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {k: (REDACTED if is_sensitive_header(k) else v) for k, v in headers.items()}


def body_for_report(body: bytes, limit: int = BODY_LIMIT) -> tuple[str, str, bool]:
    """Return ``(text, encoding, truncated)``; encoding is ``utf-8`` or ``base64``."""
    truncated = len(body) > limit
    clipped = body[:limit]
    try:
        return clipped.decode("utf-8"), "utf-8", truncated
    except UnicodeDecodeError:
        return base64.b64encode(clipped).decode("ascii"), "base64", truncated


def http_request_text(req: RequestSpec) -> str:
    """Render a request roughly as it appears on the wire, for humans."""
    parts = urlsplit(req.url)
    target = parts.path or "/"
    if parts.query:
        target += f"?{parts.query}"
    lines = [f"{req.method} {target} HTTP/1.1", f"Host: {parts.netloc}"]
    lines += [f"{k}: {v}" for k, v in redact_headers(req.headers).items()]
    text, encoding, truncated = body_for_report(req.body)
    if encoding == "base64":
        text = f"[binary body, base64] {text}"
    if truncated:
        text += "\n[... truncated]"
    return "\n".join(lines) + "\n\n" + text
