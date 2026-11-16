"""Provider profiles: a declarative description of how a service signs webhooks.

Almost every header-based webhook signing scheme is the same handful of parts
arranged differently:

* **what is signed**: a template such as ``{body}`` (GitHub, Shopify) or
  ``{timestamp}.{body}`` (Stripe) or ``v0:{timestamp}:{body}`` (Slack);
* **which HMAC hash** is used (SHA-256 almost everywhere);
* **how the signature bytes are written**: hex or base64;
* **how the header value is laid out**: a template such as ``sha256={signature}``
  or ``t={timestamp},v1={signature}``;
* **where the timestamp travels**, if there is one: inside the signature header
  or in its own header.

A :class:`ProviderProfile` captures exactly those parts, so new providers are a
YAML/JSON file rather than new code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml

BODY = "{body}"
TIMESTAMP = "{timestamp}"
SIGNATURE = "{signature}"

_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
# RFC 9110 "token" characters: what is legal in an HTTP header name.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class ProfileError(ValueError):
    """A provider profile is malformed. The message says what and where."""


class HashAlgorithm(StrEnum):
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"


class Encoding(StrEnum):
    """How signature bytes are rendered into the header."""

    HEX = "hex"
    BASE64 = "base64"


class SecretEncoding(StrEnum):
    """How the user-supplied secret string becomes HMAC key bytes."""

    UTF8 = "utf8"  # use the string as-is (Stripe, GitHub, Shopify, Slack)
    HEX = "hex"  # the string is hex for the raw key bytes (e.g. Adyen-style keys)
    BASE64 = "base64"  # the string is base64 for the raw key bytes


@dataclass(frozen=True, slots=True)
class TimestampSpec:
    """Timestamp handling for schemes with replay protection.

    ``tolerance_seconds`` is how old a timestamp a *correct* receiver should
    still accept. The replay test uses a timestamp safely outside this window.
    ``header`` names a separate timestamp header (Slack-style). When it is
    ``None`` the timestamp travels inside the signature header (Stripe-style).
    """

    tolerance_seconds: int = 300
    header: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    """How one provider signs its webhooks. Validated on construction."""

    name: str
    description: str
    algorithm: HashAlgorithm
    signed_payload: str
    signature_header: str
    signature_format: str
    signature_encoding: Encoding = Encoding.HEX
    secret_encoding: SecretEncoding = SecretEncoding.UTF8
    timestamp: TimestampSpec | None = None
    content_type: str = "application/json"
    extra_headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate(self)

    @property
    def uses_timestamp(self) -> bool:
        return self.timestamp is not None


def _placeholders(template: str) -> list[str]:
    return _PLACEHOLDER_RE.findall(template)


def _validate(p: ProviderProfile) -> None:
    where = f"profile {p.name!r}"
    if not _NAME_RE.match(p.name):
        raise ProfileError(
            f"{where}: name must be lowercase letters, digits, '-' or '_' (got {p.name!r})"
        )
    if not p.description.strip():
        raise ProfileError(f"{where}: description must not be empty")

    # --- signed_payload template -------------------------------------------
    sp = _placeholders(p.signed_payload)
    if sp.count("body") != 1:
        raise ProfileError(
            f"{where}: signed_payload must contain {BODY} exactly once "
            f"(got {p.signed_payload!r}). The raw request body is what gets authenticated."
        )
    unknown = sorted(set(sp) - {"body", "timestamp"})
    if unknown:
        raise ProfileError(
            f"{where}: signed_payload has unknown placeholder(s) {unknown}; "
            "allowed: {body}, {timestamp}"
        )

    # --- signature_format template -----------------------------------------
    sf = _placeholders(p.signature_format)
    if sf.count("signature") != 1:
        raise ProfileError(
            f"{where}: signature_format must contain {SIGNATURE} exactly once "
            f"(got {p.signature_format!r})"
        )
    unknown = sorted(set(sf) - {"signature", "timestamp"})
    if unknown:
        raise ProfileError(
            f"{where}: signature_format has unknown placeholder(s) {unknown}; "
            "allowed: {signature}, {timestamp}"
        )

    # --- headers --------------------------------------------------------------
    for header in (p.signature_header, *p.extra_headers.keys()):
        if not _HEADER_NAME_RE.match(header):
            raise ProfileError(f"{where}: {header!r} is not a valid HTTP header name")

    # --- timestamp consistency ------------------------------------------------
    mentions_ts = "timestamp" in sp or "timestamp" in sf
    if p.timestamp is None:
        if mentions_ts:
            raise ProfileError(
                f"{where}: templates use {TIMESTAMP} but the profile has no 'timestamp' section"
            )
    else:
        if p.timestamp.tolerance_seconds <= 0:
            raise ProfileError(f"{where}: timestamp.tolerance_seconds must be positive")
        if "timestamp" not in sp:
            # A timestamp that is sent but not signed can be rewritten by an
            # attacker at will, so it provides no replay protection at all.
            raise ProfileError(
                f"{where}: a timestamp section requires {TIMESTAMP} in signed_payload; "
                "an unsigned timestamp provides no replay protection"
            )
        ts_header = p.timestamp.header
        if ts_header is None and "timestamp" not in sf:
            raise ProfileError(
                f"{where}: the timestamp is never sent. Put {TIMESTAMP} in "
                "signature_format or set timestamp.header"
            )
        if ts_header is not None:
            if not _HEADER_NAME_RE.match(ts_header):
                raise ProfileError(f"{where}: {ts_header!r} is not a valid HTTP header name")
            if ts_header.lower() == p.signature_header.lower():
                raise ProfileError(f"{where}: timestamp.header must differ from signature_header")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_TOP_LEVEL_KEYS = {
    "name",
    "description",
    "algorithm",
    "signed_payload",
    "signature_header",
    "signature_format",
    "signature_encoding",
    "secret_encoding",
    "timestamp",
    "content_type",
    "extra_headers",
    "references",
}
_REQUIRED_KEYS = {
    "name",
    "description",
    "algorithm",
    "signed_payload",
    "signature_header",
    "signature_format",
}
_TIMESTAMP_KEYS = {"tolerance_seconds", "header"}


def _req_str(data: Mapping[str, Any], key: str, src: str) -> str:
    value = data[key]
    if not isinstance(value, str):
        raise ProfileError(f"{src}: {key!r} must be a string, got {type(value).__name__}")
    return value


def _enum(enum_cls: type[StrEnum], value: Any, key: str, src: str) -> Any:
    try:
        return enum_cls(str(value).lower())
    except ValueError:
        allowed = ", ".join(m.value for m in enum_cls)
        raise ProfileError(f"{src}: {key!r} must be one of: {allowed} (got {value!r})") from None


def profile_from_dict(data: Any, *, source: str = "<dict>") -> ProviderProfile:
    """Build and validate a profile from parsed YAML/JSON.

    Unknown keys are an error, so a typo such as ``signed_paylaod`` fails
    loudly instead of being silently ignored.
    """
    if not isinstance(data, Mapping):
        raise ProfileError(f"{source}: a profile must be a mapping/object at the top level")

    unknown = sorted(set(data) - _TOP_LEVEL_KEYS)
    if unknown:
        raise ProfileError(f"{source}: unknown key(s) {unknown}")
    missing = sorted(_REQUIRED_KEYS - set(data))
    if missing:
        raise ProfileError(f"{source}: missing required key(s) {missing}")

    timestamp: TimestampSpec | None = None
    ts_raw = data.get("timestamp")
    if ts_raw is not None:
        if not isinstance(ts_raw, Mapping):
            raise ProfileError(f"{source}: 'timestamp' must be a mapping")
        bad = sorted(set(ts_raw) - _TIMESTAMP_KEYS)
        if bad:
            raise ProfileError(f"{source}: unknown key(s) in 'timestamp': {bad}")
        tol = ts_raw.get("tolerance_seconds", 300)
        if not isinstance(tol, int) or isinstance(tol, bool):
            raise ProfileError(f"{source}: timestamp.tolerance_seconds must be an integer")
        ts_header = ts_raw.get("header")
        if ts_header is not None and not isinstance(ts_header, str):
            raise ProfileError(f"{source}: timestamp.header must be a string")
        timestamp = TimestampSpec(tolerance_seconds=tol, header=ts_header)

    extra_raw = data.get("extra_headers") or {}
    if not isinstance(extra_raw, Mapping) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in extra_raw.items()
    ):
        raise ProfileError(f"{source}: 'extra_headers' must map header names to strings")

    refs_raw = data.get("references") or []
    if not isinstance(refs_raw, list) or not all(isinstance(r, str) for r in refs_raw):
        raise ProfileError(f"{source}: 'references' must be a list of strings")

    content_type = data.get("content_type", "application/json")
    if not isinstance(content_type, str):
        raise ProfileError(f"{source}: 'content_type' must be a string")

    try:
        return ProviderProfile(
            name=_req_str(data, "name", source),
            description=_req_str(data, "description", source),
            algorithm=_enum(HashAlgorithm, data["algorithm"], "algorithm", source),
            signed_payload=_req_str(data, "signed_payload", source),
            signature_header=_req_str(data, "signature_header", source),
            signature_format=_req_str(data, "signature_format", source),
            signature_encoding=_enum(
                Encoding, data.get("signature_encoding", "hex"), "signature_encoding", source
            ),
            secret_encoding=_enum(
                SecretEncoding, data.get("secret_encoding", "utf8"), "secret_encoding", source
            ),
            timestamp=timestamp,
            content_type=content_type,
            extra_headers=MappingProxyType(dict(extra_raw)),
            references=tuple(refs_raw),
        )
    except ProfileError as exc:
        raise ProfileError(f"{source}: {exc}") from None


def load_profile_file(path: str | Path) -> ProviderProfile:
    """Load a profile from a ``.yaml``/``.yml`` or ``.json`` file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"cannot read profile file {path}: {exc.strerror}") from None
    try:
        # yaml.safe_load only builds plain data types. yaml.load() can construct
        # arbitrary Python objects from a crafted file. Never use it on input
        # you did not write.
        data = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        kind = "JSON" if path.suffix.lower() == ".json" else "YAML"
        raise ProfileError(f"{path}: not valid {kind}: {exc}") from None
    return profile_from_dict(data, source=str(path))


def _builtin_dir() -> Any:
    return resources.files("sigaudit").joinpath("builtin_profiles")


def builtin_profile_names() -> list[str]:
    return sorted(
        entry.name.removesuffix(".yaml")
        for entry in _builtin_dir().iterdir()
        if entry.name.endswith(".yaml")
    )


def builtin_profile_text(name: str) -> str:
    if name not in builtin_profile_names():
        raise ProfileError(
            f"unknown built-in profile {name!r}; available: {', '.join(builtin_profile_names())}"
        )
    text: str = _builtin_dir().joinpath(f"{name}.yaml").read_text(encoding="utf-8")
    return text


def load_builtin_profile(name: str) -> ProviderProfile:
    data = yaml.safe_load(builtin_profile_text(name))
    return profile_from_dict(data, source=f"built-in profile {name!r}")


def resolve_profile(name_or_path: str) -> ProviderProfile:
    """Load a built-in profile by name, or a profile file by path."""
    candidate = Path(name_or_path)
    if candidate.suffix.lower() in {".yaml", ".yml", ".json"} or candidate.exists():
        return load_profile_file(candidate)
    return load_builtin_profile(name_or_path)
