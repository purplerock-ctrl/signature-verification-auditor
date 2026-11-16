"""The authorization gate. Nothing is sent until it is passed.

Sending forged requests to a system you do not own, or are not explicitly
permitted to test, may be illegal (e.g. under computer-misuse laws) even when
the requests are harmless. The gate does not try to *verify* authorization;
it cannot. Its job is to make sure every run is a deliberate decision by
someone who has thought about it, and to record that decision in the report.

* ``--i-am-authorized`` records a non-interactive confirmation (CI, scripts).
* Otherwise, on a terminal, the operator must **type the target's hostname**.
  This is stronger than ``y/N`` because it also catches pointing the tool at
  the wrong environment, e.g. production instead of staging.
* With no flag and no terminal, the gate refuses.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, TextIO
from urllib.parse import urlsplit

REMINDER = (
    "Only test endpoints you own or are explicitly authorized to test. "
    "Unauthorized testing may be illegal."
)

AuthMethod = Literal["flag", "interactive", "demo"]


class AuthorizationRefused(Exception):
    """The operator did not confirm authorization. Nothing was sent."""


@dataclass(frozen=True, slots=True)
class AuthorizationRecord:
    method: AuthMethod
    target_host: str
    confirmed_at: datetime
    scope_note: str | None = None

    def statement(self) -> str:
        how = {
            "flag": "via the --i-am-authorized flag",
            "interactive": "by typing the target hostname at an interactive prompt",
            "demo": "automatically: the target was sigaudit's own local demo receiver",
        }[self.method]
        text = (
            f"The operator confirmed authorization to test {self.target_host} {how} "
            f"at {self.confirmed_at.isoformat(timespec='seconds')}."
        )
        if self.scope_note:
            text += f" Scope note: {self.scope_note}"
        return text


def target_host(url: str) -> str:
    host = urlsplit(url).hostname
    if not host:
        raise ValueError(f"cannot determine the host of {url!r}")
    return host.lower()


def require_authorization(
    url: str,
    *,
    flag: bool,
    scope_note: str | None,
    is_tty: bool,
    input_fn: Callable[[str], str] = input,
    out: TextIO,
) -> AuthorizationRecord:
    """Return a record of the confirmation, or raise :class:`AuthorizationRefused`."""
    host = target_host(url)
    print(f"WARNING: {REMINDER}", file=out)

    if flag:
        return AuthorizationRecord(
            method="flag", target_host=host, confirmed_at=datetime.now(UTC), scope_note=scope_note
        )

    if not is_tty:
        raise AuthorizationRefused(
            "refusing to send: no interactive terminal to confirm authorization. "
            "Re-run with --i-am-authorized if you are authorized to test this endpoint."
        )

    print(
        f"sigaudit is about to send deliberately forged webhook requests to:\n  {url}",
        file=out,
    )
    try:
        answer = input_fn(f"Type the target host ({host}) to confirm you are authorized: ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != host:
        raise AuthorizationRefused("confirmation did not match the target host; nothing was sent")
    return AuthorizationRecord(
        method="interactive",
        target_host=host,
        confirmed_at=datetime.now(UTC),
        scope_note=scope_note,
    )
