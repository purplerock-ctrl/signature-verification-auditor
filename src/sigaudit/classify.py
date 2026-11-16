"""Turn an HTTP response into an observation: ACCEPTED, REJECTED or UNCLEAR.

This module only says what *happened*. Whether that is good or bad depends on
the case and is decided in :mod:`sigaudit.runner`.

Apps differ: some return ``200 {"error": ...}`` for rejected events, some
``202`` for everything. So either side can be described with a status spec
and/or a body substring:

==================  ====================================================
rules given         behaviour
==================  ====================================================
neither             2xx = accepted, anything else = rejected
accept only         matches accept = accepted, anything else = rejected
reject only         matches reject = rejected; otherwise 2xx = accepted
both                strict: matching neither (or both) = UNCLEAR
==================  ====================================================
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class Outcome(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNCLEAR = "unclear"
    ERROR = "error"  # no HTTP response (connection refused, timeout, TLS error)


class MatcherError(ValueError):
    pass


_CLASS_RE = re.compile(r"^([1-5])xx$", re.IGNORECASE)
_RANGE_RE = re.compile(r"^(\d{3})-(\d{3})$")


def parse_status_spec(spec: str) -> frozenset[int]:
    """Parse ``"2xx"``, ``"200,202"``, ``"200-204"`` or combinations like ``"2xx,409"``."""
    codes: set[int] = set()
    for raw in spec.split(","):
        token = raw.strip()
        if not token:
            continue
        if m := _CLASS_RE.match(token):
            base = int(m.group(1)) * 100
            codes.update(range(base, base + 100))
        elif m := _RANGE_RE.match(token):
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo > hi:
                raise MatcherError(f"status range {token!r} is backwards")
            codes.update(range(lo, hi + 1))
        elif token.isdigit() and len(token) == 3:
            codes.add(int(token))
        else:
            raise MatcherError(
                f"invalid status token {token!r}; use e.g. 200, 2xx, 200-204 (comma-separated)"
            )
    if not codes:
        raise MatcherError(f"empty status spec {spec!r}")
    if min(codes) < 100 or max(codes) > 599:
        raise MatcherError(f"status codes must be between 100 and 599 (got {spec!r})")
    return frozenset(codes)


@dataclass(frozen=True, slots=True)
class ResponseMatcher:
    """Matches when every given condition holds. ``None`` means 'any'."""

    status_spec: str | None = None
    body_contains: str | None = None
    statuses: frozenset[int] | None = None

    @classmethod
    def build(
        cls, status_spec: str | None = None, body_contains: str | None = None
    ) -> ResponseMatcher:
        if status_spec is None and body_contains is None:
            raise MatcherError("a matcher needs a status spec and/or a body substring")
        if body_contains == "":
            raise MatcherError("body substring must not be empty")
        statuses = parse_status_spec(status_spec) if status_spec is not None else None
        return cls(status_spec=status_spec, body_contains=body_contains, statuses=statuses)

    def matches(self, status: int, body: str) -> bool:
        if self.statuses is not None and status not in self.statuses:
            return False
        return self.body_contains is None or self.body_contains in body

    def describe(self) -> str:
        parts = []
        if self.status_spec is not None:
            parts.append(f"status in {self.status_spec}")
        if self.body_contains is not None:
            parts.append(f"body contains {self.body_contains!r}")
        return " and ".join(parts)


DEFAULT_ACCEPT = ResponseMatcher.build(status_spec="2xx")


@dataclass(frozen=True, slots=True)
class Classifier:
    accept: ResponseMatcher | None = None  # None: the default rule (2xx)
    reject: ResponseMatcher | None = None  # None: anything that is not accepted

    def classify(self, status: int, body: str) -> Outcome:
        if self.accept is not None and self.reject is not None:
            accepted = self.accept.matches(status, body)
            rejected = self.reject.matches(status, body)
            if accepted != rejected:
                return Outcome.ACCEPTED if accepted else Outcome.REJECTED
            return Outcome.UNCLEAR
        if self.reject is not None and self.reject.matches(status, body):
            return Outcome.REJECTED
        accept = self.accept or DEFAULT_ACCEPT
        return Outcome.ACCEPTED if accept.matches(status, body) else Outcome.REJECTED

    def describe(self) -> dict[str, str]:
        if self.accept is not None and self.reject is not None:
            return {
                "accepted_when": self.accept.describe(),
                "rejected_when": self.reject.describe(),
                "otherwise": "unclear (inconclusive)",
            }
        if self.reject is not None:
            return {
                "accepted_when": f"{DEFAULT_ACCEPT.describe()} and not rejected",
                "rejected_when": f"{self.reject.describe()}, or any non-2xx status",
            }
        return {
            "accepted_when": (self.accept or DEFAULT_ACCEPT).describe(),
            "rejected_when": "anything else",
        }
