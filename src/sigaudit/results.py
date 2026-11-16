"""Result types shared by the runner and the reporters."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, StrEnum

from sigaudit.authorization import AuthorizationRecord
from sigaudit.cases import AuditCase, Expectation, RequestSpec
from sigaudit.classify import Outcome
from sigaudit.profiles import ProviderProfile


class Verdict(StrEnum):
    PASS = "pass"  # noqa: S105 - behaved correctly
    FINDING = "finding"  # a bad request was accepted
    INCONCLUSIVE = "inconclusive"  # the result cannot be interpreted
    SKIPPED = "skipped"  # not applicable to this profile
    ERROR = "error"  # no HTTP response


class ExitCode(IntEnum):
    CLEAN = 0  # every negative case was rejected and the control was accepted
    FINDINGS = 1  # at least one bad request was accepted
    INCONCLUSIVE = 2  # control not accepted, or errors/unclear responses
    REFUSED = 3  # authorization not confirmed, or a usage/configuration error


@dataclass(frozen=True, slots=True)
class ResponseRecord:
    status_code: int
    snippet: str
    content_type: str | None
    elapsed_ms: float
    truncated: bool


@dataclass(frozen=True, slots=True)
class CaseResult:
    case: AuditCase
    verdict: Verdict
    outcome: Outcome | None  # None when the request was not sent
    request: RequestSpec | None  # None when not sent
    response: ResponseRecord | None  # None when not sent or no response
    note: str = ""

    @property
    def sent(self) -> bool:
        return self.request is not None


@dataclass(frozen=True, slots=True)
class AuditReport:
    tool_version: str
    run_id: str
    target_url: str
    profile: ProviderProfile
    classifier: dict[str, str]
    authorization: AuthorizationRecord | None
    started_at: datetime
    finished_at: datetime
    rate_per_second: float
    replay_age_seconds: int
    results: tuple[CaseResult, ...]

    @property
    def control(self) -> CaseResult:
        return next(r for r in self.results if r.case.expectation is Expectation.ACCEPT)

    @property
    def control_ok(self) -> bool:
        return self.control.verdict is Verdict.PASS

    @property
    def findings(self) -> tuple[CaseResult, ...]:
        return tuple(r for r in self.results if r.verdict is Verdict.FINDING)

    def counts(self) -> dict[str, int]:
        c = Counter(r.verdict for r in self.results)
        return {v.value: c.get(v, 0) for v in Verdict}

    def exit_code(self) -> ExitCode:
        if self.findings:
            # Findings are definitive even if other cases were inconclusive.
            return ExitCode.FINDINGS
        if not self.control_ok or any(
            r.verdict in (Verdict.INCONCLUSIVE, Verdict.ERROR) for r in self.results
        ):
            return ExitCode.INCONCLUSIVE
        return ExitCode.CLEAN

    def summary_line(self) -> str:
        if not self.control_ok:
            return (
                "INCONCLUSIVE: the valid control request was not accepted, so rejections "
                "prove nothing. Check the secret, profile and matchers."
            )
        n = len(self.findings)
        if n:
            plural = "S" if n != 1 else ""
            return f"{n} FINDING{plural}: the endpoint accepted requests it should have rejected."
        if self.exit_code() is ExitCode.INCONCLUSIVE:
            return "No findings, but some cases were inconclusive or errored. See details."
        return "No findings: every bad request was rejected and the valid control was accepted."
