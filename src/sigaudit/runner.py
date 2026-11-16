"""Send the audit requests and turn responses into verdicts.

Rules worth knowing:

* **The control case goes first and gates everything.** If a correctly signed
  request is not accepted, a rejected forgery tells you nothing (the endpoint
  may simply reject everything). The remaining cases are then *not sent* and
  are marked INCONCLUSIVE. This also keeps traffic to a minimum.
* **Requests are rate-limited** (default 1/s, hard ceiling 5/s) and sent one
  at a time. This is an auditor, not a load generator.
* **Redirects are not followed.** A 302 to a login page that returns 200 must
  not look like "accepted".
* **Response bodies are capped** when read; we only need a snippet.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from sigaudit import __version__
from sigaudit.authorization import AuthorizationRecord
from sigaudit.cases import AuditCase, BuildContext, Expectation, RequestSpec
from sigaudit.classify import Classifier, Outcome
from sigaudit.results import AuditReport, CaseResult, ResponseRecord, Verdict

DEFAULT_RATE = 1.0
MAX_RATE = 5.0
DEFAULT_TIMEOUT = 10.0
SNIPPET_CHARS = 500
MAX_BODY_BYTES = 64 * 1024

NOTE_CONTROL_FAILED = (
    "Not sent: the valid control request was not accepted, so a rejection here would prove nothing."
)
NOTE_NO_TIMESTAMP = (
    "Not applicable: this profile has no signed timestamp, so the scheme itself has no "
    "replay protection. Mitigate by deduplicating on event ID."
)
NOTE_5XX = (
    "Rejected with a server error: verification may be raising an unhandled exception "
    "instead of returning a clean 4xx."
)
NOTE_3XX = (
    "Rejected with a redirect (not followed). Make sure the redirect target does not "
    "process the event."
)


class RunnerConfigError(ValueError):
    pass


class RateLimiter:
    """Ensures at least ``1/rate`` seconds between the start of consecutive requests."""

    def __init__(
        self,
        rate: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not 0 < rate <= MAX_RATE:
            raise RunnerConfigError(f"rate must be > 0 and at most {MAX_RATE} requests/second")
        self.interval = 1.0 / rate
        self._clock = clock
        self._sleep = sleep
        self._last: float | None = None

    def wait(self) -> None:
        now = self._clock()
        if self._last is not None:
            remaining = self.interval - (now - self._last)
            if remaining > 0:
                self._sleep(remaining)
                now = self._clock()
        self._last = now


@dataclass(frozen=True, slots=True)
class AuditConfig:
    ctx: BuildContext
    cases: Sequence[AuditCase]
    classifier: Classifier
    authorization: AuthorizationRecord | None
    rate: float = DEFAULT_RATE
    timeout: float = DEFAULT_TIMEOUT
    verify: str | bool = True  # True, or a path to a CA bundle; never disabled


def judge(case: AuditCase, outcome: Outcome, status: int | None) -> tuple[Verdict, str]:
    """Map an observation to a verdict for this case."""
    if outcome is Outcome.ERROR:
        return Verdict.ERROR, ""
    if outcome is Outcome.UNCLEAR:
        return (
            Verdict.INCONCLUSIVE,
            "Response matched neither (or both) of the accept/reject rules.",
        )
    if case.expectation is Expectation.ACCEPT:
        if outcome is Outcome.ACCEPTED:
            return Verdict.PASS, ""
        return Verdict.INCONCLUSIVE, (
            "Control rejected: check the secret, the profile, and the accept/reject matchers."
        )
    if outcome is Outcome.ACCEPTED:
        return Verdict.FINDING, ""
    if status is not None and 500 <= status <= 599:
        return Verdict.PASS, NOTE_5XX
    if status is not None and 300 <= status <= 399:
        return Verdict.PASS, NOTE_3XX
    return Verdict.PASS, ""


def _send(
    client: httpx.Client,
    req: RequestSpec,
    classifier: Classifier,
    clock: Callable[[], float],
) -> tuple[Outcome, ResponseRecord | None, str]:
    start = clock()
    try:
        with client.stream(req.method, req.url, headers=req.headers, content=req.body) as resp:
            chunks: list[bytes] = []
            size = 0
            truncated = False
            for chunk in resp.iter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY_BYTES:
                    truncated = True
                    break
            raw = b"".join(chunks)[:MAX_BODY_BYTES]
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            status = resp.status_code
            content_type = resp.headers.get("content-type")
    except httpx.HTTPError as exc:
        return Outcome.ERROR, None, f"No response: {type(exc).__name__}: {exc}"
    elapsed_ms = (clock() - start) * 1000
    snippet = text[:SNIPPET_CHARS]
    record = ResponseRecord(
        status_code=status,
        snippet=snippet,
        content_type=content_type,
        elapsed_ms=round(elapsed_ms, 1),
        truncated=truncated or len(text) > SNIPPET_CHARS,
    )
    return classifier.classify(status, text), record, ""


def run_audit(
    config: AuditConfig,
    *,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    on_result: Callable[[CaseResult], None] | None = None,
) -> AuditReport:
    cases = sorted(config.cases, key=lambda c: c.number)
    if not cases or cases[0].expectation is not Expectation.ACCEPT:
        raise RunnerConfigError("the valid control case must be included and run first")
    if config.timeout <= 0:
        raise RunnerConfigError("timeout must be positive")
    limiter = RateLimiter(config.rate, clock=clock, sleep=sleep)
    ctx = config.ctx

    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=config.timeout, follow_redirects=False, verify=config.verify)

    started_at = datetime.now(UTC)
    results: list[CaseResult] = []
    control_failed = False
    try:
        for case in cases:
            if case.requires_timestamp and not ctx.profile.uses_timestamp:
                result = CaseResult(case, Verdict.SKIPPED, None, None, None, NOTE_NO_TIMESTAMP)
            elif control_failed:
                result = CaseResult(
                    case, Verdict.INCONCLUSIVE, None, None, None, NOTE_CONTROL_FAILED
                )
            else:
                req = case.build(ctx)
                limiter.wait()
                outcome, response, error_note = _send(client, req, config.classifier, clock)
                verdict, note = judge(case, outcome, response.status_code if response else None)
                result = CaseResult(case, verdict, outcome, req, response, error_note or note)
                if case.expectation is Expectation.ACCEPT and verdict is not Verdict.PASS:
                    control_failed = True
            results.append(result)
            if on_result is not None:
                on_result(result)
    finally:
        if owns_client:
            client.close()

    return AuditReport(
        tool_version=__version__,
        run_id=ctx.run_id,
        target_url=ctx.url,
        profile=ctx.profile,
        classifier=config.classifier.describe(),
        authorization=config.authorization,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        rate_per_second=config.rate,
        replay_age_seconds=ctx.replay_age_seconds,
        results=tuple(results),
    )
