"""End-to-end: the auditor against the local receiver, correct and broken."""

from __future__ import annotations

import time
from collections.abc import Sequence

import httpx
import pytest

from sigaudit.cases import ALL_CASES, AuditCase, BuildContext, select_cases
from sigaudit.classify import Classifier, Outcome, ResponseMatcher
from sigaudit.demo_server import DemoReceiver, Flaw, Scheme
from sigaudit.profiles import load_builtin_profile
from sigaudit.results import AuditReport, ExitCode, Verdict
from sigaudit.runner import (
    NOTE_5XX,
    NOTE_CONTROL_FAILED,
    NOTE_NO_TIMESTAMP,
    AuditConfig,
    RateLimiter,
    RunnerConfigError,
    run_audit,
)
from sigaudit.signing import Signer
from tests.conftest import SECRET, ReceiverFactory

ALL_NEGATIVE = {c.number for c in ALL_CASES if c.number != 1}


def audit(
    rx: DemoReceiver,
    *,
    secret: str = SECRET,
    classifier: Classifier | None = None,
    cases: Sequence[AuditCase] = ALL_CASES,
    url: str | None = None,
) -> AuditReport:
    profile = load_builtin_profile(rx.config.scheme.value)
    ctx = BuildContext.create(
        url=url or rx.url, signer=Signer.from_secret(profile, secret), now=int(time.time())
    )
    config = AuditConfig(
        ctx=ctx,
        cases=cases,
        classifier=classifier or Classifier(),
        authorization=None,
        rate=5.0,
        timeout=5.0,
    )
    return run_audit(config, sleep=lambda _s: None)


def finding_numbers(report: AuditReport) -> set[int]:
    return {r.case.number for r in report.findings}


@pytest.mark.parametrize("scheme", list(Scheme))
def test_correct_receiver_has_no_findings(make_receiver: ReceiverFactory, scheme: Scheme) -> None:
    report = audit(make_receiver(scheme=scheme))
    assert report.findings == ()
    assert report.control_ok
    assert report.exit_code() is ExitCode.CLEAN
    verdicts = {r.case.id: r.verdict for r in report.results}
    if scheme is Scheme.GENERIC:
        assert verdicts.pop("replay-old-timestamp") is Verdict.SKIPPED
    assert set(verdicts.values()) == {Verdict.PASS}


# Each flaw must produce exactly these findings: no more, no fewer.
EXPECTED: list[tuple[Scheme, Flaw, set[int]]] = [
    (Scheme.STRIPE, Flaw.NO_VERIFICATION, ALL_NEGATIVE),
    (Scheme.GENERIC, Flaw.NO_VERIFICATION, ALL_NEGATIVE - {7}),  # replay N/A without timestamp
    (Scheme.STRIPE, Flaw.SKIP_IF_MISSING, {2, 3}),
    (Scheme.GENERIC, Flaw.SKIP_IF_MISSING, {2, 3}),
    (Scheme.STRIPE, Flaw.FAIL_OPEN, {3, 4}),  # empty Stripe header fails to parse
    (Scheme.GENERIC, Flaw.FAIL_OPEN, {4}),  # empty hex decodes fine, then mismatches
    (Scheme.STRIPE, Flaw.LOG_ONLY, ALL_NEGATIVE - {2}),
    (Scheme.GENERIC, Flaw.LOG_ONLY, ALL_NEGATIVE - {2, 7}),
    (Scheme.STRIPE, Flaw.NO_TIMESTAMP_CHECK, {7}),
    (Scheme.STRIPE, Flaw.ACCEPT_SHA1, {8}),
    (Scheme.GENERIC, Flaw.ACCEPT_SHA1, {8}),
]


@pytest.mark.parametrize(("scheme", "flaw", "expected"), EXPECTED)
def test_each_flaw_is_detected_precisely(
    make_receiver: ReceiverFactory, scheme: Scheme, flaw: Flaw, expected: set[int]
) -> None:
    report = audit(make_receiver(scheme=scheme, flaws=frozenset({flaw})))
    assert report.control_ok
    assert finding_numbers(report) == expected
    assert report.exit_code() is ExitCode.FINDINGS
    for result in report.findings:
        assert result.outcome is Outcome.ACCEPTED
        assert result.request is not None
        assert result.response is not None
        assert result.response.status_code == 200


def test_combined_flaws(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver(flaws=frozenset({Flaw.SKIP_IF_MISSING, Flaw.NO_TIMESTAMP_CHECK}))
    assert finding_numbers(audit(rx)) == {2, 3, 7}


def test_control_failure_stops_the_run(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    report = audit(rx, secret="the-wrong-secret")
    assert not report.control_ok
    assert report.exit_code() is ExitCode.INCONCLUSIVE
    assert len(rx.received) == 1  # only the control was sent
    for result in report.results[1:]:
        assert not result.sent
        assert result.verdict in (Verdict.INCONCLUSIVE, Verdict.SKIPPED)
    assert report.results[1].note == NOTE_CONTROL_FAILED
    assert "INCONCLUSIVE" in report.summary_line()


def test_control_failure_is_not_hidden_by_a_broken_endpoint(make_receiver: ReceiverFactory) -> None:
    # An endpoint that accepts everything accepts the control too, so it runs fully.
    rx = make_receiver(flaws=frozenset({Flaw.NO_VERIFICATION}))
    report = audit(rx, secret="the-wrong-secret")
    assert report.control_ok
    assert len(report.findings) == 7


def test_body_matchers_with_always_200_app(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver(reject_status=200, flaws=frozenset({Flaw.NO_TIMESTAMP_CHECK}))
    naive = audit(rx)
    assert len(naive.findings) == 7  # default 2xx rule is fooled by 200-on-reject

    classifier = Classifier(
        accept=ResponseMatcher.build("2xx", '"received": true'),
        reject=ResponseMatcher.build(body_contains="invalid signature"),
    )
    tuned = audit(rx, classifier=classifier)
    assert finding_numbers(tuned) == {7}


def test_unclear_responses_are_inconclusive(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    classifier = Classifier(
        accept=ResponseMatcher.build("2xx"), reject=ResponseMatcher.build("401")
    )
    report = audit(rx, classifier=classifier)  # receiver rejects with 400, not 401
    assert report.control_ok
    sent_negatives = [r for r in report.results[1:] if r.sent]
    assert sent_negatives
    assert all(r.verdict is Verdict.INCONCLUSIVE for r in sent_negatives)
    assert report.exit_code() is ExitCode.INCONCLUSIVE


def test_5xx_rejection_gets_a_note(make_receiver: ReceiverFactory) -> None:
    report = audit(make_receiver(reject_status=500))
    assert report.findings == ()
    assert report.results[1].note == NOTE_5XX


def test_no_timestamp_profile_skips_replay(make_receiver: ReceiverFactory) -> None:
    report = audit(make_receiver(scheme=Scheme.GENERIC))
    replay = next(r for r in report.results if r.case.id == "replay-old-timestamp")
    assert replay.verdict is Verdict.SKIPPED
    assert replay.note == NOTE_NO_TIMESTAMP
    assert report.exit_code() is ExitCode.CLEAN


def test_case_selection(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    report = audit(rx, cases=select_cases(only=["tampered-body"]))
    assert [r.case.id for r in report.results] == ["valid", "tampered-body"]
    assert len(rx.received) == 2


def test_connection_error_is_reported_not_raised() -> None:
    profile = load_builtin_profile("stripe")
    ctx = BuildContext.create(
        url="http://127.0.0.1:9/webhook",  # discard port: nothing listens
        signer=Signer.from_secret(profile, SECRET),
        now=int(time.time()),
    )
    report = run_audit(
        AuditConfig(
            ctx=ctx, cases=ALL_CASES, classifier=Classifier(), authorization=None, timeout=2.0
        ),
        sleep=lambda _s: None,
    )
    assert report.results[0].verdict is Verdict.ERROR
    assert "No response" in report.results[0].note
    assert report.exit_code() is ExitCode.INCONCLUSIVE
    assert not any(r.sent for r in report.results[1:])


def test_redirects_are_not_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/webhook":
            return httpx.Response(302, headers={"Location": "/login"})
        return httpx.Response(200, text="login page")

    profile = load_builtin_profile("generic-hmac-sha256")
    ctx = BuildContext.create(
        url="http://example.test/webhook", signer=Signer.from_secret(profile, SECRET), now=0
    )
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    report = run_audit(
        AuditConfig(ctx=ctx, cases=ALL_CASES, classifier=Classifier(), authorization=None),
        client=client,
        sleep=lambda _s: None,
    )
    assert report.results[0].response is not None
    assert report.results[0].response.status_code == 302
    assert not report.control_ok


def test_large_response_bodies_are_capped() -> None:
    big = "x" * 200_000
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=big)))
    profile = load_builtin_profile("generic-hmac-sha256")
    ctx = BuildContext.create(
        url="http://e.test/", signer=Signer.from_secret(profile, SECRET), now=0
    )
    report = run_audit(
        AuditConfig(ctx=ctx, cases=ALL_CASES[:1], classifier=Classifier(), authorization=None),
        client=client,
        sleep=lambda _s: None,
    )
    response = report.results[0].response
    assert response is not None
    assert len(response.snippet) == 500
    assert response.truncated


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_rate_limiter_spaces_requests() -> None:
    clock = FakeClock()
    limiter = RateLimiter(2.0, clock=clock, sleep=clock.sleep)
    limiter.wait()
    limiter.wait()
    clock.now += 0.2
    limiter.wait()
    assert clock.sleeps == pytest.approx([0.5, 0.3])


def test_runner_uses_the_rate_limiter(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    clock = FakeClock()
    profile = load_builtin_profile("stripe")
    ctx = BuildContext.create(
        url=rx.url, signer=Signer.from_secret(profile, SECRET), now=int(time.time())
    )
    run_audit(
        AuditConfig(
            ctx=ctx, cases=ALL_CASES, classifier=Classifier(), authorization=None, rate=1.0
        ),
        sleep=clock.sleep,
        clock=clock,
    )
    assert len(clock.sleeps) == len(ALL_CASES) - 1
    assert all(s == pytest.approx(1.0) for s in clock.sleeps)


@pytest.mark.parametrize("rate", [0, -1, 5.01, 100])
def test_rate_ceiling(rate: float) -> None:
    with pytest.raises(RunnerConfigError):
        RateLimiter(rate)


def test_control_case_is_required() -> None:
    profile = load_builtin_profile("stripe")
    ctx = BuildContext.create(
        url="http://e.test/", signer=Signer.from_secret(profile, SECRET), now=0
    )
    with pytest.raises(RunnerConfigError, match="control"):
        run_audit(
            AuditConfig(ctx=ctx, cases=ALL_CASES[1:], classifier=Classifier(), authorization=None)
        )
