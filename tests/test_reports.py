from __future__ import annotations

import io
import json
from datetime import UTC, datetime

from rich.console import Console

from sigaudit.authorization import AuthorizationRecord
from sigaudit.cases import ALL_CASES, RequestSpec
from sigaudit.classify import Classifier, Outcome
from sigaudit.profiles import load_builtin_profile
from sigaudit.report import (
    REDACTED,
    body_for_report,
    http_request_text,
    is_sensitive_header,
    redact_headers,
)
from sigaudit.report.json_report import SCHEMA_VERSION, render_json
from sigaudit.report.markdown_report import _fence, render_markdown
from sigaudit.report.terminal import print_summary
from sigaudit.results import AuditReport, CaseResult, ExitCode, ResponseRecord, Verdict

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def make_report(verdicts: dict[int, Verdict]) -> AuditReport:
    results = []
    for case in ALL_CASES:
        verdict = verdicts.get(case.number, Verdict.PASS)
        req = RequestSpec(
            "POST",
            "https://staging.example.test/hooks?x=1",
            {"Content-Type": "application/json", "Stripe-Signature": "t=1,v1=ab"},
            b'{"id":"evt"}',
        )
        resp = ResponseRecord(
            200 if verdict is Verdict.FINDING else 400, "``` ok |", None, 3.0, False
        )
        if case.number == 1:
            resp = ResponseRecord(200, "ok", "application/json", 1.0, False)
        outcome = (
            Outcome.ACCEPTED if verdict is Verdict.FINDING or case.number == 1 else Outcome.REJECTED
        )
        results.append(CaseResult(case, verdict, outcome, req, resp, ""))
    return AuditReport(
        tool_version="0.1.0",
        run_id="abcd1234",
        target_url="https://staging.example.test/hooks?x=1",
        profile=load_builtin_profile("stripe"),
        classifier=Classifier().describe(),
        authorization=AuthorizationRecord("flag", "staging.example.test", NOW, "own staging"),
        started_at=NOW,
        finished_at=NOW,
        rate_per_second=1.0,
        replay_age_seconds=3900,
        results=tuple(results),
    )


def test_sensitive_header_detection() -> None:
    for name in ("Authorization", "cookie", "X-Api-Key", "X-Staging-Token", "Client-Secret"):
        assert is_sensitive_header(name)
    for name in (
        "Stripe-Signature",
        "X-Hub-Signature-256",
        "Content-Type",
        "X-Shopify-Hmac-Sha256",
    ):
        assert not is_sensitive_header(name)
    assert redact_headers({"Authorization": "x", "A": "b"}) == {"Authorization": REDACTED, "A": "b"}


def test_body_for_report() -> None:
    assert body_for_report(b"abc") == ("abc", "utf-8", False)
    assert body_for_report(b"\xff\x00") == ("/wA=", "base64", False)
    text, _, truncated = body_for_report(b"a" * 10, limit=4)
    assert text == "aaaa"
    assert truncated


def test_http_request_text() -> None:
    req = RequestSpec("POST", "https://h.test:8443/p?q=1", {"Authorization": "secret"}, b"{}")
    text = http_request_text(req)
    assert text.startswith("POST /p?q=1 HTTP/1.1\nHost: h.test:8443\n")
    assert "secret" not in text
    assert text.endswith("\n\n{}")


def test_json_report_shape() -> None:
    data = json.loads(render_json(make_report({6: Verdict.FINDING})))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["summary"]["findings"] == 1
    assert data["summary"]["exit_code"] == ExitCode.FINDINGS
    assert data["summary"]["counts"]["finding"] == 1
    assert data["profile"]["name"] == "stripe"
    assert data["authorization"]["statement"].startswith("The operator confirmed")
    assert len(data["results"]) == 8
    tampered = data["results"][5]
    assert tampered["verdict"] == "finding"
    assert tampered["risk"]
    assert tampered["request"]["body"] == '{"id":"evt"}'


def test_markdown_report_findings_and_escaping() -> None:
    md = render_markdown(make_report({2: Verdict.FINDING, 6: Verdict.FINDING}))
    assert md.startswith("# Webhook signature verification audit: staging.example.test")
    assert "2 FINDINGS" in md
    assert "### 1. No signature header (critical)" in md
    assert "### 2. Body modified after signing (critical)" in md
    assert "```http\nPOST /hooks?x=1 HTTP/1.1" in md
    assert "````\n``` ok |\n````" in md  # snippet containing ``` gets a longer fence
    assert "own staging" in md


def test_markdown_clean_report_has_no_findings_section() -> None:
    md = render_markdown(make_report({}))
    assert "## Findings" not in md
    assert "No findings" in md


def test_fence() -> None:
    assert _fence("a").startswith("```\n")
    assert _fence("x ```` y").startswith("`````")


def test_terminal_summary() -> None:
    buf = io.StringIO()
    console = Console(file=buf, no_color=True, width=120)
    print_summary(console, make_report({7: Verdict.FINDING}))
    out = buf.getvalue()
    assert "Replay with an old timestamp" in out
    assert "1 FINDING:" in out
