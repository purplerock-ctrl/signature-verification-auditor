"""Human-readable report, laid out to be attached to a bug report or ticket."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from sigaudit.report import http_request_text
from sigaudit.results import AuditReport, CaseResult, Verdict

VERDICT_LABEL = {
    Verdict.PASS: "PASS",
    Verdict.FINDING: "**FINDING**",
    Verdict.INCONCLUSIVE: "inconclusive",
    Verdict.SKIPPED: "skipped",
    Verdict.ERROR: "error",
}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _fence(text: str, lang: str = "") -> str:
    # Use a fence longer than any backtick run inside the text.
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


def _observed(r: CaseResult) -> str:
    if not r.sent:
        return "not sent"
    if r.response is None:
        return "no response"
    return r.outcome.value if r.outcome else "-"


def _response_block(r: CaseResult) -> list[str]:
    if r.response is None:
        return [f"**Response:** none ({r.note or 'no response'})", ""]
    resp = r.response
    lines = [
        f"**Response:** HTTP `{resp.status_code}` in {resp.elapsed_ms:.0f} ms"
        + (f", `{resp.content_type}`" if resp.content_type else ""),
        "",
        _fence(resp.snippet + ("\n[... truncated]" if resp.truncated else "")),
        "",
    ]
    return lines


def render_markdown(report: AuditReport) -> str:
    host = urlsplit(report.target_url).netloc
    p = report.profile
    out: list[str] = [
        f"# Webhook signature verification audit: {host}",
        "",
        f"> **{report.summary_line()}**",
        "",
        "| | |",
        "|---|---|",
        f"| Target | `{_cell(report.target_url)}` |",
        f"| Profile | `{p.name}`: {_cell(p.description)} |",
        f"| Tool | sigaudit {report.tool_version} |",
        f"| Run ID | `{report.run_id}` |",
        f"| Started | {report.started_at.isoformat(timespec='seconds')} |",
        f"| Finished | {report.finished_at.isoformat(timespec='seconds')} |",
        f"| Request rate | {report.rate_per_second:g} req/s |",
        f"| Counted as accepted | {_cell(report.classifier['accepted_when'])} |",
        f"| Counted as rejected | {_cell(report.classifier['rejected_when'])} |",
        "",
        "## Authorization",
        "",
        report.authorization.statement()
        if report.authorization
        else "No authorization record was attached to this run.",
        "",
        "## Results",
        "",
        "| # | Case | Expected | Observed | HTTP | Verdict |",
        "|---|---|---|---|---|---|",
    ]
    for r in report.results:
        status = str(r.response.status_code) if r.response else "-"
        out.append(
            f"| {r.case.number} | {_cell(r.case.title)} | {r.case.expectation.value} "
            f"| {_observed(r)} | {status} | {VERDICT_LABEL[r.verdict]} |"
        )
    out.append("")

    findings = report.findings
    if findings:
        out += ["## Findings", ""]
        for i, r in enumerate(findings, 1):
            assert r.request is not None
            out += [
                f"### {i}. {r.case.title} ({r.case.severity.value})",
                "",
                f"**Risk:** {r.case.risk}",
                "",
                f"**Recommended fix:** {r.case.fix}",
                "",
                f"**What was sent:** {r.case.description}",
                "",
                _fence(http_request_text(r.request), "http"),
                "",
                *_response_block(r),
            ]

    notes = [r for r in report.results if r.note and r.verdict is not Verdict.FINDING]
    if notes:
        out += ["## Notes", ""]
        out += [f"- **{r.case.number}. {r.case.title}:** {r.note}" for r in notes]
        out.append("")

    out += [
        "## About this audit",
        "",
        "Each request breaks exactly one part of a validly signed webhook. A correctly "
        "implemented receiver rejects all of them and accepts only the valid control. Every "
        "accepted bad request is a finding. Each request carried a unique event ID "
        f"(prefix `evt_sigaudit_{report.run_id}_`) so it can be traced in the receiver's logs.",
        "",
        "Limitations: the audit observes HTTP responses only. A receiver that returns 2xx and "
        "then discards the event later will be reported as accepting it (confirm in its logs). "
        "Timing-unsafe signature comparison cannot be measured reliably over a network and is "
        "not tested; check that the receiver uses a constant-time comparison.",
        "",
    ]
    if p.references:
        out += ["Provider documentation:", ""] + [f"- {ref}" for ref in p.references] + [""]
    return "\n".join(out)


def write_markdown(report: AuditReport, path: str | Path) -> None:
    Path(path).write_text(render_markdown(report), encoding="utf-8")
