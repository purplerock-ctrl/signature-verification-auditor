"""Machine-readable report. Stable keys; ``schema_version`` bumps on breaking changes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sigaudit.report import body_for_report, redact_headers
from sigaudit.results import AuditReport, CaseResult

SCHEMA_VERSION = 1


def _result(r: CaseResult) -> dict[str, Any]:
    out: dict[str, Any] = {
        "number": r.case.number,
        "id": r.case.id,
        "title": r.case.title,
        "expectation": r.case.expectation.value,
        "severity": r.case.severity.value,
        "verdict": r.verdict.value,
        "outcome": r.outcome.value if r.outcome else None,
        "description": r.case.description,
        "risk": r.case.risk,
        "fix": r.case.fix,
        "note": r.note or None,
        "sent": r.sent,
        "request": None,
        "response": None,
    }
    if r.request is not None:
        text, encoding, truncated = body_for_report(r.request.body)
        out["request"] = {
            "method": r.request.method,
            "url": r.request.url,
            "headers": redact_headers(r.request.headers),
            "body": text,
            "body_encoding": encoding,
            "body_truncated": truncated,
        }
    if r.response is not None:
        out["response"] = {
            "status_code": r.response.status_code,
            "content_type": r.response.content_type,
            "body_snippet": r.response.snippet,
            "body_truncated": r.response.truncated,
            "elapsed_ms": r.response.elapsed_ms,
        }
    return out


def report_to_dict(report: AuditReport) -> dict[str, Any]:
    p = report.profile
    auth = report.authorization
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "sigaudit", "version": report.tool_version},
        "run_id": report.run_id,
        "target": report.target_url,
        "started_at": report.started_at.isoformat(timespec="seconds"),
        "finished_at": report.finished_at.isoformat(timespec="seconds"),
        "profile": {
            "name": p.name,
            "description": p.description,
            "algorithm": p.algorithm.value,
            "signature_header": p.signature_header,
            "signed_payload": p.signed_payload,
            "timestamp_tolerance_seconds": p.timestamp.tolerance_seconds if p.timestamp else None,
            "references": list(p.references),
        },
        "settings": {
            "rate_per_second": report.rate_per_second,
            "replay_age_seconds": report.replay_age_seconds,
            "classification": report.classifier,
        },
        "authorization": None
        if auth is None
        else {
            "method": auth.method,
            "target_host": auth.target_host,
            "confirmed_at": auth.confirmed_at.isoformat(timespec="seconds"),
            "scope_note": auth.scope_note,
            "statement": auth.statement(),
        },
        "summary": {
            "control_accepted": report.control_ok,
            "findings": len(report.findings),
            "counts": report.counts(),
            "exit_code": int(report.exit_code()),
            "message": report.summary_line(),
        },
        "results": [_result(r) for r in report.results],
    }


def render_json(report: AuditReport) -> str:
    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n"


def write_json(report: AuditReport, path: str | Path) -> None:
    Path(path).write_text(render_json(report), encoding="utf-8")
