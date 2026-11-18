"""Audit the example Flask receiver, so the case study in its README stays true.

Also a cross-check worth having: the correct endpoint uses Stripe's official
library, so a passing control case proves sigaudit's Stripe-style signatures
are exactly what Stripe's own verifier expects.

Skipped unless the example's dependencies are installed (pip install -e ".[examples]").
"""

from __future__ import annotations

import importlib.util
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("flask")
pytest.importorskip("stripe")

from werkzeug.serving import make_server

from sigaudit.cases import ALL_CASES, BuildContext
from sigaudit.classify import Classifier
from sigaudit.profiles import load_builtin_profile
from sigaudit.results import AuditReport, ExitCode, Verdict
from sigaudit.runner import AuditConfig, run_audit
from sigaudit.signing import Signer

APP_PATH = Path(__file__).resolve().parent.parent / "examples" / "stripe-receiver" / "app.py"
SECRET = "whsec_local_example_secret"


def load_example() -> Any:
    spec = importlib.util.spec_from_file_location("stripe_receiver_example", APP_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def base_url() -> Iterator[str]:
    app = load_example().create_app(SECRET)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join(timeout=5)


def audit(url: str) -> AuditReport:
    signer = Signer.from_secret(load_builtin_profile("stripe"), SECRET)
    ctx = BuildContext.create(url=url, signer=signer, now=int(time.time()))
    config = AuditConfig(
        ctx=ctx, cases=ALL_CASES, classifier=Classifier(), authorization=None, rate=5.0
    )
    return run_audit(config, sleep=lambda _s: None)


def test_official_library_endpoint_is_clean(base_url: str) -> None:
    report = audit(f"{base_url}/webhook")
    assert report.control_ok, "Stripe's own library rejected sigaudit's valid signature"
    assert report.findings == ()
    assert report.exit_code() is ExitCode.CLEAN
    assert all(r.verdict is Verdict.PASS for r in report.results)


def test_naive_endpoint_has_the_documented_findings(base_url: str) -> None:
    report = audit(f"{base_url}/webhook-naive")
    assert report.control_ok
    assert {r.case.id for r in report.findings} == {
        "missing-signature",
        "empty-signature",
        "replay-old-timestamp",
    }
    assert report.exit_code() is ExitCode.FINDINGS
