from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from sigaudit.cli import CliIO, main
from sigaudit.demo_server import Flaw
from sigaudit.results import ExitCode
from tests.conftest import SECRET, ReceiverFactory


class FakeIO(CliIO):
    def __init__(self, *, tty: bool = False, answer: str = "", env: dict[str, str] | None = None):
        super().__init__(
            stdout=io.StringIO(),
            stderr=io.StringIO(),
            is_tty=lambda: tty,
            input_fn=lambda _p: answer,
            getpass_fn=lambda _p: SECRET,
            sleep=lambda _s: None,
            environ={"WEBHOOK_SECRET": SECRET, **(env or {})},
        )

    @property
    def out(self) -> str:
        assert isinstance(self.stdout, io.StringIO)
        return self.stdout.getvalue()

    @property
    def err(self) -> str:
        assert isinstance(self.stderr, io.StringIO)
        return self.stderr.getvalue()


def run_args(url: str, *extra: str) -> list[str]:
    return [
        "run",
        url,
        "--profile",
        "stripe",
        "--secret-env",
        "WEBHOOK_SECRET",
        "--no-color",
        *extra,
    ]


def test_refuses_without_authorization_and_sends_nothing(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    fio = FakeIO(tty=False)
    assert main(run_args(rx.url), fio) == ExitCode.REFUSED
    assert "--i-am-authorized" in fio.err
    assert "Unauthorized testing may be illegal" in fio.err
    assert rx.received == []


def test_interactive_wrong_host_refuses(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    fio = FakeIO(tty=True, answer="yes")
    assert main(run_args(rx.url), fio) == ExitCode.REFUSED
    assert rx.received == []


def test_interactive_correct_host_runs(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    fio = FakeIO(tty=True, answer="127.0.0.1")
    assert main(run_args(rx.url), fio) == ExitCode.CLEAN
    assert len(rx.received) == 8


def test_flag_run_with_findings_and_reports(make_receiver: ReceiverFactory, tmp_path: Path) -> None:
    rx = make_receiver(flaws=frozenset({Flaw.NO_TIMESTAMP_CHECK}))
    json_path, md_path = tmp_path / "r.json", tmp_path / "r.md"
    fio = FakeIO()
    code = main(
        run_args(
            rx.url,
            "--i-am-authorized",
            "--scope-note",
            "own staging",
            "--json-report",
            str(json_path),
            "--markdown-report",
            str(md_path),
            "-H",
            "Authorization: Bearer staging-gateway-token",
            "-H",
            "X-Researcher: alice",
        ),
        fio,
    )
    assert code == ExitCode.FINDINGS
    assert "FINDING" in fio.out
    assert "Unauthorized testing may be illegal" in fio.err

    data = json.loads(json_path.read_text())
    assert data["summary"]["findings"] == 1
    assert data["summary"]["exit_code"] == 1
    assert data["authorization"]["method"] == "flag"
    assert data["authorization"]["scope_note"] == "own staging"
    finding = next(r for r in data["results"] if r["verdict"] == "finding")
    assert finding["id"] == "replay-old-timestamp"
    assert finding["response"]["status_code"] == 200
    assert finding["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert finding["request"]["headers"]["X-Researcher"] == "alice"

    markdown = md_path.read_text()
    assert "## Findings" in markdown
    assert "Replay with an old timestamp" in markdown
    assert "own staging" in markdown

    # The extra header really was sent (redaction is for reports only).
    assert rx.received[0].headers["Authorization"] == "Bearer staging-gateway-token"

    # The signing secret and the redacted token appear in no output at all.
    for text in (fio.out, fio.err, json_path.read_text(), markdown):
        assert SECRET not in text
        assert "staging-gateway-token" not in text


def test_secret_file_and_permission_warning(make_receiver: ReceiverFactory, tmp_path: Path) -> None:
    rx = make_receiver()
    secret_file = tmp_path / "secret"
    secret_file.write_text(SECRET + "\n")
    secret_file.chmod(0o644)
    fio = FakeIO()
    args = [
        "run",
        rx.url,
        "-p",
        "stripe",
        "--secret-file",
        str(secret_file),
        "--i-am-authorized",
        "--no-color",
    ]
    assert main(args, fio) == ExitCode.CLEAN
    assert "readable by other users" in fio.out


def test_secret_prompt_when_interactive(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    fio = FakeIO(tty=True, answer="127.0.0.1")
    assert main(["run", rx.url, "-p", "stripe", "--no-color"], fio) == ExitCode.CLEAN


def test_wrong_secret_is_inconclusive(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver()
    fio = FakeIO(env={"WEBHOOK_SECRET": "not-the-secret"})
    assert main(run_args(rx.url, "--i-am-authorized"), fio) == ExitCode.INCONCLUSIVE
    assert "INCONCLUSIVE" in fio.out
    assert len(rx.received) == 1


def test_body_matchers_from_cli(make_receiver: ReceiverFactory) -> None:
    rx = make_receiver(reject_status=200)
    fio = FakeIO()
    code = main(run_args(rx.url, "--i-am-authorized", "--reject-body", "invalid signature"), fio)
    assert code == ExitCode.CLEAN


def test_custom_payload_and_case_selection(make_receiver: ReceiverFactory, tmp_path: Path) -> None:
    rx = make_receiver()
    payload = tmp_path / "event.json"
    payload.write_text('{"id": "__SIGAUDIT_EVENT_ID__", "type": "test.custom"}')
    fio = FakeIO()
    code = main(
        run_args(
            rx.url,
            "--i-am-authorized",
            "--payload-file",
            str(payload),
            "--only",
            "tampered-body,replay-old-timestamp",
        ),
        fio,
    )
    assert code == ExitCode.CLEAN
    assert len(rx.received) == 3
    first = json.loads(rx.received[0].body)
    assert first["type"] == "test.custom"
    assert first["id"].startswith("evt_sigaudit_")


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--rate", "50"], "capped"),
        (["--only", "nope"], "unknown case"),
        (["--skip", "valid"], "cannot be skipped"),
        (["-H", "no colon"], "invalid --header"),
        (["--accept-status", "abc"], "invalid status"),
        (["--payload-file", "/nonexistent/x.json"], "cannot read payload"),
        (["--ca-bundle", "/nonexistent/ca.pem"], "CA bundle not found"),
    ],
)
def test_usage_errors_exit_3_and_send_nothing(
    make_receiver: ReceiverFactory, extra: list[str], message: str
) -> None:
    rx = make_receiver()
    fio = FakeIO()
    assert main(run_args(rx.url, "--i-am-authorized", *extra), fio) == ExitCode.REFUSED
    assert message in fio.err
    assert rx.received == []


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["run", "ftp://x/", "-p", "stripe", "--secret-env", "WEBHOOK_SECRET"], "http"),
        (["run", "https://x/", "-p", "nope", "--secret-env", "WEBHOOK_SECRET"], "unknown built-in"),
        (["run", "https://x/", "-p", "stripe", "--secret-env", "MISSING"], "not set"),
        (["run", "https://x/", "-p", "stripe"], "no signing secret"),
    ],
)
def test_validation_happens_before_authorization(argv: list[str], message: str) -> None:
    fio = FakeIO()
    assert main(argv, fio) == ExitCode.REFUSED
    assert message in fio.err
    assert "illegal" not in fio.err  # failed before reaching the gate


def test_argparse_errors_use_exit_code_3(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["run"])
    assert excinfo.value.code == ExitCode.REFUSED
    with pytest.raises(SystemExit) as excinfo:
        main(["run", "https://x/", "-p", "stripe", "--secret-env", "A", "--secret-file", "B"])
    assert excinfo.value.code == ExitCode.REFUSED


def test_demo_default_and_correct() -> None:
    fio = FakeIO()
    assert main(["demo", "--no-color"], fio) == ExitCode.FINDINGS
    assert "skip-if-missing" in fio.out
    fio = FakeIO()
    assert main(["demo", "--correct", "--scheme", "generic-hmac-sha256", "--no-color"], fio) == 0


def test_demo_single_flaw(tmp_path: Path) -> None:
    fio = FakeIO()
    out = tmp_path / "demo.json"
    code = main(["demo", "--flaw", "accept-sha1", "--json-report", str(out), "--no-color"], fio)
    assert code == ExitCode.FINDINGS
    data = json.loads(out.read_text())
    assert [r["id"] for r in data["results"] if r["verdict"] == "finding"] == ["wrong-algorithm"]
    assert data["authorization"]["method"] == "demo"


def test_profiles_and_cases_commands() -> None:
    fio = FakeIO()
    assert main(["profiles"], fio) == 0
    assert "stripe" in fio.out
    fio = FakeIO()
    assert main(["profiles", "slack"], fio) == 0
    assert "X-Slack-Request-Timestamp" in fio.out
    fio = FakeIO()
    assert main(["profiles", "nope"], fio) == ExitCode.REFUSED
    fio = FakeIO()
    assert main(["cases"], fio) == 0
    assert "tampered-body" in fio.out


def test_profiles_validates_a_file(tmp_path: Path) -> None:
    good = tmp_path / "acme.yaml"
    good.write_text(
        "name: acme\ndescription: Acme\nalgorithm: sha256\n"
        'signed_payload: "{body}"\nsignature_header: X-Acme-Signature\n'
        'signature_format: "{signature}"\n'
    )
    fio = FakeIO()
    assert main(["profiles", str(good)], fio) == 0
    assert "OK:" in fio.out
    assert "replay case will be skipped" in fio.out

    bad = tmp_path / "bad.yaml"
    bad.write_text("name: bad\n")
    fio = FakeIO()
    assert main(["profiles", str(bad)], fio) == ExitCode.REFUSED
    assert "missing required" in fio.err


def test_broken_pipe_exits_quietly() -> None:
    class ClosedPipe(io.StringIO):
        def write(self, _s: str) -> int:
            raise BrokenPipeError

    fio = FakeIO()
    fio.stdout = ClosedPipe()
    assert main(["profiles"], fio) == 141
