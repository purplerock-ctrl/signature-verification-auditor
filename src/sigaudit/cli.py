"""Command-line interface.

Order of operations in ``sigaudit run`` is deliberate: everything that can be
validated offline (URL, profile, payload, matchers, secret) is checked first,
the authorization gate comes last, and only then is anything sent.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, TextIO
from urllib.parse import urlsplit

from rich.console import Console

from sigaudit import __version__
from sigaudit.authorization import (
    REMINDER,
    AuthorizationRecord,
    AuthorizationRefused,
    require_authorization,
    target_host,
)
from sigaudit.cases import ALL_CASES, EVENT_ID_TOKEN, BuildContext, CaseSelectionError, select_cases
from sigaudit.classify import Classifier, MatcherError, ResponseMatcher
from sigaudit.demo_server import FLAW_DESCRIPTIONS, DemoReceiver, Flaw, ReceiverConfig, Scheme
from sigaudit.profiles import (
    ProfileError,
    ProviderProfile,
    builtin_profile_names,
    builtin_profile_text,
    load_builtin_profile,
    resolve_profile,
)
from sigaudit.report.json_report import write_json
from sigaudit.report.markdown_report import write_markdown
from sigaudit.report.terminal import print_header, print_progress, print_summary
from sigaudit.results import AuditReport, ExitCode
from sigaudit.runner import (
    DEFAULT_RATE,
    DEFAULT_TIMEOUT,
    MAX_RATE,
    AuditConfig,
    RunnerConfigError,
    run_audit,
)
from sigaudit.signing import Signer, SigningError

MAX_PAYLOAD_BYTES = 1024 * 1024
DEMO_SECRET = "whsec_demo_only_not_a_real_secret"  # noqa: S105 - local demo receiver only
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class UsageError(Exception):
    """Bad input. Reported as one line, exit code 3, nothing sent."""


@dataclass
class CliIO:
    """Injectable I/O so tests can drive the CLI without a real terminal."""

    stdout: TextIO = field(default_factory=lambda: sys.stdout)
    stderr: TextIO = field(default_factory=lambda: sys.stderr)
    is_tty: Callable[[], bool] = field(default_factory=lambda: sys.stdin.isatty)
    input_fn: Callable[[str], str] = input
    getpass_fn: Callable[[str], str] = getpass.getpass
    sleep: Callable[[float], None] = time.sleep
    environ: dict[str, str] | None = None

    def env(self, name: str) -> str | None:
        return (self.environ if self.environ is not None else os.environ).get(name)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse exits 2 by default, which would collide with INCONCLUSIVE.
        self.print_usage(sys.stderr)
        self.exit(int(ExitCode.REFUSED), f"{self.prog}: error: {message}\n")


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="sigaudit",
        description=(
            "Audit a webhook endpoint's HMAC signature verification by sending deliberately "
            "bad callbacks and reporting any it wrongly accepts. " + REMINDER
        ),
    )
    parser.add_argument("--version", action="version", version=f"sigaudit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    # --- run ---------------------------------------------------------------
    run = sub.add_parser(
        "run",
        help="audit an endpoint you are authorized to test",
        description="Audit an endpoint you own or are explicitly authorized to test. " + REMINDER,
    )
    run.add_argument("url", help="the webhook endpoint URL (http or https)")
    run.add_argument(
        "-p",
        "--profile",
        required=True,
        help="built-in profile name (see `sigaudit profiles`) or path to a YAML/JSON profile",
    )

    secret = run.add_argument_group("signing secret (never passed as a plain argument)")
    sx = secret.add_mutually_exclusive_group()
    sx.add_argument("--secret-env", metavar="VAR", help="read the secret from this env variable")
    sx.add_argument("--secret-file", metavar="PATH", help="read the secret from this file")

    auth = run.add_argument_group("authorization")
    auth.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm non-interactively that you are authorized to test this endpoint",
    )
    auth.add_argument(
        "--scope-note",
        metavar="TEXT",
        help="recorded in reports, e.g. 'own staging' or 'Example Corp bug bounty, in scope'",
    )

    net = run.add_argument_group("network")
    net.add_argument(
        "--rate",
        type=_positive_float,
        default=DEFAULT_RATE,
        help=f"requests per second (default {DEFAULT_RATE:g}, max {MAX_RATE:g})",
    )
    net.add_argument(
        "--timeout",
        type=_positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"per-request timeout in seconds (default {DEFAULT_TIMEOUT:g})",
    )
    net.add_argument(
        "--ca-bundle",
        metavar="PATH",
        help="CA bundle for endpoints with a private CA (TLS verification is never disabled)",
    )
    net.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="extra request header, repeatable (e.g. a bug-bounty identification header)",
    )

    req = run.add_argument_group("requests")
    req.add_argument(
        "--payload-file",
        metavar="PATH",
        help=f"custom request body; {EVENT_ID_TOKEN} is replaced with a unique event ID per case",
    )
    req.add_argument("--only", type=_csv, metavar="IDS", help="comma-separated case IDs to run")
    req.add_argument("--skip", type=_csv, metavar="IDS", help="comma-separated case IDs to skip")
    req.add_argument(
        "--replay-age",
        type=_positive_int,
        metavar="SECONDS",
        help="age of the replayed timestamp (default: profile tolerance + 3600)",
    )

    match = run.add_argument_group(
        "classification (default: 2xx = accepted, anything else = rejected)"
    )
    match.add_argument("--accept-status", metavar="SPEC", help="e.g. 2xx, 200,202, 200-204")
    match.add_argument("--accept-body", metavar="TEXT", help="accepted responses contain TEXT")
    match.add_argument("--reject-status", metavar="SPEC", help="e.g. 4xx or 400,401,403")
    match.add_argument("--reject-body", metavar="TEXT", help="rejected responses contain TEXT")

    _add_output_args(run)

    # --- demo --------------------------------------------------------------
    demo = sub.add_parser(
        "demo",
        help="audit a deliberately broken receiver on 127.0.0.1 (no external traffic)",
        description=(
            "Start a local receiver with configurable verification bugs and audit it. "
            "Nothing leaves your machine."
        ),
    )
    demo.add_argument(
        "--scheme",
        choices=[s.value for s in Scheme],
        default=Scheme.STRIPE.value,
        help="signing scheme the demo receiver speaks (default: stripe)",
    )
    flaws = demo.add_mutually_exclusive_group()
    flaws.add_argument(
        "--flaw",
        action="append",
        choices=[f.value for f in Flaw],
        default=None,
        help="enable a flaw (repeatable; default: skip-if-missing + no-timestamp-check)",
    )
    flaws.add_argument("--correct", action="store_true", help="run the receiver with no flaws")
    _add_output_args(demo)

    # --- profiles / cases ----------------------------------------------------
    prof = sub.add_parser("profiles", help="list built-in profiles, or show one")
    prof.add_argument("name", nargs="?", help="profile to print as YAML")
    sub.add_parser("cases", help="list the audit cases")
    return parser


def _add_output_args(p: argparse.ArgumentParser) -> None:
    out = p.add_argument_group("output")
    out.add_argument("--json-report", metavar="PATH", help="write a JSON report")
    out.add_argument("--markdown-report", metavar="PATH", help="write a Markdown report")
    out.add_argument("--no-color", action="store_true", help="disable colour output")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def validate_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UsageError(f"URL must start with http:// or https:// (got {url!r})")
    try:
        target_host(url)
    except ValueError as exc:
        raise UsageError(str(exc)) from None
    return url


def parse_headers(raw: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw:
        name, sep, value = item.partition(":")
        name = name.strip()
        if not sep or not _HEADER_NAME_RE.match(name):
            raise UsageError(f"invalid --header {item!r}; expected 'Name: value'")
        headers[name] = value.strip()
    return headers


def build_classifier(args: argparse.Namespace) -> Classifier:
    try:
        accept = None
        if args.accept_status or args.accept_body:
            accept = ResponseMatcher.build(args.accept_status or "2xx", args.accept_body)
        reject = None
        if args.reject_status or args.reject_body:
            reject = ResponseMatcher.build(args.reject_status, args.reject_body)
    except MatcherError as exc:
        raise UsageError(str(exc)) from None
    return Classifier(accept=accept, reject=reject)


def read_payload(path: str | None) -> bytes | None:
    if path is None:
        return None
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read payload file {path}: {exc.strerror}") from None
    if len(data) > MAX_PAYLOAD_BYTES:
        raise UsageError(f"payload file is larger than {MAX_PAYLOAD_BYTES} bytes")
    if not data:
        raise UsageError("payload file is empty")
    return data


def resolve_secret(args: argparse.Namespace, io: CliIO, console: Console) -> str:
    if args.secret_env:
        value = io.env(args.secret_env)
        if not value:
            raise UsageError(f"environment variable {args.secret_env} is not set or is empty")
        return value
    if args.secret_file:
        path = Path(args.secret_file)
        try:
            value = path.read_text(encoding="utf-8").rstrip("\r\n")
            mode = path.stat().st_mode
        except OSError as exc:
            raise UsageError(f"cannot read secret file {path}: {exc.strerror}") from None
        if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
            console.print(
                f"[yellow]warning:[/] {path} is readable by other users; consider chmod 600"
            )
        if not value:
            raise UsageError(f"secret file {path} is empty")
        return value
    if io.is_tty():
        value = io.getpass_fn("Signing secret for the test endpoint (input hidden): ")
        if not value:
            raise UsageError("no secret entered")
        return value
    raise UsageError("no signing secret: use --secret-env VAR or --secret-file PATH")


def _write_reports(args: argparse.Namespace, report: AuditReport, console: Console) -> None:
    for path, writer in ((args.json_report, write_json), (args.markdown_report, write_markdown)):
        if path:
            try:
                writer(report, path)
            except OSError as exc:
                raise UsageError(f"cannot write report {path}: {exc.strerror}") from None
            console.print(f"[dim]report written:[/] {path}")


def _console(args: argparse.Namespace, io: CliIO) -> Console:
    return Console(
        file=io.stdout, no_color=getattr(args, "no_color", False), highlight=False, soft_wrap=True
    )


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace, io: CliIO) -> int:
    console = _console(args, io)
    url = validate_url(args.url)
    try:
        profile = resolve_profile(args.profile)
        cases = select_cases(args.only, args.skip)
    except (ProfileError, CaseSelectionError) as exc:
        raise UsageError(str(exc)) from None
    if args.rate > MAX_RATE:
        raise UsageError(f"--rate is capped at {MAX_RATE:g} requests/second")
    extra_headers = parse_headers(args.header)
    classifier = build_classifier(args)
    payload = read_payload(args.payload_file)
    if args.ca_bundle and not Path(args.ca_bundle).is_file():
        raise UsageError(f"CA bundle not found: {args.ca_bundle}")

    host = target_host(url)
    if urlsplit(url).scheme == "http" and host not in _LOOPBACK:
        console.print("[yellow]warning:[/] plain HTTP: requests are visible on the network")

    secret = resolve_secret(args, io, console)
    try:
        signer = Signer.from_secret(profile, secret)
    except SigningError as exc:
        raise UsageError(str(exc)) from None

    # Last step before any traffic: the authorization gate.
    authorization = require_authorization(
        url,
        flag=args.i_am_authorized,
        scope_note=args.scope_note,
        is_tty=io.is_tty(),
        input_fn=io.input_fn,
        out=io.stderr,
    )

    ctx = BuildContext.create(
        url=url,
        signer=signer,
        now=int(time.time()),
        replay_age_seconds=args.replay_age,
        payload_template=payload,
        extra_headers=extra_headers,
    )
    config = AuditConfig(
        ctx=ctx,
        cases=cases,
        classifier=classifier,
        authorization=authorization,
        rate=args.rate,
        timeout=args.timeout,
        verify=args.ca_bundle or True,
    )
    return _execute(args, config, profile, io, console)


def _execute(
    args: argparse.Namespace,
    config: AuditConfig,
    profile: ProviderProfile,
    io: CliIO,
    console: Console,
) -> int:
    print_header(console, config.ctx.url, profile, list(config.cases), config.rate)
    try:
        report = run_audit(config, sleep=io.sleep, on_result=lambda r: print_progress(console, r))
    except RunnerConfigError as exc:
        raise UsageError(str(exc)) from None
    print_summary(console, report)
    _write_reports(args, report, console)
    return int(report.exit_code())


def cmd_demo(args: argparse.Namespace, io: CliIO) -> int:
    console = _console(args, io)
    scheme = Scheme(args.scheme)
    if args.correct:
        flaws: frozenset[Flaw] = frozenset()
    elif args.flaw:
        flaws = frozenset(Flaw(f) for f in args.flaw)
    else:
        flaws = frozenset({Flaw.SKIP_IF_MISSING, Flaw.NO_TIMESTAMP_CHECK})

    console.print(
        "[bold]Demo:[/] auditing a local receiver on 127.0.0.1 (nothing leaves your machine)"
    )
    if flaws:
        for flaw in sorted(flaws):
            console.print(f"  planted flaw [cyan]{flaw.value}[/]: {FLAW_DESCRIPTIONS[flaw]}")
    else:
        console.print("  no flaws planted: the receiver verifies correctly")
    console.print()

    profile = load_builtin_profile(scheme.value)
    with DemoReceiver(ReceiverConfig(secret=DEMO_SECRET, scheme=scheme, flaws=flaws)) as rx:
        ctx = BuildContext.create(
            url=rx.url, signer=Signer.from_secret(profile, DEMO_SECRET), now=int(time.time())
        )
        config = AuditConfig(
            ctx=ctx,
            cases=ALL_CASES,
            classifier=Classifier(),
            authorization=AuthorizationRecord(
                method="demo", target_host="127.0.0.1", confirmed_at=datetime.now(UTC)
            ),
            rate=MAX_RATE,
        )
        return _execute(args, config, profile, io, console)


def cmd_profiles(args: argparse.Namespace, io: CliIO) -> int:
    if args.name:
        try:
            io.stdout.write(builtin_profile_text(args.name))
        except ProfileError as exc:
            raise UsageError(str(exc)) from None
        return 0
    for name in builtin_profile_names():
        p = load_builtin_profile(name)
        io.stdout.write(f"{name:<22} {p.description}\n")
    io.stdout.write("\nShow one with `sigaudit profiles NAME`; add your own as a YAML/JSON file.\n")
    return 0


def cmd_cases(_args: argparse.Namespace, io: CliIO) -> int:
    for c in ALL_CASES:
        io.stdout.write(f"{c.number}. {c.id:<22} [{c.severity.value}] {c.description}\n")
    return 0


COMMANDS: dict[str, Callable[[argparse.Namespace, CliIO], int]] = {
    "run": cmd_run,
    "demo": cmd_demo,
    "profiles": cmd_profiles,
    "cases": cmd_cases,
}


def main(argv: Sequence[str] | None = None, io: CliIO | None = None) -> int:
    io = io or CliIO()
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args, io)
    except AuthorizationRefused as exc:
        io.stderr.write(f"sigaudit: {exc}\n")
        return int(ExitCode.REFUSED)
    except UsageError as exc:
        io.stderr.write(f"sigaudit: error: {exc}\n")
        return int(ExitCode.REFUSED)
    except KeyboardInterrupt:
        io.stderr.write("sigaudit: interrupted\n")
        return 130
