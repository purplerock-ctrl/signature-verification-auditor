"""Colour-coded terminal output (via rich; honours NO_COLOR and --no-color)."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from sigaudit.cases import AuditCase
from sigaudit.profiles import ProviderProfile
from sigaudit.results import AuditReport, CaseResult, ExitCode, Verdict

VERDICT_STYLE = {
    Verdict.PASS: "green",
    Verdict.FINDING: "bold red",
    Verdict.INCONCLUSIVE: "yellow",
    Verdict.SKIPPED: "dim",
    Verdict.ERROR: "magenta",
}


def print_header(
    console: Console, url: str, profile: ProviderProfile, cases: list[AuditCase], rate: float
) -> None:
    console.print(f"[bold]sigaudit[/] -> {escape(url)}")
    console.print(
        f"profile [cyan]{profile.name}[/] | {len(cases)} cases | {rate:g} req/s", style="dim"
    )
    console.print()


def print_progress(console: Console, result: CaseResult) -> None:
    status = str(result.response.status_code) if result.response else "-"
    observed = result.outcome.value if result.outcome else "not sent"
    style = VERDICT_STYLE[result.verdict]
    console.print(
        f"  {result.case.number}. {result.case.title:<32} "
        f"{status:>4}  {observed:<9} [{style}]{result.verdict.value.upper()}[/]"
    )


def print_summary(console: Console, report: AuditReport) -> None:
    console.print()
    if report.findings:
        table = Table(title="Findings", title_style="bold red", show_lines=True, expand=False)
        table.add_column("#", justify="right")
        table.add_column("Case")
        table.add_column("Severity")
        table.add_column("Risk", overflow="fold")
        for r in report.findings:
            table.add_row(
                str(r.case.number),
                r.case.title,
                r.case.severity.value,
                escape(r.case.risk),
            )
        console.print(table)

    notes = [r for r in report.results if r.note and r.verdict is not Verdict.FINDING]
    for r in notes:
        console.print(f"  [dim]note {r.case.number}:[/] {escape(r.note)}")
    if notes:
        console.print()

    code = report.exit_code()
    style = {ExitCode.CLEAN: "bold green", ExitCode.FINDINGS: "bold red"}.get(code, "bold yellow")
    console.print(f"[{style}]{escape(report.summary_line())}[/]")
