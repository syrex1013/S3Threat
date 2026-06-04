"""
Rich console output for S3Threat — panels, tables, progress, and consistent colors.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    pass

console = Console(highlight=False, soft_wrap=True)

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

STATUS_STYLE = {
    "WRITABLE": ("CRITICAL", "bold white on red"),
    "OPEN": ("OPEN", "bold red"),
    "PRIVATE": ("PRIV", "bold yellow"),
    "ERROR": ("ERROR", "bold red"),
    "NONE": ("NONE", "dim"),
}

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim",
    "none": "dim",
}

MISCONFIG_STYLE = {
    "listable": "red",
    "writable": "bold white on red",
    "deletable": "bold white on red",
    "public-policy": "magenta",
    "public-acl": "magenta",
    "public-read": "red",
    "public-cors": "yellow",
    "website": "cyan",
}


def format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KB"
    if n < 1024**3:
        return f"{n / 1024**2:.1f} MB"
    return f"{n / 1024**3:.1f} GB"


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

def die(message: str, title: str = "Error") -> None:
    console.print(Panel(
        Text(message, style="bold red"),
        title=f"[bold red]{title}[/]",
        border_style="red",
        padding=(1, 2),
    ))
    sys.exit(1)


def success(message: str) -> None:
    console.print(f"[bold green]✓[/] {message}")


def warn(message: str) -> None:
    console.print(f"[bold yellow]![/] {message}")


def info(message: str) -> None:
    console.print(f"[cyan]›[/] {message}")


def rule(title: str = "") -> None:
    console.print(Rule(title, style="bold cyan") if title else Rule(style="dim"))


def panel(title: str, body: str, *, border: str = "cyan", fit: bool = True) -> None:
    fn = Panel.fit if fit else Panel
    console.print(fn(body, title=f"[bold]{title}[/]", border_style=border))


def kv_table(title: str, rows: list[tuple[str, str]], *, border: str = "cyan") -> None:
    t = Table(
        title=f"[bold]{title}[/]",
        box=box.ROUNDED,
        border_style=border,
        show_header=False,
        expand=True,
        padding=(0, 1),
    )
    t.add_column("Key", style="bold dim", no_wrap=True)
    t.add_column("Value", overflow="fold")
    for k, v in rows:
        t.add_row(k, v)
    console.print(t)


# ---------------------------------------------------------------------------
# Startup & scrape
# ---------------------------------------------------------------------------

def print_banner() -> None:
    console.print(
        Panel(
            "[bold cyan]S3Threat[/]  [dim]— anonymous S3 discovery & security audit[/]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_run_config(
    mode: str,
    *,
    threads: int,
    write_probe: bool,
    aws: bool = False,
) -> None:
    kv_table(
        "Run configuration",
        [
            ("Mode", f"[bold]{mode}[/]"),
            ("Workers", f"[bold]{threads}[/]"),
            ("Write probe", "[bold red]on[/]" if write_probe else "[dim]off[/]"),
            ("AWS CLI audit", "[bold green]on[/]" if aws else "[dim]off[/]"),
        ],
    )


def print_scrape_report(
    url: str,
    *,
    depth: int,
    max_pages: int,
    pages_crawled: int,
    tokens_seen: int,
    seeds: list[str],
) -> None:
    kv_table(
        "Site scrape",
        [
            ("URL", f"[cyan underline]{url}[/]"),
            ("Depth", str(depth)),
            ("Max pages", str(max_pages)),
            ("Pages fetched", f"[bold]{pages_crawled}[/]"),
            ("Tokens extracted", f"[bold]{tokens_seen}[/]"),
            ("Seeds", f"[bold green]{len(seeds)}[/]"),
        ],
        border="green",
    )
    if seeds:
        print_seeds_table(seeds, title="Extracted seeds")


def print_seeds_table(seeds: list[str], *, title: str = "Seeds") -> None:
    t = Table(
        title=f"[bold]{title}[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        expand=True,
        row_styles=["", "dim"],
    )
    t.add_column("#", style="dim", justify="right", no_wrap=True)
    t.add_column("Seed", style="bold green")
    for i, s in enumerate(seeds[:60], 1):
        t.add_row(str(i), s)
    if len(seeds) > 60:
        t.add_row("…", f"[dim]+{len(seeds) - 60} more[/]")
    console.print(t)


# ---------------------------------------------------------------------------
# Findings & hits
# ---------------------------------------------------------------------------

def status_cell(status: str) -> str:
    label, style = STATUS_STYLE.get(status, (status, "dim"))
    return f"[{style}]{label}[/]"


def severity_cell(severity: str) -> str:
    if severity in ("none", "", "-"):
        return "[dim]-[/]"
    style = SEVERITY_STYLE.get(severity, "dim")
    return f"[{style}]{severity}[/]"


def misconfig_tags(tags: list[str], labels: dict[str, str]) -> str:
    parts = []
    for tag in tags:
        style = MISCONFIG_STYLE.get(tag, "yellow")
        label = labels.get(tag, tag)
        parts.append(f"[{style}]{label}[/]")
    return "  ".join(parts) if parts else "[dim]—[/]"


def new_findings_table(title: str = "S3 Recon Findings") -> Table:
    t = Table(
        title=f"[bold cyan]{title}[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold white on blue",
        border_style="blue",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    t.add_column("Status", no_wrap=True)
    t.add_column("Bucket", style="bold", no_wrap=True)
    t.add_column("Region", style="cyan", no_wrap=True)
    t.add_column("Objs", justify="right", style="dim", no_wrap=True)
    t.add_column("Size", justify="right", no_wrap=True)
    t.add_column("Sev", justify="center", no_wrap=True)
    t.add_column("Score", justify="right", no_wrap=True)
    t.add_column("Findings", overflow="fold", style="dim")
    return t


def result_row_cells(r, misconfig_labels: dict[str, str]) -> tuple:
    score = (
        f"[bold magenta]{r.interest}[/]"
        if r.interesting
        else (f"[dim]{r.interest}[/]" if r.interest else "[dim]-[/]")
    )
    top_audit = sorted(
        getattr(r, "audit_findings", []) or [],
        key=lambda f: ["critical", "high", "medium", "low", "info"].index(
            f.get("severity", "info")
        )
        if f.get("severity") in ("critical", "high", "medium", "low", "info")
        else 5,
    )[:2]
    audit_bits = [
        f"[{SEVERITY_STYLE.get(f['severity'], 'dim')}]{f['severity']}[/]: {f['check']}"
        for f in top_audit
    ]
    mc = misconfig_tags(r.misconfigs, misconfig_labels)
    why = "; ".join(r.reasons) if r.reasons else ""
    detail_parts = [p for p in (mc, " · ".join(audit_bits), why) if p and p != "[dim]—[/]"]
    detail = " — ".join(detail_parts) if detail_parts else "[dim]—[/]"
    if r.status in ("OPEN", "WRITABLE") and r.url:
        detail = f"[cyan underline]{r.url}[/]\n{detail}"
    elif r.url:
        detail = f"{detail}\n[dim]{r.url}[/]"

    count = r.object_count or ("-" if r.status not in ("OPEN", "WRITABLE") else "0")
    size = format_bytes(r.sample_bytes) if r.sample_bytes else "[dim]-[/]"
    if r.interesting:
        count = f"[bold magenta]{count}[/]"

    return (
        status_cell(r.status),
        f"[bold]{r.bucket}[/]" + (" [magenta]★[/]" if r.interesting else ""),
        r.region or "[dim]-[/]",
        count,
        size,
        severity_cell(r.severity),
        score,
        detail,
    )


def stats_line(probed: int, hits: int, interesting: int, batch: int = 0) -> str:
    batch_s = f"  [cyan]batch[/] [bold]{batch}[/]" if batch else ""
    return (
        f"[bold cyan]S3Threat[/]{batch_s}   "
        f"[dim]probed[/] [bold]{probed}[/]   "
        f"[yellow]hits[/] [bold]{hits}[/]   "
        f"[magenta]interesting[/] [bold]{interesting}[/]"
    )


def print_hit(r, misconfig_labels: dict[str, str]) -> None:
    label, style = STATUS_STYLE.get(r.status, (r.status, "dim"))
    parts = [f"[{style}]{label}[/]", f"[bold]{r.bucket}[/]"]
    if r.region:
        parts.append(f"[cyan]{r.region}[/]")
    if r.severity not in ("none", ""):
        parts.append(severity_cell(r.severity))
    if r.object_count:
        parts.append(f"[dim]{r.object_count} objs[/]")
    if r.interesting:
        parts.append("[bold magenta]★ INTERESTING[/]")
    console.print(Columns(parts, padding=(0, 2)))

    if r.misconfigs:
        console.print(
            "  " + misconfig_tags(r.misconfigs, misconfig_labels),
            highlight=False,
        )
    if r.status in ("OPEN", "WRITABLE") and r.url:
        console.print(f"  [cyan underline]{r.url}[/]")
        for url in (r.object_urls or [])[:3]:
            console.print(f"    [dim]→[/] [cyan]{url}[/]")


def print_audit_report(r, severity_order: tuple[str, ...]) -> None:
    kv_table(
        "Security audit",
        [
            ("Bucket", f"[bold]{r.bucket}[/]"),
            ("Status", status_cell(r.status)),
            ("Severity", severity_cell(r.severity)),
            ("Region", f"[cyan]{r.region or '-'}[/]"),
        ],
        border="magenta",
    )
    if not r.audit_findings:
        info("No audit findings — bucket unreachable or no exposure detected.")
        return

    t = Table(
        title="[bold]Checklist findings[/]",
        box=box.SIMPLE_HEAVY,
        header_style="bold",
        expand=True,
        row_styles=["", "on grey11"],
    )
    t.add_column("Severity", no_wrap=True)
    t.add_column("Section", style="cyan", no_wrap=True)
    t.add_column("Check", style="bold")
    t.add_column("Detail", overflow="fold", style="dim")
    order = {s: i for i, s in enumerate(severity_order)}
    for f in sorted(
        r.audit_findings,
        key=lambda x: (order.get(x["severity"], 9), x["section"]),
    ):
        sev = f["severity"]
        t.add_row(
            severity_cell(sev),
            f["section"],
            f["check"],
            f["detail"],
        )
    console.print(t)


def print_summary(results: list, probed: int) -> None:
    crit = sum(r.status == "WRITABLE" for r in results)
    opn = sum(r.status == "OPEN" for r in results)
    priv = sum(r.status == "PRIVATE" for r in results)
    interesting = sum(r.interesting for r in results)
    policy = sum("public-policy" in r.misconfigs for r in results)
    acl = sum("public-acl" in r.misconfigs for r in results)
    reads = sum("public-read" in r.misconfigs for r in results)

    t = Table(
        title="[bold cyan]Summary[/]",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        show_header=True,
        header_style="bold",
        expand=False,
        padding=(0, 2),
    )
    t.add_column("Metric", style="bold")
    t.add_column("Count", justify="right")
    rows = [
        ("Writable", f"[bold white on red]{crit}[/]"),
        ("Open", f"[bold red]{opn}[/]"),
        ("Private (exists)", f"[bold yellow]{priv}[/]"),
        ("Interesting ★", f"[bold magenta]{interesting}[/]"),
        ("Public policy", str(policy)),
        ("Public ACL", str(acl)),
        ("Public read", str(reads)),
        ("Total probed", f"[bold]{probed}[/]"),
    ]
    for k, v in rows:
        t.add_row(k, v)
    console.print(t)


def print_found_interesting() -> None:
    console.print()
    success("Interesting bucket found — stopping scan.")


def print_file_saved(path: str, nbytes: int) -> None:
    success(f"Saved [bold]{format_bytes(nbytes)}[/] → [cyan]{path}[/]")


def print_download_skip(key: str, reason: str) -> None:
    warn(f"Skip [dim]{key}[/] — {reason}")


def print_download_progress(key: str, nbytes: int) -> None:
    console.print(f"  [green]↓[/] [dim]{key}[/]  [bold]{format_bytes(nbytes)}[/]")


def print_download_complete(saved: int, total: int, dest: str) -> None:
    panel(
        "Download complete",
        f"[bold green]{saved}[/] file(s)  ·  [bold]{format_bytes(total)}[/]\n"
        f"[cyan]{dest}[/]",
        border="green",
    )


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------

def print_view_object(
    bucket: str,
    key: str,
    url: str,
    data: bytes,
    *,
    truncated: bool,
    content_type: str,
    is_textual: bool,
) -> None:
    kv_table(
        "Object view",
        [
            ("Bucket", f"[bold]{bucket}[/]"),
            ("Key", f"[cyan]{key}[/]"),
            ("URL", f"[cyan underline]{url}[/]"),
            ("Size", format_bytes(len(data)) + (" [yellow](truncated)[/]" if truncated else "")),
            ("Type", content_type or "[dim]unknown[/]"),
        ],
        border="cyan",
    )
    if is_textual:
        text = data.decode("utf-8", errors="replace")
        if truncated:
            text += "\n… [truncated]"
        lang = "json" if key.endswith(".json") else "text"
        console.print(Panel(
            Syntax(text, lang, theme="monokai", line_numbers=True, word_wrap=True),
            title="[bold]Content[/]",
            border_style="dim",
            expand=True,
        ))
    else:
        preview = data[:64]
        panel("Binary preview", f"[dim]{preview!r}[/]", border="yellow", fit=True)


def print_view_bucket_header(r) -> None:
    kv_table(
        "Bucket view",
        [
            ("Bucket", f"[bold]{r.bucket}[/]"),
            ("Status", status_cell(r.status)),
            ("Region", f"[cyan]{r.region or '-'}[/]"),
            ("Note", r.note or "[dim]—[/]"),
        ],
    )
    if r.misconfigs:
        info("Misconfigs: " + ", ".join(r.misconfigs))
    if r.url:
        console.print(f"  [cyan underline]{r.url}[/]")


def print_objects_table(keys: list[str], sizes: dict, *, limit: int = 100) -> None:
    if not keys:
        info("No listable objects to display.")
        return
    t = Table(
        title=f"[bold]Objects[/] [dim]({len(keys)} total)[/]",
        box=box.SIMPLE,
        header_style="bold cyan",
        expand=True,
    )
    t.add_column("Key", style="cyan", overflow="fold")
    t.add_column("Size", justify="right", no_wrap=True)
    for k in keys[:limit]:
        sz = sizes.get(k, 0)
        t.add_row(k, format_bytes(sz) if sz else "[dim]-[/]")
    if len(keys) > limit:
        t.add_row(f"[dim]… +{len(keys) - limit} more[/]", "")
    console.print(t)


# ---------------------------------------------------------------------------
# Progress & live
# ---------------------------------------------------------------------------

def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold cyan]{task.description}[/]"),
        BarColumn(
            bar_width=40,
            style="blue",
            complete_style="bold green",
            finished_style="bold green",
            pulse_style="cyan",
        ),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    )


def live_group(stats: str, progress: Progress, table: Table) -> Group:
    return Group(
        Panel(stats, border_style="blue", padding=(0, 1)),
        progress,
        table,
    )
