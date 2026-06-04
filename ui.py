"""
Rich console output for S3Threat — panels, tables, progress, and consistent colors.
"""

from __future__ import annotations

import re
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
_TABLE_MARGIN = 2


def _usable_width() -> int:
    """Terminal width available for tables (never wider than the pane)."""
    w = console.size.width
    if not w or w < 40:
        return 80
    return max(40, w - _TABLE_MARGIN)


def _make_table(
    *,
    title: str | None = None,
    box_style=box.ROUNDED,
    border_style: str = "cyan",
    header_style: str = "bold",
    show_header: bool = True,
    expand: bool | None = None,
    width: int | None = None,
    **kwargs,
) -> Table:
    """Create a width-bounded table that fits the terminal."""
    w = width or _usable_width()
    if expand is None:
        expand = False
    opts = dict(
        box=box_style,
        border_style=border_style,
        header_style=header_style,
        show_header=show_header,
        expand=expand,
        width=w,
        padding=(0, 1),
    )
    opts.update(kwargs)
    if title:
        opts["title"] = title
    return Table(**opts)


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _strip_markup(text: str) -> str:
    return re.sub(r"\[/?[^\]]+\]", "", text)

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
    w = _usable_width()
    key_w = min(14, max(10, w // 5))
    t = _make_table(
        title=f"[bold]{title}[/]",
        border_style=border,
        show_header=False,
        box_style=box.ROUNDED,
    )
    t.add_column("Key", style="bold dim", no_wrap=True, width=key_w)
    t.add_column("Value", overflow="fold", no_wrap=False)
    for k, v in rows:
        t.add_row(k, v)
    console.print(t, width=w)


# ---------------------------------------------------------------------------
# Startup & scrape
# ---------------------------------------------------------------------------

def print_banner(version: str = "1.0.0") -> None:
    console.print(
        Panel(
            f"[bold cyan]S3Threat[/]  [dim]v{version}[/]\n"
            "[dim]S3 exposure discovery · misconfiguration audit · pentest recon[/]",
            border_style="cyan",
            padding=(0, 2),
            width=_usable_width(),
        )
    )


def print_cli_help(parser, *, prog: str, version: str) -> None:
    """Rich help screen for security researchers and pentesters."""
    import io

    print_banner(version)
    console.print()

    kv_table(
        "Who this is for",
        [
            ("Audience", "Penetration testers, red team, cloud security assessors"),
            ("Auth model", "Anonymous S3 API (no AWS keys for discovery)"),
            ("Optional", "AWS CLI (--aws) when you have authorized account access"),
            ("Output", "Live Rich UI + JSON for reporting pipelines"),
        ],
        border="blue",
    )
    console.print()

    w = _usable_width()
    modes = _make_table(
        title="[bold]Operations[/]",
        header_style="bold cyan",
    )
    modes.add_column("Mode", style="bold", no_wrap=True, width=12)
    modes.add_column("Invoke", style="cyan", overflow="fold", width=max(24, w // 3))
    modes.add_column("Purpose", style="dim", overflow="fold")
    modes.add_row(
        "Discover",
        f"{prog} SEED [SEED ...] -o out.json",
        "Enumerate & probe buckets from target keywords",
    )
    modes.add_row(
        "OSINT scrape",
        f"{prog} --site-url URL --depth 3",
        "Derive seeds from corporate website content",
    )
    modes.add_row(
        "Random hunt",
        f"{prog} --random --until-interesting",
        "Batch dictionary names until INTERESTING hit",
    )
    modes.add_row(
        "Audit",
        f"{prog} --audit BUCKET [--aws]",
        "18-point checklist on one bucket",
    )
    modes.add_row(
        "View",
        f"{prog} --view BUCKET/key",
        "List objects or preview file contents",
    )
    modes.add_row(
        "Download",
        f"{prog} --download BUCKET/key",
        "Save exposed objects locally",
    )
    console.print(modes, width=w)
    console.print()

    workflow = _make_table(
        title="[bold]Typical engagement workflow[/]",
        box_style=box.SIMPLE,
        show_header=False,
    )
    workflow.add_column("Step", style="bold cyan", no_wrap=True, width=10)
    workflow.add_column("Action", overflow="fold")
    for step, action in [
        ("1. Scope", "Confirm written authorization for target org + domains"),
        ("2. Seeds", "Manual seeds, --site-url crawl, or OSINT wordlists"),
        ("3. Scan", "Run discovery with -o report.json; tune -t threads"),
        ("4. Triage", "Review INTERESTING rows; ignore public static asset buckets"),
        ("5. Audit", "--audit on confirmed buckets; add --aws if credentialed"),
        ("6. PoC", "--view / --download only with explicit approval"),
    ]:
        workflow.add_row(step, action)
    console.print(workflow, width=w)
    console.print()

    status = _make_table(
        title="[bold]Bucket status codes[/]",
        box_style=box.SIMPLE,
    )
    status.add_column("Status", no_wrap=True, width=14)
    status.add_column("Meaning", overflow="fold")
    for code, meaning in [
        ("WRITABLE", "Anonymous upload succeeded — critical"),
        ("OPEN", "Anonymous ListBucket succeeded"),
        ("PRIVATE", "Bucket exists; anonymous access denied"),
        ("NONE", "No bucket at this name"),
        ("INTERESTING", "Triage flag — manual review recommended"),
    ]:
        style = "bold white on red" if code == "WRITABLE" else (
            "bold red" if code == "OPEN" else (
                "bold yellow" if code == "PRIVATE" else (
                    "bold magenta" if code == "INTERESTING" else "dim"
                )
            )
        )
        status.add_row(f"[{style}]{code}[/]", meaning)
    console.print(status, width=w)
    console.print()

    buf = io.StringIO()
    parser.print_help(buf)
    help_w = _usable_width()
    console.print(Panel(
        Syntax(
            buf.getvalue().replace("optional arguments:", "options:")
            .replace("positional arguments:", "arguments:"),
            "bash",
            theme="monokai",
            line_numbers=False,
            word_wrap=True,
        ),
        title=f"[bold]Options[/]  [dim]{prog} {version}[/]",
        border_style="dim",
        width=help_w,
    ))
    console.print()
    warn(
        "Authorized assessments only. You are responsible for scope, RoE, and evidence handling."
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
    w = _usable_width()
    t = _make_table(
        title=f"[bold]{title}[/]",
        box_style=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        row_styles=["", "dim"],
    )
    t.add_column("#", style="dim", justify="right", no_wrap=True, width=5)
    t.add_column("Seed", style="bold green", overflow="ellipsis")
    for i, s in enumerate(seeds[:60], 1):
        t.add_row(str(i), _truncate(s, w - 10))
    if len(seeds) > 60:
        t.add_row("…", f"[dim]+{len(seeds) - 60} more[/]")
    console.print(t, width=w)


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


def _url_cell(r) -> str:
    """Full bucket URL for copy-paste."""
    if r.url and r.status in ("OPEN", "WRITABLE", "PRIVATE"):
        return r.url
    return ""


def hit_detail_lines(r, misconfig_labels: dict[str, str]) -> list[str]:
    """Vertical hit block: status, findings, full URL(s), one line each."""
    label, style = STATUS_STYLE.get(r.status, (r.status, "dim"))
    meta: list[str] = []
    if r.region:
        meta.append(f"[cyan]{r.region}[/]")
    if getattr(r, "severity", "") not in ("none", "", "-"):
        meta.append(severity_cell(r.severity))
    if r.object_count:
        meta.append(f"[dim]{r.object_count} objs[/]")
    if getattr(r, "sample_bytes", 0):
        meta.append(f"[dim]{format_bytes(r.sample_bytes)}[/]")
    if r.interesting:
        meta.append("[bold magenta]★ INTERESTING[/]")
    if getattr(r, "interest", 0):
        meta.append(f"[dim]score {r.interest}[/]")

    head = f"[{style}]{label}[/]  [bold]{r.bucket}[/]"
    if meta:
        head += "  " + "  ".join(meta)
    lines = [head]

    if r.misconfigs:
        lines.append("  " + misconfig_tags(r.misconfigs, misconfig_labels))
    if r.reasons:
        lines.append(f"  [dim]triage:[/] {'; '.join(r.reasons)}")
    top_audit = sorted(
        getattr(r, "audit_findings", []) or [],
        key=lambda f: ["critical", "high", "medium", "low", "info"].index(
            f.get("severity", "info")
        )
        if f.get("severity") in ("critical", "high", "medium", "low", "info")
        else 5,
    )[:2]
    for f in top_audit:
        lines.append(
            f"  {severity_cell(f['severity'])}  "
            f"[dim]{f.get('section', '')}[/]  {f.get('check', '')}"
        )
    if r.url:
        lines.append(f"  [cyan underline]{r.url}[/]")
    if r.object_urls:
        for url in r.object_urls[:5]:
            lines.append(f"    [dim]→[/] [cyan]{url}[/]")
    elif r.status in ("OPEN", "WRITABLE") and r.sample_keys:
        for key in r.sample_keys[:3]:
            lines.append(f"    [dim]·[/] [cyan]{key}[/]")
        if len(r.sample_keys) > 3:
            lines.append(f"    [dim]… +{len(r.sample_keys) - 3} keys[/]")
    if r.note:
        lines.append(f"  [dim]{r.note}[/]")
    return lines


def new_findings_table(title: str = "S3 Recon Findings") -> Table:
    w = _usable_width()
    compact = w < 100
    t = _make_table(
        title=f"[bold cyan]{title}[/]",
        box_style=box.SIMPLE_HEAVY,
        header_style="bold white on blue",
        border_style="blue",
        show_lines=False,
    )
    t.add_column("St", no_wrap=True, width=6)
    t.add_column("Bucket", style="bold", overflow="ellipsis", width=22 if compact else 28)
    t.add_column(
        "URL",
        style="cyan",
        overflow="fold",
        no_wrap=False,
        width=max(28, w // 3) if compact else max(36, w // 4),
    )
    if not compact:
        t.add_column("Reg", style="cyan", no_wrap=True, width=11, overflow="ellipsis")
        t.add_column("Objs", justify="right", style="dim", no_wrap=True, width=6)
        t.add_column("Size", justify="right", no_wrap=True, width=8)
    t.add_column("Sev", justify="center", no_wrap=True, width=8)
    t.add_column("Scr", justify="right", no_wrap=True, width=4)
    t.add_column("Findings", overflow="fold", style="dim", no_wrap=False)
    t._s3_compact = compact  # noqa: SLF001 — layout hint for row builder
    return t


def _findings_summary(r, misconfig_labels: dict[str, str], max_len: int) -> str:
    """One-line findings cell (URLs live in the URL column)."""
    top_audit = sorted(
        getattr(r, "audit_findings", []) or [],
        key=lambda f: ["critical", "high", "medium", "low", "info"].index(
            f.get("severity", "info")
        )
        if f.get("severity") in ("critical", "high", "medium", "low", "info")
        else 5,
    )[:1]
    bits = []
    if r.misconfigs:
        plain = ", ".join(misconfig_labels.get(m, m) for m in r.misconfigs[:3])
        if len(r.misconfigs) > 3:
            plain += f" +{len(r.misconfigs) - 3}"
        bits.append(plain)
    if top_audit:
        f = top_audit[0]
        bits.append(f"{f['severity']}: {f['check']}")
    if r.reasons:
        bits.append(_strip_markup("; ".join(r.reasons[:2])))
    text = " · ".join(bits) if bits else "—"
    return _truncate(text, max_len)


def result_row_cells(r, misconfig_labels: dict[str, str], *, compact: bool = False) -> tuple:
    w = _usable_width()
    score = (
        f"[bold magenta]{r.interest}[/]"
        if r.interesting
        else (f"[dim]{r.interest}[/]" if r.interest else "[dim]-[/]")
    )
    bucket = f"[bold]{_truncate(r.bucket, 22 if compact else 28)}[/]"
    if r.interesting:
        bucket += " [magenta]★[/]"
    url = _url_cell(r) or "[dim]—[/]"
    count = r.object_count or ("-" if r.status not in ("OPEN", "WRITABLE") else "0")
    if r.interesting:
        count = f"[bold magenta]{count}[/]"
    size = format_bytes(r.sample_bytes) if r.sample_bytes else "[dim]-[/]"
    detail = _findings_summary(r, misconfig_labels, max_len=max(24, w // 4))

    base = (
        status_cell(r.status),
        bucket,
        url,
    )
    if compact:
        return base + (
            severity_cell(r.severity),
            score,
            detail,
        )
    return base + (
        _truncate(r.region or "-", 11),
        count,
        size,
        severity_cell(r.severity),
        score,
        detail,
    )


def print_findings_table(
    results: list,
    misconfig_labels: dict[str, str],
    *,
    title: str = "S3 Recon Findings",
) -> None:
    """Print one findings table (sorted, with URLs for accessible buckets)."""
    if not results:
        info("No buckets to display.")
        return
    w = _usable_width()
    t = new_findings_table(title=title)
    compact = getattr(t, "_s3_compact", False)
    for r in results:
        t.add_row(*result_row_cells(r, misconfig_labels, compact=compact))
    console.print(t, width=w)


def stats_line(probed: int, hits: int, interesting: int, batch: int = 0) -> str:
    batch_s = f"  [cyan]batch[/] [bold]{batch}[/]" if batch else ""
    return (
        f"[bold cyan]S3Threat[/]{batch_s}   "
        f"[dim]probed[/] [bold]{probed}[/]   "
        f"[yellow]hits[/] [bold]{hits}[/]   "
        f"[magenta]interesting[/] [bold]{interesting}[/]"
    )


def print_hit(r, misconfig_labels: dict[str, str]) -> None:
    console.print(Text.from_markup("\n".join(hit_detail_lines(r, misconfig_labels))))


def live_hits_panel(
    hits: list,
    misconfig_labels: dict[str, str],
    *,
    max_visible: int = 18,
) -> Panel:
    """Stacked hit blocks for the live scan view."""
    w = _usable_width()
    if not hits:
        return Panel(
            Text("Waiting for hits…", style="dim"),
            title="[bold]Hits[/]",
            border_style="yellow",
            padding=(0, 1),
            width=w,
        )
    overflow = max(0, len(hits) - max_visible)
    visible = hits[-max_visible:] if overflow else hits
    body_lines: list[str] = []
    if overflow:
        body_lines.append(f"[dim]… {overflow} earlier hit(s) above[/]")
        body_lines.append("")
    for i, r in enumerate(visible):
        if i:
            body_lines.append("[dim]" + "─" * min(40, w - 4) + "[/]")
        body_lines.extend(hit_detail_lines(r, misconfig_labels))
    title = f"[bold]Hits[/] [yellow]({len(hits)})[/]"
    return Panel(
        Text.from_markup("\n".join(body_lines)),
        title=title,
        border_style="yellow",
        padding=(0, 1),
        width=w,
    )


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

    w = _usable_width()
    t = _make_table(
        title="[bold]Checklist findings[/]",
        box_style=box.SIMPLE_HEAVY,
        row_styles=["", "on grey11"],
    )
    t.add_column("Sev", no_wrap=True, width=10)
    t.add_column("Sec", style="cyan", no_wrap=True, width=8, overflow="ellipsis")
    t.add_column("Check", style="bold", overflow="fold", width=max(18, w // 4))
    t.add_column("Detail", overflow="fold", style="dim")
    order = {s: i for i, s in enumerate(severity_order)}
    for f in sorted(
        r.audit_findings,
        key=lambda x: (order.get(x["severity"], 9), x["section"]),
    ):
        sev = f["severity"]
        t.add_row(
            severity_cell(sev),
            _truncate(f["section"], 8),
            _truncate(f["check"], max(24, w // 4)),
            _truncate(f["detail"], max(40, w // 2)),
        )
    console.print(t, width=w)


def print_summary(results: list, probed: int) -> None:
    crit = sum(r.status == "WRITABLE" for r in results)
    opn = sum(r.status == "OPEN" for r in results)
    priv = sum(r.status == "PRIVATE" for r in results)
    none = sum(r.status == "NONE" for r in results)
    err = sum(r.status == "ERROR" for r in results)
    interesting = sum(r.interesting for r in results)
    policy = sum("public-policy" in r.misconfigs for r in results)
    acl = sum("public-acl" in r.misconfigs for r in results)
    reads = sum("public-read" in r.misconfigs for r in results)
    deletable = sum("deletable" in r.misconfigs for r in results)
    website = sum("website" in r.misconfigs for r in results)
    exposed_bytes = sum(
        r.sample_bytes for r in results if r.status in ("OPEN", "WRITABLE")
    )
    listed_keys = sum(
        len(r.sample_keys) for r in results if r.status in ("OPEN", "WRITABLE")
    )
    audit_crit = audit_high = 0
    for r in results:
        for f in r.audit_findings or []:
            sev = f.get("severity", "")
            if sev == "critical":
                audit_crit += 1
            elif sev == "high":
                audit_high += 1

    t = _make_table(
        title="[bold cyan]Summary[/]",
        box_style=box.DOUBLE_EDGE,
        border_style="cyan",
        padding=(0, 2),
        width=min(52, _usable_width()),
    )
    t.add_column("Metric", style="bold", no_wrap=True)
    t.add_column("Value", justify="right", no_wrap=True)
    rows: list[tuple[str, str]] = [
        ("Writable", f"[bold white on red]{crit}[/]"),
        ("Open (listable)", f"[bold red]{opn}[/]"),
        ("Private (exists)", f"[bold yellow]{priv}[/]"),
        ("Interesting ★", f"[bold magenta]{interesting}[/]"),
    ]
    if exposed_bytes:
        rows.append(("Listed sample size", f"[bold]{format_bytes(exposed_bytes)}[/]"))
    if listed_keys:
        rows.append(("Sample keys listed", str(listed_keys)))
    if policy:
        rows.append(("Public policy", str(policy)))
    if acl:
        rows.append(("Public ACL", str(acl)))
    if reads:
        rows.append(("Public read", str(reads)))
    if deletable:
        rows.append(("Anonymous delete", str(deletable)))
    if website:
        rows.append(("Static website", str(website)))
    if audit_crit or audit_high:
        rows.append(
            ("Audit critical / high", f"[bold red]{audit_crit}[/] / [bold]{audit_high}[/]"),
        )
    if err:
        rows.append(("Errors", str(err)))
    if none:
        rows.append(("Not found", str(none)))
    rows.append(("Total probed", f"[bold]{probed}[/]"))
    for k, v in rows:
        t.add_row(k, v)
    console.print(t, width=min(52, _usable_width()))


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
            width=_usable_width(),
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
    w = _usable_width()
    t = _make_table(
        title=f"[bold]Objects[/] [dim]({len(keys)} total)[/]",
        box_style=box.SIMPLE,
        header_style="bold cyan",
    )
    t.add_column("Key", style="cyan", overflow="ellipsis")
    t.add_column("Size", justify="right", no_wrap=True, width=10)
    key_max = max(20, w - 14)
    for k in keys[:limit]:
        sz = sizes.get(k, 0)
        t.add_row(_truncate(k, key_max), format_bytes(sz) if sz else "[dim]-[/]")
    if len(keys) > limit:
        t.add_row(f"[dim]… +{len(keys) - limit} more[/]", "")
    console.print(t, width=w)


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


def live_scan_group(
    stats: str,
    progress: Progress,
    hits: list | None = None,
    misconfig_labels: dict[str, str] | None = None,
) -> Group:
    """Live scan UI — stats, progress, and stacked hit blocks."""
    w = _usable_width()
    items = [
        Panel(stats, border_style="blue", padding=(0, 1), width=w),
        progress,
    ]
    if hits is not None and misconfig_labels is not None:
        items.append(live_hits_panel(hits, misconfig_labels))
    return Group(*items)
