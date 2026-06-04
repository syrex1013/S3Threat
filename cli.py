"""
S3Threat command-line interface — argument groups and help text.
"""

from __future__ import annotations

import argparse
import textwrap

VERSION = "1.1.0"
PROG = "s3threat"
EPILOG = """
AUTHORIZED USE ONLY
  Run only against AWS resources you own or are explicitly permitted to test.
  Write probes (--check-write) modify bucket contents — require written approval.

DOCUMENTATION
  Checklist mapping : CHECKLIST.md
  Full guide        : README.md

EXAMPLES
  Engagement scan (seeds + JSON export)
    %(prog)s acme acmecorp -o report.json -t 80

  OSINT seeds from corporate website (depth 3)
    %(prog)s --site-url https://www.acme.com --depth 3 -o report.json

  Scrape only — build wordlist for other tools
    %(prog)s --site-url https://acme.com --scrape-only --save-seeds seeds.txt

  Continuous random hunt until high-value exposure
    %(prog)s --random --until-interesting --batch-size 400

  Single-bucket checklist (anonymous + optional AWS CLI)
    %(prog)s --audit target-bucket --aws --aws-profile assess

  Inspect / exfiltrate (authorized)
    %(prog)s --view target-bucket/backup/db.sql
    %(prog)s --download https://bucket.s3.amazonaws.com/path/file.zip
""".strip()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=PROG,
        description=textwrap.dedent("""\
            S3Threat — professional S3 exposure discovery for security researchers
            and penetration testers.

            Enumerate bucket names, probe anonymous S3 API access, triage findings
            by real risk, and run an 18-point misconfiguration checklist. No AWS
            credentials required for core discovery; optional AWS CLI augments audit
            when you have authorized console/API access to the account.
        """).strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG % {"prog": PROG},
        add_help=False,
    )

    ap.add_argument(
        "-h", "--help",
        action="store_true",
        help="show professional help (Rich) and exit",
    )
    ap.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    # --- positional ---
    pos = ap.add_argument_group(
        "target seeds",
        "Brand, product, or domain stems used to generate bucket name candidates. "
        "Optional when using --site-url or --random.",
    )
    pos.add_argument(
        "seeds",
        nargs="*",
        metavar="SEED",
        help="keywords: brand name, domain stem, product lines (e.g. acme acmecorp)",
    )

    # --- recon ---
    recon = ap.add_argument_group(
        "reconnaissance & name generation",
        "Build the candidate bucket list before probing.",
    )
    recon.add_argument(
        "--site-url",
        metavar="URL",
        help="crawl company website; extract seeds from HTML, paths, JS, JSON-LD",
    )
    recon.add_argument(
        "--depth",
        type=int,
        default=3,
        metavar="N",
        help="max link depth for --site-url crawl (default: 3)",
    )
    recon.add_argument(
        "--max-pages",
        type=int,
        default=80,
        metavar="N",
        help="max pages fetched per crawl (default: 80)",
    )
    recon.add_argument(
        "--scrape-only",
        action="store_true",
        help="crawl --site-url only; print/save seeds without S3 probes",
    )
    recon.add_argument(
        "--save-seeds",
        metavar="FILE",
        help="write scraped seeds to file (one per line)",
    )
    recon.add_argument(
        "--affixes",
        metavar="FILE",
        help="extra affix wordlist (one word per line) for permutations",
    )
    recon.add_argument(
        "--years",
        action="store_true",
        help="append recent years to seed permutations",
    )
    recon.add_argument(
        "--random",
        action="store_true",
        help="add random names from English dictionary (dict/english.txt)",
    )
    recon.add_argument(
        "--random-count",
        type=int,
        default=5000,
        metavar="N",
        help="random bucket names to generate (default: 5000)",
    )
    recon.add_argument(
        "--random-seed",
        type=int,
        default=None,
        metavar="N",
        help="RNG seed for reproducible --random output",
    )
    recon.add_argument(
        "--until-interesting",
        action="store_true",
        help="with --random: batch until an INTERESTING finding (live table)",
    )
    recon.add_argument(
        "--batch-size",
        type=int,
        default=400,
        metavar="N",
        help="names per batch for --until-interesting (default: 400)",
    )
    recon.add_argument(
        "--words-dict",
        metavar="FILE",
        help="custom wordlist for --random (default: dict/english.txt)",
    )

    # --- scan ---
    scan = ap.add_argument_group(
        "scanning & output",
        "Concurrent anonymous S3 probing and reporting.",
    )
    scan.add_argument(
        "-t", "--threads",
        type=int,
        default=60,
        metavar="N",
        help="concurrent probe workers (default: 60)",
    )
    scan.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="export findings as JSON (status, audit, severity, sample keys)",
    )
    scan.add_argument(
        "--show-all",
        action="store_true",
        help="include NONE/ERROR rows in final results table",
    )
    scan.add_argument(
        "--check-write",
        action="store_true",
        help="test anonymous PUT/DELETE on OPEN buckets (destructive; authorized only)",
    )

    # --- audit ---
    audit = ap.add_argument_group(
        "security audit",
        "Deep checklist on a single bucket (see CHECKLIST.md).",
    )
    audit.add_argument(
        "--audit",
        metavar="BUCKET",
        help="run full misconfiguration report on one bucket and exit",
    )
    audit.add_argument(
        "--aws",
        action="store_true",
        help="include AWS CLI checks (encryption, logging, public access block, …)",
    )
    audit.add_argument(
        "--aws-profile",
        metavar="PROFILE",
        help="AWS CLI profile for --aws / --audit",
    )

    # --- inspect ---
    inspect = ap.add_argument_group(
        "inspect & download",
        "Post-discovery object review. TARGET = bucket | bucket/key | HTTPS URL.",
    )
    inspect.add_argument(
        "--view",
        metavar="TARGET",
        help="inspect bucket listing or view object (syntax-highlighted text)",
    )
    inspect.add_argument(
        "--download",
        metavar="TARGET",
        help="download object or all listable keys in a bucket",
    )
    inspect.add_argument(
        "--download-dir",
        metavar="DIR",
        default="downloads/",
        help="download output directory (default: downloads)",
    )
    inspect.add_argument(
        "--max-download",
        metavar="BYTES",
        type=int,
        default=50 * 1024 * 1024,
        help="per-object download size cap in bytes (default: 52428800)",
    )

    return ap


def parse_args(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if args.help:
        return None, ap
    return args, ap
