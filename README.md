# S3Threat

<p align="center">
  <strong>Anonymous S3 bucket discovery, exposure triage, and security auditing</strong><br>
  For authorized penetration tests and cloud security assessments
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://github.com/syrex1013/S3Threat"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python"></a>
</p>

---

## Overview

**S3Threat** is a CLI built for **penetration testers, red team operators, and cloud security researchers** performing authorized AWS assessments. It discovers S3 buckets without credentials, classifies anonymous exposure, runs an [18-point security checklist](CHECKLIST.md), and presents results in a **Rich** terminal UI (live tables, severity colors, progress bars).

```bash
python3 main.py -h    # full professional help (Rich)
python3 main.py -V    # version
```

Typical workflow:

1. **Generate candidates** from brand seeds, a crawled company website, or a random dictionary.
2. **Probe** buckets concurrently over the public S3 API.
3. **Triage** so only meaningful findings are marked **INTERESTING** (not every public listing).
4. **Audit**, **view**, or **download** exposed objects for manual review.

---

## Features

| Area | What it does |
|------|----------------|
| **Seed enumeration** | Permute keywords with affixes (`dev`, `prod`, `backup`, …), separators, optional years |
| **Site scraping** | Crawl `--site-url` (depth **3** by default); extract seeds from HTML, paths, JS, JSON-LD |
| **Random discovery** | Realistic names from `dict/english.txt`; one full randomized pass |
| **Repeat-until-hit** | Keep generating fresh random passes until a hit appears |
| **Anonymous probes** | ListBucket, GetObject, policy/ACL/CORS/website, optional PUT/DELETE test |
| **Smart triage** | INTERESTING only when content, writes, or serious misconfigs warrant review |
| **Security audit** | Checklist-aligned findings with critical / high / medium severity |
| **AWS CLI mode** | Optional `--aws` for encryption, versioning, logging, Public Access Block, etc. |
| **Rich UI** | Banner, config tables, live findings board, syntax-highlighted `--view` |
| **Export** | JSON with `audit_findings`, `severity`, sample keys, and sizes |

---

## Requirements

- **Python 3.10+**
- Network access to `*.amazonaws.com`
- **[Rich](https://github.com/Textualize/rich)** (terminal UI)
- **AWS CLI** (optional, only for `--aws` / authenticated checklist items)

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/syrex1013/S3Threat.git
cd S3Threat
pip install -r requirements.txt
```

---

## Examples & Outputs

### 1. Targeted Seed Discovery
Generate candidates from multiple brand keywords simultaneously.
```bash
python3 main.py acme acme-corp acmecorp -o findings.json -t 80
```
**Output:**
- Generates permutations for all three seeds (e.g., `acme-dev`, `acmecorp-backup`).
- Displays a live table of `OPEN`, `WRITABLE`, and `PRIVATE` buckets.

### 2. Website Spider & Seed Extraction
Crawl a corporate site to find hidden S3 seeds in HTML, JS, or meta tags.
```bash
# Crawl depth 3, then scan
python3 main.py --site-url https://www.google.com --depth 3

# Scrape tokens only (no S3 probing)
python3 main.py --site-url https://www.google.com --scrape-only --save-seeds google_seeds.txt
```

### 3. OSINT-based Discovery
Query Shodan, Censys, and ZoomEye for subdomains and leaked bucket names.
```bash
# Requires keys.json
python3 main.py --osint google.com
```

### 4. Randomized Hunting (Dictionary Pass)
Search for buckets using common English words + common S3 suffixes.
```bash
python3 main.py --random --random-count 1000 --until-found
```

### 5. Custom Bucket List
Scan a specific list of bucket names from a text file.
```bash
python3 main.py --bucket-file my_targets.txt --show-all
```

### 6. S3-Compatible Storage (MinIO, Ceph, RGW)
Scan private network ranges or custom endpoints for exposed buckets.
```bash
# Scan a CIDR range with seeds (seeds required for named bucket probing)
python3 main.py acme backups --cidr 10.0.0.0/24

# Target a specific MinIO instance
python3 main.py backups data logs --endpoint http://minio.internal:9000
```

### 7. Security Audit & Object Review
Run a deep 18-point checklist on a specific bucket.
```bash
# Anonymous + AWS CLI authenticated audit
python3 main.py --audit target-bucket --aws

# Preview object content (syntax highlighted)
python3 main.py --view target-bucket/config/db.json
```

---

## How buckets are classified

| Status | Meaning |
|--------|---------|
| `WRITABLE` | Anonymous upload succeeded — **critical** |
| `OPEN` | Anonymous `ListBucket` succeeded |
| `PRIVATE` | Bucket exists; anonymous access denied |
| `NONE` | No bucket at that name |
| `ERROR` | Timeout or unexpected HTTP response |

**Misconfiguration tags:** `listable`, `writable`, `deletable`, `public-policy`, `public-acl`, `public-read`, `public-cors`, `website`

A row is marked **INTERESTING** when triage or audit finds real risk (sensitive keys, public policy, anonymous writes, etc.) — not merely because listing is enabled.

---

## Command reference

```
python3 main.py [-h] [seeds ...]
    [--affixes FILE] [--years]
    [--site-url URL] [--depth N] [--max-pages N] [--scrape-only] [--save-seeds FILE]
    [--random] [--random-count N] [--random-seed N] [--until-found]
    [--words-dict FILE]
    [-t THREADS] [--check-write] [-o OUTPUT] [--show-all]
    [--audit BUCKET] [--aws] [--aws-profile PROFILE]
    [--view TARGET] [--download TARGET]
    [--download-dir DIR] [--max-download BYTES]
```

### Discovery

| Flag | Default | Description |
|------|---------|-------------|
| `seeds` | — | Brand / product keywords (e.g. `acme acmecorp`) |
| `--site-url` | — | Crawl company site for seeds |
| `--depth` | `3` | Max link depth for crawl |
| `--max-pages` | `80` | Page fetch limit per crawl |
| `--scrape-only` | off | Crawl only; no S3 probes |
| `--save-seeds` | — | Write scraped seeds to file |
| `--osint` | — | Query Shodan/Censys/ZoomEye for subdomains of DOMAIN |
| `--random` | off | Add dictionary-based random names |
| `--random-count` | `5000` | Random names to generate |
| `--until-found` | off | Repeat fresh random passes until a hit appears |
| `--affixes` | — | Extra affix word list (one per line) |
| `--years` | off | Append recent years to permutations |

### Scanning & output

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--threads` | `60` | Concurrent workers |
| `-o`, `--output` | — | JSON findings path |
| `--show-all` | off | Include PRIVATE and NONE rows in final findings (ERROR always hidden) |
| `--check-write` | off | Anonymous PUT/DELETE test on open buckets |

### Audit & AWS

| Flag | Description |
|------|-------------|
| `--audit BUCKET` | Full checklist report for one bucket |
| `--aws` | Run authenticated AWS CLI checks (see [CHECKLIST.md](CHECKLIST.md)) |
| `--aws-profile` | AWS CLI profile name |

### Inspect & download

| Flag | Default | Description |
|------|---------|-------------|
| `--view TARGET` | — | Inspect bucket or object (syntax highlight for text) |
| `--download TARGET` | — | Download object or listable bucket |
| `--download-dir` | `downloads/` | Download output directory |
| `--max-download` | 50 MiB | Per-file size limit |

**TARGET formats:** `bucket`, `bucket/key/path`, or `https://bucket.s3.region.amazonaws.com/key`

---

## Terminal output

S3Threat uses [Rich](https://github.com/Textualize/rich) for all output:

- **Banner** and run configuration table  
- **Live findings board** - rows append as they arrive (not overwritten)
- **Colored status** - writable (red), open, private, severity columns
- **Stacked findings output** - each hit or misconfiguration prints as a vertical block
- **Summary table** - writable / open / private / interesting counts
- **Audit tables** - checklist findings sorted by severity

---

## JSON output

With `-o findings.json`, each hit includes:

```json
{
  "bucket": "acme-prod-backup",
  "status": "OPEN",
  "region": "us-east-1",
  "url": "https://acme-prod-backup.s3.amazonaws.com/",
  "sample_keys": ["backup/data.sql"],
  "object_count": ">=25",
  "sample_bytes": 1048576,
  "misconfigs": ["listable", "public-read"],
  "severity": "critical",
  "interesting": true,
  "audit_findings": [
    {
      "section": "3. Object-level exposure",
      "check": "Anonymous GetObject",
      "severity": "critical",
      "detail": "..."
    }
  ],
  "interest": 78,
  "reasons": ["files: .sql", "keys: backup"]
}
```

---

## Project structure

```
S3Threat/
├── main.py           # Entry point, probe engine, name generation
├── cli.py            # Argument groups, help, version
├── ui.py             # Rich terminal formatting
├── audit.py          # 18-section security checklist
├── scrape.py         # Website crawler & seed extraction
├── osint.py          # Shodan / Censys / ZoomEye seed discovery
├── CHECKLIST.md      # Checklist ↔ implementation map
├── requirements.txt
├── dict/
│   └── english.txt   # Word list for --random
├── .github/
│   └── FUNDING.yml
├── LICENSE
└── README.md
```

---

## Methodology

- **Bucket existence** — `GET ?max-keys=1` (anonymous `HEAD` often returns false 404s).
- **Random names** — Short stems + common affixes (`prod`, `backup`, years), not obscure dictionary compounds.
- **Site scrape** — Same-origin BFS; tokens from meta tags, paths, inline JS, JSON-LD, S3 hints in scripts.
- **Write probe** — Uploads `security-test/s3-threat-write-test.txt` and attempts delete when `--check-write` is set. Use only with written authorization.

Details: [CHECKLIST.md](CHECKLIST.md)

---

## Legal & ethical use

**Use S3Threat only on infrastructure you own or are explicitly authorized to test.**

Unauthorized scanning may violate law and cloud provider policies. You are responsible for scope, consent, and data handling. The authors assume no liability for misuse.

---

## License

[MIT License](LICENSE) — Copyright (c) 2026 [syrex1013](https://github.com/syrex1013)

---

## Support

Maintained by [**syrex1013**](https://github.com/syrex1013).  
GitHub Sponsors: see [.github/FUNDING.yml](.github/FUNDING.yml).
