# S3Threat

**Anonymous Amazon S3 bucket discovery and misconfiguration assessment for authorized security engagements.**

S3Threat generates high-signal bucket name candidates, probes the public S3 API without credentials, classifies exposure, and surfaces only findings that warrant manual review. It is designed for penetration testers, cloud security engineers, and red teams operating under explicit written authorization.

---

## Features

| Capability | Description |
|------------|-------------|
| **Target-scoped enumeration** | Permute seeds with environment affixes (`dev`, `prod`, `backup`, `assets`, …), separators, and optional year suffixes |
| **Dictionary-driven discovery** | `--random` mode uses `dict/english.txt` with realistic naming patterns (short stems, affixes, years) |
| **Continuous batch scanning** | `--until-interesting` appends hits to a single live table across batches—no overwritten output |
| **Misconfiguration probes** | Anonymous ListBucket, GetObject, bucket policy, bucket ACL, and optional write tests |
| **Smart triage** | `INTERESTING` flag based on sensitive keys, extensions, and exposure—not every open listing |
| **Object intelligence** | Per-bucket object counts and sampled byte totals in the results table |
| **Inspect & export** | `--view` and `--download` for buckets, keys, or full HTTPS URLs |
| **Structured output** | JSON export for pipelines and reporting |

---

## Classification model

| Status | Meaning |
|--------|---------|
| `WRITABLE` | Anonymous `PutObject` succeeded (critical) |
| `OPEN` | Anonymous `ListBucket` succeeded |
| `PRIVATE` | Bucket exists; anonymous access denied |
| `NONE` | No bucket at that name (404) |
| `ERROR` | Network, timeout, or unexpected HTTP response |

**Misconfiguration tags:** `listable`, `writable`, `public-policy`, `public-acl`, `public-read`

A bucket is marked **INTERESTING** only when triage detects meaningful risk—for example sensitive object names, readable policies, or anonymous writes—not merely because listing is enabled.

---

## Requirements

- Python **3.10+**
- Network access to `*.amazonaws.com`
- [Rich](https://github.com/Textualize/rich) (`pip install rich`)

```bash
pip install -r requirements.txt
```

---

## Quick start

### Seed-based scan (recommended for engagements)

```bash
python3 main.py acme acmecorp acme-corp -o findings.json -t 80
```

### Random discovery with live table until a high-value hit

```bash
python3 main.py --random --until-interesting --batch-size 400 -t 80
```

### Inspect or download a finding

```bash
python3 main.py --view acme-prod-backup
python3 main.py --view acme-prod-backup/exports/customers.csv
python3 main.py --download https://bucket.s3.us-west-2.amazonaws.com/path/to/object.zip
```

---

## Usage

```
usage: main.py [-h] [--affixes AFFIXES] [--years] [--random]
               [--random-count N] [--random-seed N] [--until-interesting]
               [--batch-size N] [--words-dict FILE] [-t THREADS]
               [--check-write] [-o OUTPUT] [--show-all] [--view TARGET]
               [--download TARGET] [--download-dir DIR] [--max-download BYTES]
               [seeds ...]
```

### Discovery modes

| Mode | Command |
|------|---------|
| Seeds only | `python3 main.py <seed> [seed ...]` |
| Seeds + affix years | `python3 main.py acme --years` |
| Random candidates | `python3 main.py --random --random-count 5000` |
| Random until triage hit | `python3 main.py --random --until-interesting` |
| Combined | `python3 main.py acme --random --random-count 2000` |

### Notable flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--threads` | `60` | Concurrent probe workers |
| `-o`, `--output` | — | Write JSON findings |
| `--check-write` | off | Non-destructive PUT probe on open buckets (**authorized only**) |
| `--show-all` | off | Include all statuses in the final table |
| `--words-dict` | `dict/english.txt` | Custom word list for `--random` |
| `--download-dir` | `downloads/` | Output root for `--download` |
| `--max-download` | 50 MiB | Per-object download cap |

### Target formats (`--view` / `--download`)

- Bucket name: `my-bucket`
- Bucket and key: `my-bucket/path/to/file.env`
- Virtual-hosted URL: `https://my-bucket.s3.eu-west-1.amazonaws.com/path/to/file`

---

## Output

The terminal UI provides:

1. A **live findings table** that accumulates rows across batches
2. A **progress bar** with batch and completion metrics
3. A **summary panel** (writable / open / private / interesting counts)

JSON output (`-o`) includes buckets with status `OPEN`, `WRITABLE`, `PRIVATE`, or `interesting: true`, with fields for region, URLs, sample keys, sizes, misconfigs, and triage reasons.

---

## Project layout

```
S3Threat/
├── main.py              # CLI entry point
├── requirements.txt     # Python dependencies
├── dict/
│   └── english.txt      # Word list for --random (alpha words, 3–12 chars used)
├── downloads/           # Default --download output (gitignored)
├── LICENSE
└── README.md
```

---

## Methodology notes

- **Existence checks** use `GET ?max-keys=1` rather than `HEAD`, because many real buckets return misleading `404` responses to anonymous `HEAD`.
- **Random names** favor short dictionary stems and common cloud naming patterns instead of obscure multi-word combinations.
- **Write probes** upload a single empty test object (`s3recon-authz-write-test.txt`) when `--check-write` is enabled; use only with customer approval.

---

## Legal and ethical use

**Use S3Threat only on AWS accounts, buckets, and infrastructure you own or are explicitly authorized to test in writing.**

Unauthorized scanning may violate computer-fraud laws, cloud provider acceptable-use policies, and your employer's rules of engagement. The authors assume no liability for misuse. You are responsible for scope, consent, data handling, and reporting.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author & support

Maintained by [**syrex1013**](https://github.com/syrex1013).

If this tool saves you time on an engagement, consider supporting development via GitHub Sponsors (see `.github/FUNDING.yml`).
