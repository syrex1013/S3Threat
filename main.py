#!/usr/bin/env python3
"""
S3Threat — S3 exposure discovery and security audit for authorized assessments.

Professional CLI for penetration testers and cloud security researchers.
Run ``python3 main.py -h`` for the full Rich help screen.
"""

import concurrent.futures as cf
import json
import os
import random
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from itertools import product

import audit as s3_audit
import cli
import scrape as site_scrape
import osint

try:
    from rich.live import Live
except ImportError:
    sys.exit("[!] missing dependency: pip install rich")

import ui

try:
    _SSL_CTX = ssl._create_unverified_context()
except Exception:
    _SSL_CTX = None


# ----------------------------------------------------------------------------
# Smart name generation
# ----------------------------------------------------------------------------

AFFIXES = [
    "dev", "develop", "development", "prod", "production", "stage", "staging",
    "test", "testing", "qa", "uat", "demo", "sandbox", "internal", "intranet",
    "backup", "backups", "bak", "bkp", "archive", "archives", "old", "new",
    "data", "files", "file", "assets", "asset", "static", "media", "images",
    "img", "photos", "videos", "uploads", "upload", "downloads", "download",
    "public", "private", "secret", "secrets", "confidential", "shared",
    "logs", "log", "dump", "dumps", "db", "database", "sql", "mysql",
    "config", "configs", "configuration", "settings", "env",
    "cdn", "web", "www", "site", "app", "apps", "api", "mobile", "ios",
    "android", "build", "builds", "artifacts", "release", "releases",
    "store", "storage", "bucket", "s3", "cloud", "tmp", "temp", "cache",
    "client", "clients", "customer", "customers", "user", "users", "admin",
    "finance", "hr", "billing", "invoices", "reports", "exports", "import",
    "docs", "documents", "repo", "git", "code", "source", "src", "wp",
]

SEPARATORS = ["-", ".", "", "_"]
YEARS = [str(y) for y in range(2019, time.localtime().tm_year + 1)]
_SOURCE_STOP_TOKENS = {"com", "net", "org", "io", "co", "www", "http", "https"}
_ENVIRONMENT_WORDS = [
    "prod", "production", "dev", "development", "stage", "staging", "test",
    "testing", "qa", "uat", "lab", "sandbox", "main", "core", "live",
]
_PURPOSE_WORDS = [
    "assets", "static", "media", "images", "files", "uploads", "docs",
    "documents", "archive", "archives", "backup", "backups", "logs", "log",
    "data", "database", "db", "reports", "exports", "import", "builds",
    "artifacts", "terraform-state", "tfstate", "cloudtrail", "security",
    "security-archive", "guardduty", "waf-logs", "wazuh", "malware",
    "malware-samples", "analytics", "raw-data", "processed-data",
    "curated-data", "longterm-retention",
]
_REGION_WORDS = [
    "us-east-1", "us-west-1", "us-west-2", "eu-central-1", "eu-west-1",
    "eu-west-2", "eu-west-3", "eu-north-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-south-1", "ca-central-1",
    "sa-east-1", "me-south-1",
]
_PREFIX_WORDS = [
    "aws", "s3", "cdn", "files", "assets", "media", "static", "img",
    "images", "uploads", "download", "archive", "backup", "internal",
    "corp", "mgt", "cloudtrail", "guardduty", "terraform", "iac", "security",
]

_VALID = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def valid_bucket_name(name: str) -> bool:
    if not (3 <= len(name) <= 63):
        return False
    if not _VALID.match(name):
        return False
    if ".." in name or _IP.match(name):
        return False
    if name.startswith(("xn--", "sthree-")) or name.endswith(("-s3alias", "--ol-s3")):
        return False
    return True


def generate_names(seeds, affixes, years=False):
    """Permutations across common bucket naming patterns."""
    seeds = [s.strip().lower() for s in seeds if s.strip()]
    affix_list = list(dict.fromkeys(affixes))
    extra = YEARS if years else []
    out = set()
    for s in seeds:
        if valid_bucket_name(s):
            out.add(s)
        # seed-affix and affix-seed with all separators
        for a in affix_list + _ENVIRONMENT_WORDS + _PURPOSE_WORDS:
            for sep in SEPARATORS:
                n1, n2 = f"{s}{sep}{a}", f"{a}{sep}{s}"
                if valid_bucket_name(n1):
                    out.add(n1)
                if valid_bucket_name(n2):
                    out.add(n2)
                for y in extra:
                    n3, n4 = f"{n1}{sep}{y}", f"{s}{sep}{y}"
                    if valid_bucket_name(n3):
                        out.add(n3)
                    if valid_bucket_name(n4):
                        out.add(n4)
        # seed-env-purpose and seed-purpose-env (no region expansion)
        for env in ["prod", "dev", "stage", "test"]:
            for purpose in ["backup", "data", "logs", "db", "assets", "files", "archive"]:
                for sep in ["-", "."]:
                    for n in (f"{s}{sep}{env}{sep}{purpose}", f"{s}{sep}{purpose}{sep}{env}"):
                        if valid_bucket_name(n):
                            out.add(n)
    return sorted(out)


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_WORDS = os.path.join(_SCRIPT_DIR, "dict", "english.txt")
_SYSTEM_WORDS = ("/usr/share/dict/words", "/usr/dict/words")
_FALLBACK_WORDS = (
    "alpha", "backup", "cloud", "data", "delta", "files", "green", "hello",
    "image", "lambda", "media", "north", "omega", "photo", "public", "secret",
    "south", "static", "storage", "upload", "video", "west", "archive", "beta",
    "client", "config", "deploy", "dev", "docs", "export", "finance", "gold",
    "internal", "logs", "mobile", "music", "office", "portal", "private",
    "prod", "project", "report", "sandbox", "server", "shared", "silver",
    "source", "stage", "store", "sync", "temp", "test", "tools", "vault",
    "web", "www",
)


def load_word_dictionary(path=None):
    """Load lowercase English words suitable for bucket name generation."""
    paths = []
    if path:
        paths.append(path)
    else:
        paths.append(_DEFAULT_WORDS)
        paths.extend(p for p in _SYSTEM_WORDS if os.path.isfile(p))

    words = set()
    for dict_path in paths:
        try:
            with open(dict_path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip().lower()
                    if w.isalpha() and 3 <= len(w) <= 12:
                        words.add(w)
        except OSError:
            continue
        if words:
            break

    if not words:
        words = set(_FALLBACK_WORDS)
    return sorted(words)


_RANDOM_AFFIXES = [a for a in AFFIXES if 2 <= len(a) <= 12]
_RANDOM_YEARS = [str(y) for y in range(2016, time.localtime().tm_year + 1)]
# High-frequency bucket stems seen in the wild (always in random pool)
_COMMON_STEMS = (
    "backup", "data", "test", "dev", "prod", "stage", "demo", "app", "web",
    "api", "cdn", "static", "media", "images", "files", "uploads", "public",
    "private", "storage", "assets", "logs", "db", "config", "docs", "tmp",
    "archive", "download", "video", "photo", "share", "cloud", "mobile",
)
_RANDOM_PREFIXES = list(dict.fromkeys(_PREFIX_WORDS))
_RANDOM_TYPES = list(dict.fromkeys(_PURPOSE_WORDS + [
    "web", "api", "app", "mobile", "ios", "android", "build", "release",
    "releases", "reports", "temp", "tmp", "config",
]))
_RANDOM_ENVIRONMENTS = list(dict.fromkeys(_ENVIRONMENT_WORDS))
_RANDOM_REGIONS = list(_REGION_WORDS)


def _seed_source_tokens(seed_sources):
    """Derive bucket-relevant source tokens from seed/domain strings."""
    tokens = []
    for seed in seed_sources or []:
        s = seed.strip().lower()
        if not s:
            continue
        s = re.sub(r"^https?://", "", s)
        s = s.split("/", 1)[0]
        s = s.split(":", 1)[0]
        if valid_bucket_name(s):
            tokens.append(s)

        parts = [p for p in re.split(r"[.\-_]+", s) if p]
        if not parts:
            continue
        for part in parts:
            if part in _SOURCE_STOP_TOKENS:
                continue
            if valid_bucket_name(part):
                tokens.append(part)
        if len(parts) >= 2:
            joined = "".join(parts[:2])
            dashed = f"{parts[0]}-{parts[1]}"
            for candidate in (joined, dashed):
                if valid_bucket_name(candidate):
                    tokens.append(candidate)
    return list(dict.fromkeys(tokens))


def random_word_pool(word_list, rng, max_words=2000, seed_sources=None):
    """Return source-aware random pools for bucket candidate generation."""
    seed_words = _seed_source_tokens(seed_sources)
    short = [w for w in word_list if 4 <= len(w) <= 8 and valid_bucket_name(w)]
    if len(short) > max_words:
        short = rng.sample(short, max_words)
    stems = [w for w in _COMMON_STEMS if valid_bucket_name(w)]
    extra = [w for w in _RANDOM_AFFIXES if valid_bucket_name(w)]
    prefixes = [w for w in _RANDOM_PREFIXES if valid_bucket_name(w)]
    types = [w for w in _RANDOM_TYPES if valid_bucket_name(w)]
    envs = [w for w in _RANDOM_ENVIRONMENTS if valid_bucket_name(w)]
    regions = [w for w in _RANDOM_REGIONS if valid_bucket_name(w)]
    return {
        "seed": seed_words,
        "common": list(dict.fromkeys(stems + extra)),
        "prefixes": prefixes,
        "types": types,
        "envs": envs,
        "regions": regions,
        "dict": short,
    }


def _pick_weighted_base(rng, sources):
    seed_pool = sources.get("seed", [])
    common_pool = sources.get("common", [])
    dict_pool = sources.get("dict", [])
    fallback = seed_pool or common_pool or dict_pool
    if not fallback:
        return None

    roll = rng.random()
    if seed_pool and roll < 0.60:
        return rng.choice(seed_pool)
    if common_pool and roll < 0.95:
        return rng.choice(common_pool)
    return rng.choice(dict_pool or fallback)


def generate_random_names(word_list, count, rng=None, exclude=None, sources=None):
    """
    Advanced randomized bucket discovery.
    Uses industry patterns: CloudBrute/S3Scanner style tiered mutations.
    """
    rng = rng or random.Random()
    if sources is None:
        sources = random_word_pool(word_list, rng)
    if not any(sources.get(k) for k in ("seed", "common", "dict")):
        return []
    exclude = exclude or set()

    affixes = _RANDOM_AFFIXES
    years = _RANDOM_YEARS
    seps = ["-", ".", ""]
    prefixes = sources.get("prefixes", list(_RANDOM_PREFIXES))
    types = sources.get("types", list(_RANDOM_TYPES))
    envs = sources.get("envs", list(_RANDOM_ENVIRONMENTS))
    regions = sources.get("regions", list(_RANDOM_REGIONS))

    out = set()
    if count >= 10:
        simple_pool = list(dict.fromkeys(
            sources.get("seed", [])
            + sources.get("common", [])
            + prefixes
            + types
            + envs
        ))
        simple_candidates = []
        for base in simple_pool:
            if valid_bucket_name(base):
                simple_candidates.append(base)
            for suffix in ("s3", "bucket", "files", "assets", "static"):
                for sep in ("-", ""):
                    candidate = f"{base}{sep}{suffix}"
                    if valid_bucket_name(candidate):
                        simple_candidates.append(candidate)

        simple_candidates = [
            n for n in dict.fromkeys(simple_candidates)
            if n not in exclude
        ]
        if simple_candidates:
            quota = min(len(simple_candidates), max(1, count // 5))
            out.update(rng.sample(simple_candidates, quota))

    attempts = 0
    limit = max(count * 50, 10000)
    
    while len(out) < count and attempts < limit:
        attempts += 1
        roll = rng.random()

        base = _pick_weighted_base(rng, sources)
        if not base:
            break

        # 1. High-signal source + environment/type/region combinations.
        if roll < 0.40:
            sep = rng.choice(seps)
            env = rng.choice(envs)
            typ = rng.choice(types)
            if rng.random() < 0.45 and regions:
                region = rng.choice(regions)
                name = f"{base}{sep}{typ}{sep}{env}{sep}{region}"
            elif rng.random() < 0.5:
                name = f"{base}{sep}{env}{sep}{typ}"
            else:
                name = f"{base}{sep}{typ}{sep}{env}"

        # 2. High-signal source + bucket affixes.
        elif roll < 0.64:
            a = rng.choice(affixes)
            sep = rng.choice(seps)
            name = f"{base}{sep}{a}" if rng.random() < 0.6 else f"{a}{sep}{base}"

        # 3. Infrastructure prefixes commonly seen in public buckets.
        elif roll < 0.82:
            prefix = rng.choice(prefixes)
            sep = rng.choice(seps)
            name = f"{prefix}{sep}{base}"

        # 4. Source + year / digits / region.
        elif roll < 0.92:
            if rng.random() < 0.5:
                name = f"{base}{rng.choice(seps)}{rng.choice(years)}"
            elif regions and rng.random() < 0.5:
                name = f"{base}{rng.choice(seps)}{rng.choice(regions)}"
            else:
                name = f"{base}{rng.randint(1, 9999)}"

        # 5. Two-token bucket names and dotted variants.
        else:
            other = _pick_weighted_base(rng, sources)
            if other is None or other == base:
                other = rng.choice(envs + types + affixes + regions)
            name = f"{base}.{other}" if rng.random() < 0.7 else f"{base}-{other}"

        if valid_bucket_name(name) and name not in exclude:
            out.add(name)
            
    return sorted(out)


# ----------------------------------------------------------------------------
# Triage: flag only buckets with real exposure signals
# ----------------------------------------------------------------------------

SENSITIVE_EXT = {
    ".sql", ".db", ".sqlite", ".bak", ".backup", ".dump", ".tar", ".gz", ".tgz",
    ".zip", ".7z", ".env", ".pem", ".key", ".ppk", ".pfx", ".p12", ".crt", ".cer",
    ".htpasswd", ".kdbx", ".tfstate", ".csv", ".xls", ".xlsx", ".doc", ".docx",
    ".pdf", ".log", ".json", ".yml", ".yaml", ".conf", ".config", ".ini", ".git",
}
BENIGN_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".svg", ".bmp", ".tif",
    ".tiff", ".mp4", ".mov", ".avi", ".mp3", ".wav", ".woff", ".woff2", ".ttf",
    ".eot", ".css", ".js", ".map", ".html", ".htm",
}
SENSITIVE_TOKENS = {
    "customer", "client", "user", "employee", "staff", "personal", "password",
    "passwd", "secret", "credential", "token", "apikey", "api_key", "private",
    "confidential", "backup", "dump", "finance", "billing", "invoice", "salary",
    "payroll", "ssn", "passport", "kyc", "pii", "gdpr", "database", "internal",
    "contract", "tax", "bank", "card", "auth", "admin", "prod", "production",
}
MISCONFIG_LABELS = {
    "listable": "anonymous ListBucket",
    "writable": "anonymous PutObject",
    "deletable": "anonymous DeleteObject",
    "public-policy": "bucket policy readable",
    "public-acl": "bucket ACL readable",
    "public-read": "anonymous object GET",
    "public-cors": "CORS configuration readable",
    "website": "static website hosting",
}
COMMON_PROBE_KEYS = s3_audit.PROBE_KEYS
LIST_MAX_KEYS = 25


def _is_benign_key(key):
    kl = key.lower().rstrip("/")
    if not kl or kl.endswith("/"):
        return True
    ext = os.path.splitext(kl)[1]
    if ext in BENIGN_EXT:
        return True
    base = os.path.basename(kl)
    if base in ("1", "2", "test", "readme.txt", "favicon.ico"):
        return True
    return False


def _score_listing(sample_keys):
    """Score object keys only; OPEN listing alone does not auto-flag review."""
    score, reasons = 0, []
    if not sample_keys:
        return score, reasons

    ext_hits, tok_hits = set(), set()
    benign = 0
    for k in sample_keys:
        if _is_benign_key(k):
            benign += 1
            continue
        kl = k.lower()
        ext = os.path.splitext(kl)[1]
        if ext in SENSITIVE_EXT:
            ext_hits.add(ext)
        for t in SENSITIVE_TOKENS:
            if t in kl:
                tok_hits.add(t)
    if ext_hits:
        score += 6 * len(ext_hits)
        reasons.append("files: " + ", ".join(sorted(ext_hits)))
    if tok_hits:
        score += 5 * len(tok_hits)
        reasons.append("keys: " + ", ".join(sorted(tok_hits)))
    if benign == len(sample_keys) and not (ext_hits or tok_hits):
        reasons.append("sample looks like public assets only")
    return score, reasons


def triage(bucket, status, sample_keys, misconfigs, exposed):
    """Return (score, reasons[], interesting). Interesting = manual review warranted."""
    score, reasons = 0, []
    content_score, content_reasons = _score_listing(sample_keys)
    score += content_score
    reasons.extend(content_reasons)

    if status == "WRITABLE":
        score += 100
        reasons.insert(0, "anonymous WRITE")
    for mc in misconfigs:
        if mc == "listable":
            score += 8
        elif mc == "writable":
            score += 100
        elif mc == "public-policy":
            score += 45
            reasons.append(MISCONFIG_LABELS[mc])
        elif mc == "public-acl":
            score += 40
            reasons.append(MISCONFIG_LABELS[mc])
        elif mc == "public-read":
            score += 25
            reasons.append(MISCONFIG_LABELS[mc])

    if exposed and status in ("OPEN", "WRITABLE"):
        name_l = bucket.lower()
        hit_name = sorted({t for t in SENSITIVE_TOKENS if t in name_l})
        if hit_name:
            score += min(16, 8 * len(hit_name))
            reasons.append("name: " + ", ".join(hit_name))

    interesting = (
        status == "WRITABLE"
        or "writable" in misconfigs
        or "deletable" in misconfigs
        or "public-policy" in misconfigs
        or "public-acl" in misconfigs
        or (content_score >= 12)
        or ("public-read" in misconfigs and content_score >= 6)
        or ("public-read" in misconfigs and status == "PRIVATE")
        or (status == "OPEN" and content_score >= 18)
    )
    return score, reasons, interesting


def _interesting_from_audit(audit_findings, base_interesting):
    if any(f.severity == "critical" for f in audit_findings):
        return True
    if any(f.severity == "high" for f in audit_findings):
        return True
    return base_interesting


def generate_exploit_command(check: str, detail: str, bucket: str, region: str = "") -> str:
    """Generate POC exploit command for a given finding."""
    check_lower = check.lower()
    detail_lower = detail.lower()
    bucket_url = f"{bucket}.s3.amazonaws.com"
    if region and region != "us-east-1":
        bucket_url = f"{bucket}.s3.{region}.amazonaws.com"

    # Anonymous ListBucket
    if "anonymous listbucket" in check_lower:
        return f"aws s3 ls s3://{bucket} --no-sign-request"

    # Anonymous PutObject/Write
    if "anonymous putobject" in check_lower or "put" in check_lower and "object" in check_lower:
        return f"echo 'pwned' > /tmp/test.txt && aws s3 cp /tmp/test.txt s3://{bucket}/ --no-sign-request"

    # Anonymous DeleteObject
    if "anonymous deleteobject" in check_lower or "delete" in check_lower and "object" in check_lower:
        return f"aws s3 rm s3://{bucket}/OBJECT_KEY --no-sign-request"

    # Public GetObject
    if "anonymous getobject" in check_lower or "public read" in detail_lower:
        return f"aws s3 cp s3://{bucket}/OBJECT_KEY /tmp/ --no-sign-request"

    # Public policy
    if "public policy" in detail_lower or "policy readable" in detail_lower:
        return f"curl https://{bucket_url}/?policy"

    # Public ACL
    if "public acl" in detail_lower or "acl readable" in detail_lower:
        return f"curl https://{bucket_url}/?acl"

    # Public CORS
    if "cors" in check_lower:
        return f"curl https://{bucket_url}/?cors"

    # Website hosting
    if "website" in check_lower:
        return f"curl http://{bucket}.s3-website-{region or 'us-east-1'}.amazonaws.com/"

    # Default fallback
    return f"aws s3 ls s3://{bucket} --no-sign-request"


# ----------------------------------------------------------------------------
# S3 probing
# ----------------------------------------------------------------------------

UA = "S3Threat/1.0 (authorized-assessment)"
TIMEOUT = 8.0
TIMEOUT_FAST = 2.0  # Faster timeout for --until-found / CIDR mode
VIEW_MAX_BYTES = 256 * 1024
DOWNLOAD_MAX_BYTES = 50 * 1024 * 1024
DOWNLOAD_DIR = "downloads"


@dataclass
class Result:
    bucket: str
    status: str = "NONE"
    region: str = ""
    url: str = ""
    object_urls: list = field(default_factory=list)
    sample_keys: list = field(default_factory=list)
    sample_sizes: dict = field(default_factory=dict)
    object_count: str = ""
    sample_bytes: int = 0
    misconfigs: list = field(default_factory=list)
    audit_findings: list = field(default_factory=list)
    severity: str = "none"
    interest: int = 0
    interesting: bool = False
    reasons: list = field(default_factory=list)
    note: str = ""


def _host(bucket, region, endpoint=None):
    if endpoint:
        # Support both path-style and vhost-style if endpoint is provided
        if "{bucket}" in endpoint:
            return endpoint.format(bucket=bucket, region=region or "us-east-1")
        return f"{endpoint.rstrip('/')}/{bucket}"
    if region and region != "us-east-1":
        return f"https://{bucket}.s3.{region}.amazonaws.com"
    return f"https://{bucket}.s3.amazonaws.com"


def _website_host(bucket, region="us-east-1", endpoint=None):
    if endpoint:
        return _host(bucket, region, endpoint)
    return f"http://{bucket}.s3-website-{region}.amazonaws.com"


def _object_url(bucket, region, key, endpoint=None):
    return f"{_host(bucket, region, endpoint)}/{urllib.parse.quote(key, safe='/')}"


def _request(url, method="GET", timeout=None):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    to = timeout if timeout is not None else TIMEOUT
    if url.lower().startswith("https://"):
        return urllib.request.urlopen(req, timeout=to, context=_SSL_CTX)
    return urllib.request.urlopen(req, timeout=to)


def _region_of(bucket, timeout=None, endpoint=None):
    if endpoint:
        return "us-east-1", 200
    url = f"https://s3.amazonaws.com/{bucket}/"
    try:
        resp = _request(url, method="HEAD", timeout=timeout)
        return resp.headers.get("x-amz-bucket-region", "us-east-1"), 200
    except urllib.error.HTTPError as e:
        return e.headers.get("x-amz-bucket-region", ""), e.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return "", None


def _parse_listing(xml_bytes, key_limit=LIST_MAX_KEYS):
    keys, sizes, truncated = [], {}, False
    key_count = None
    try:
        root = ET.fromstring(xml_bytes)
        ns = root.tag[: root.tag.find("}") + 1] if "}" in root.tag else ""
        truncated = (root.findtext(f"{ns}IsTruncated") or "").lower() == "true"
        kc = root.findtext(f"{ns}KeyCount")
        if kc and kc.isdigit():
            key_count = int(kc)
        contents = root.findall(f"{ns}Contents")
        if key_limit is not None:
            contents = contents[:key_limit]
        for c in contents:
            k = c.findtext(f"{ns}Key")
            if not k:
                continue
            keys.append(k)
            sz = c.findtext(f"{ns}Size")
            if sz and sz.isdigit():
                sizes[k] = int(sz)
    except ET.ParseError:
        pass
    return keys, sizes, key_count, truncated


def _object_count_label(key_count, listed, truncated):
    if truncated:
        base = key_count if key_count is not None else len(listed)
        return f">={base}"
    if key_count is not None:
        return str(key_count)
    return str(len(listed)) if listed else "0"


def _fetch_bucket_subresource(host, subresource, max_bytes=65536, timeout=None):
    """Fetch ?policy, ?acl, ?cors, ?website, etc. Returns text or None."""
    try:
        resp = _request(host + f"/?{subresource}", timeout=timeout)
        body = resp.read(max_bytes)
        if resp.status == 200 and body:
            return body.decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        pass
    return None


def _object_readable(host, key, timeout=None):
    url = host.rstrip("/") + "/" + urllib.parse.quote(key, safe="/")
    to = timeout if timeout is not None else TIMEOUT
    try:
        resp = _request(url, method="HEAD", timeout=timeout)
        return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        if e.code == 200:
            return True
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": UA, "Range": "bytes=0-0"},
            )
            if url.lower().startswith("https://"):
                resp = urllib.request.urlopen(req, timeout=to, context=_SSL_CTX)
            else:
                resp = urllib.request.urlopen(req, timeout=to)
            resp.read(1)
            return 200 <= resp.status < 300
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            return False
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _probe_public_reads(host, status, sample_keys, max_keys=20, timeout=None):
    keys = list(sample_keys[:8])
    if status != "OPEN":
        keys.extend(k for k in COMMON_PROBE_KEYS if k not in keys)
    readable = []
    for key in keys[:max_keys]:
        if _object_readable(host, key, timeout=timeout):
            readable.append(key)
    return readable


_WRITE_TEST_KEY = "security-test/s3-threat-write-test.txt"


def check_write(bucket, region, timeout=None, endpoint=None):
    url = _object_url(bucket, region, _WRITE_TEST_KEY, endpoint=endpoint)
    to = timeout if timeout is not None else TIMEOUT
    try:
        req = urllib.request.Request(
            url, method="PUT", data=b"authorized-test",
            headers={"User-Agent": UA, "Content-Type": "text/plain"},
        )
        resp = urllib.request.urlopen(req, timeout=to)
        return 200 <= resp.status < 300
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return False


def check_delete(bucket, region, timeout=None, endpoint=None):
    url = _object_url(bucket, region, _WRITE_TEST_KEY, endpoint=endpoint)
    to = timeout if timeout is not None else TIMEOUT
    try:
        req = urllib.request.Request(url, method="DELETE", headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=to)
        return 200 <= resp.status < 300
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return False


def _apply_security_audit(r, do_write=False, aws_profile=None, use_aws=False, timeout=None, endpoint=None):
    if not r.url or r.status in ("NONE", "ERROR"):
        return
    host = r.url.rstrip("/")
    mc = list(r.misconfigs)
    if r.status in ("OPEN", "WRITABLE"):
        if "listable" not in mc:
            mc.append("listable")

    if r.note.startswith("list endpoint returned 404") or (endpoint and not r.bucket):
        policy_text = acl_text = cors_text = website_xml = None
    else:
        policy_text = _fetch_bucket_subresource(host, "policy", timeout=timeout)
        acl_text = _fetch_bucket_subresource(host, "acl", timeout=timeout)
        cors_text = _fetch_bucket_subresource(host, "cors", timeout=timeout)
        website_xml = _fetch_bucket_subresource(host, "website", timeout=timeout)

    if policy_text and ("Statement" in policy_text or '"Effect"' in policy_text):
        mc.append("public-policy")
    if acl_text and ("AllUsers" in acl_text or "AuthenticatedUsers" in acl_text):
        mc.append("public-acl")
    if cors_text and "CORSRule" in cors_text:
        mc.append("public-cors")
    if website_xml and "IndexDocument" in website_xml:
        mc.append("website")

    readable = list(r.sample_keys) if "public-read" in mc else _probe_public_reads(
        host, r.status, r.sample_keys, timeout=timeout
    )
    if readable:
        mc.append("public-read")

    writable = r.status == "WRITABLE" or "writable" in mc
    deletable = False
    if do_write and writable:
        deletable = check_delete(r.bucket, r.region, timeout=timeout, endpoint=endpoint)
        if deletable:
            mc.append("deletable")

    anon_findings = s3_audit.run_anonymous_audit(
        status=r.status,
        sample_keys=r.sample_keys,
        readable_keys=readable,
        policy_text=policy_text,
        acl_text=acl_text,
        cors_text=cors_text,
        website_xml=website_xml,
        writable=writable,
        deletable=deletable,
    )
    aws_findings = []
    if use_aws:
        if _aws_available():
            aws_findings = s3_audit.run_aws_audit(r.bucket, profile=aws_profile)
        else:
            r.note = (r.note + "; " if r.note else "") + "aws cli not available"

    findings = s3_audit.merge_findings(anon_findings, aws_findings)
    r.audit_findings = [f.to_dict() for f in findings]
    r.severity = s3_audit.max_severity(findings)
    r.misconfigs = list(dict.fromkeys(mc))

    if readable:
        preview = ", ".join(readable[:3])
        if len(readable) > 3:
            preview += f" (+{len(readable) - 3})"
        r.note = (r.note + "; " if r.note else "") + f"readable: {preview}"


def _aws_available():
    try:
        subprocess.run(
            ["aws", "--version"], capture_output=True, timeout=5, check=False,
        )
        return True
    except (FileNotFoundError, OSError):
        return False


@dataclass
class Target:
    bucket: str
    region: str = ""
    key: str = ""
    endpoint: str = ""


_S3_VHOST = re.compile(
    r"^https?://(?P<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"\.s3(?:\.(?P<region>[a-z0-9\-]+))?\.amazonaws\.com(?P<path>/.*)?$",
    re.I,
)
_S3_PATH = re.compile(
    r"^https?://s3(?:\.(?P<region>[a-z0-9\-]+))?\.amazonaws\.com/"
    r"(?P<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])(?P<path>/.*)?$",
    re.I,
)


def parse_target(spec):
    """Parse bucket, bucket/key, or S3 HTTPS URL into a Target."""
    spec = spec.strip()
    if spec.startswith(("http://", "https://")):
        m = _S3_VHOST.match(spec) or _S3_PATH.match(spec)
        if not m:
            raise ValueError(f"not a recognized S3 URL: {spec}")
        key = ""
        if m.groupdict().get("path"):
            key = urllib.parse.unquote(m.group("path").lstrip("/"))
        return Target(
            bucket=m.group("bucket").lower(),
            region=(m.group("region") or "").lower(),
            key=key,
        )
    if "/" in spec:
        bucket, key = spec.split("/", 1)
        return Target(bucket=bucket.lower(), key=key)
    return Target(bucket=spec.lower())


def resolve_target(target):
    """Fill region on target; raises if bucket does not exist."""
    if target.region:
        return target
    region, code = _region_of(target.bucket)
    if code is None:
        raise RuntimeError(f"could not reach bucket {target.bucket}")
    if code == 404:
        raise RuntimeError(f"bucket not found: {target.bucket}")
    target.region = region or "us-east-1"
    return target


def _fetch_bytes(url, max_bytes=None):
    try:
        resp = _request(url)
        data = resp.read((max_bytes + 1) if max_bytes else None)
        if max_bytes and len(data) > max_bytes:
            return data[:max_bytes], True, resp.headers.get("Content-Type", "")
        return data, False, resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} for {url}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RuntimeError(str(e)) from e


def fetch_object(target, max_bytes=None):
    target = resolve_target(parse_target(target) if isinstance(target, str) else target)
    if not target.key:
        raise ValueError("object key required (bucket/key or S3 object URL)")
    url = _object_url(target.bucket, target.region, target.key)
    return _fetch_bytes(url, max_bytes=max_bytes)


def list_bucket_objects(bucket, region, max_objects=1000):
    host = _host(bucket, region)
    keys, sizes = [], {}
    marker = ""
    while len(keys) < max_objects:
        qs = f"?max-keys={min(1000, max_objects - len(keys))}"
        if marker:
            qs += "&marker=" + urllib.parse.quote(marker, safe="")
        resp = _request(host + "/" + qs)
        body = resp.read()
        if b"ListBucketResult" not in body:
            break
        batch_keys, batch_sizes, _, truncated = _parse_listing(body, key_limit=None)
        if not batch_keys:
            break
        for k in batch_keys:
            if k not in sizes:
                keys.append(k)
                sizes[k] = batch_sizes.get(k, 0)
        marker = batch_keys[-1]
        if not truncated:
            break
    return keys, sizes


def _is_textual(data, content_type=""):
    if content_type.startswith("text/"):
        return True
    if content_type in ("application/json", "application/xml", "application/javascript"):
        return True
    if not data:
        return True
    if b"\x00" in data[:8192]:
        return False
    try:
        data[:8192].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def view_target(spec):
    ui.print_banner(cli.VERSION)
    target = resolve_target(parse_target(spec))
    if target.key:
        data, truncated, ctype = fetch_object(target, max_bytes=VIEW_MAX_BYTES)
        url = _object_url(target.bucket, target.region, target.key)
        ui.print_view_object(
            target.bucket, target.key, url, data,
            truncated=truncated, content_type=ctype or "",
            is_textual=_is_textual(data, ctype),
        )
        return

    r = probe(target.bucket, do_write=False)
    ui.print_view_bucket_header(r)
    if r.reasons:
        ui.info("Triage: " + "; ".join(r.reasons))
    ui.rule("Audit")
    ui.print_audit_report(r, s3_audit.SEVERITY_ORDER)

    keys, sizes = [], {}
    if r.status in ("OPEN", "WRITABLE"):
        keys, sizes = list_bucket_objects(target.bucket, target.region)
    elif "public-read" in r.misconfigs:
        keys = list(r.sample_keys)

    ui.rule("Objects")
    ui.print_objects_table(keys, sizes)
    if keys:
        ui.info(f"Download: [bold]--download {target.bucket}/<key>[/]")


def download_target(spec, out_dir=DOWNLOAD_DIR, max_bytes=DOWNLOAD_MAX_BYTES):
    ui.print_banner(cli.VERSION)
    target = resolve_target(parse_target(spec))
    os.makedirs(out_dir, exist_ok=True)

    if target.key:
        data, truncated, _ = fetch_object(target, max_bytes=max_bytes + 1)
        if truncated or len(data) > max_bytes:
            raise RuntimeError(
                f"object exceeds --max-download ({ui.format_bytes(max_bytes)})"
            )
        dest = os.path.join(out_dir, target.bucket, target.key.replace("/", os.sep))
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
        ui.print_file_saved(dest, len(data))
        return

    r = probe(target.bucket, do_write=False)
    if r.status not in ("OPEN", "WRITABLE") and "public-read" not in r.misconfigs:
        raise RuntimeError(f"bucket not downloadable anonymously ({r.status})")

    keys, sizes = list_bucket_objects(target.bucket, target.region)
    if not keys:
        keys = r.sample_keys
        sizes = r.sample_sizes
    if not keys:
        raise RuntimeError("no objects found to download")

    ui.panel(
        "Download",
        f"Bucket [bold]{target.bucket}[/]  ·  [bold]{len(keys)}[/] object(s)",
        border="green",
    )
    saved, total = 0, 0
    for key in keys:
        sz = sizes.get(key, 0)
        if sz > max_bytes:
            ui.print_download_skip(key, f"{ui.format_bytes(sz)} > limit")
            continue
        try:
            data, _, _ = fetch_object(
                Target(target.bucket, target.region, key),
                max_bytes=max_bytes + 1,
            )
        except RuntimeError as e:
            ui.print_download_skip(key, str(e))
            continue
        dest = os.path.join(out_dir, target.bucket, key.replace("/", os.sep))
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(dest, "wb") as fh:
            fh.write(data)
        saved += 1
        total += len(data)
        ui.print_download_progress(key, len(data))

    ui.print_download_complete(
        saved, total, f"{out_dir}/{target.bucket}/",
    )


def probe(bucket, do_write=False, aws_profile=None, use_aws=False, timeout=None, endpoint=None):
    r = Result(bucket=bucket)
    region, code = _region_of(bucket, timeout=timeout, endpoint=endpoint)
    r.region = region

    if code is None:
        r.status, r.note = "ERROR", "request failed / timeout"
        return r
    if code == 404:
        host = _host(bucket, region, endpoint=endpoint)
        readable = []
        if "." in bucket and not endpoint:
            website_host = _website_host(bucket, endpoint=endpoint)
            readable = _probe_public_reads(
                website_host, "PRIVATE", [], max_keys=3
            )
            if readable:
                host = website_host
        if readable:
            r.status = "PRIVATE"
            r.note = "list endpoint returned 404; public object probe succeeded"
            r.url = host + "/"
            r.sample_keys = readable
            r.object_urls = [
                host.rstrip("/") + "/" + urllib.parse.quote(k, safe="/")
                for k in readable[:10]
            ]
            r.misconfigs = ["public-read"]
        else:
            r.status = "NONE"
            return r
    elif code in (403, 401):
        r.status = "PRIVATE"
        r.note = "exists, anonymous access denied"
        host = _host(bucket, region, endpoint=endpoint)
        r.url = host if bucket == "" else host + "/"
    else:
        host = _host(bucket, region, endpoint=endpoint)
        r.url = host if bucket == "" else host + "/"
        try:
            resp = _request(host + f"/?max-keys={LIST_MAX_KEYS}", timeout=timeout)
            body = resp.read()
            if resp.status == 200 and b"ListBucketResult" in body:
                keys, sizes, key_count, truncated = _parse_listing(body)
                r.status = "OPEN"
                r.sample_keys = keys
                r.sample_sizes = sizes
                r.sample_bytes = sum(sizes.values())
                r.object_urls = [_object_url(bucket, region, k, endpoint=endpoint) for k in keys[:10]]
                r.object_count = _object_count_label(key_count, keys, truncated)
                r.note = "anonymous listing enabled"
                r.misconfigs = ["listable"]
            else:
                r.status, r.note = "PRIVATE", f"resolved but not listable ({resp.status})"
        except urllib.error.HTTPError as e:
            r.status = "PRIVATE" if e.code in (403, 401) else "ERROR"
            r.note = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            r.status, r.note = "ERROR", str(e)

    if do_write and r.status == "OPEN":
        if check_write(bucket, region, timeout=timeout, endpoint=endpoint):
            r.status = "WRITABLE"
            r.misconfigs = list(dict.fromkeys(r.misconfigs + ["writable"]))
            r.note += "; anonymous PUT accepted"

    _apply_security_audit(r, do_write=do_write, aws_profile=aws_profile, use_aws=use_aws, timeout=timeout, endpoint=endpoint)
    exposed = bool(r.misconfigs) or r.status in ("OPEN", "WRITABLE")
    r.interest, r.reasons, base_interesting = triage(
        bucket, r.status, r.sample_keys, r.misconfigs, exposed,
    )
    findings_objs = [
        s3_audit.AuditFinding(**f) for f in r.audit_findings
    ]
    r.interesting = _interesting_from_audit(findings_objs, base_interesting)
    if r.severity in ("critical", "high"):
        r.interest = max(r.interest, 50 if r.severity == "critical" else 35)
    return r


# ----------------------------------------------------------------------------
# Presentation (Rich via ui.py)
# ----------------------------------------------------------------------------


def _show_in_table(r, show_all):
    if r.status == "ERROR":
        return False
    return show_all or r.status in ("OPEN", "WRITABLE", "PRIVATE") or r.interesting


class FindingsBoard:
    """Accumulate probe results for live stats, hit feed, and final table."""

    def __init__(self, show_all=False):
        self.show_all = show_all
        self.results = []
        self.live_hits = []
        self._live_buckets = set()

    def add(self, r):
        self.results.append(r)
        # Live panel should only show actual hits/interesting findings to keep
        # the display clean and synchronized with the stats line.
        if r.status not in ("OPEN", "WRITABLE", "PRIVATE") and not r.interesting:
            return
        if r.bucket in self._live_buckets:
            return
        self._live_buckets.add(r.bucket)
        self.live_hits.append(r)
        self.live_hits.sort(key=_findings_sort_key)

    def stats_line(self, probed, rate=None):
        hits = sum(1 for r in self.results
                   if r.status in ("OPEN", "WRITABLE", "PRIVATE"))
        interesting = sum(r.interesting for r in self.results)
        return ui.stats_line(probed, hits, interesting, rate=rate)


def _findings_sort_key(r):
    status_order = {"WRITABLE": 0, "OPEN": 1, "PRIVATE": 2, "ERROR": 3, "NONE": 4}
    return (not r.interesting, -r.interest, status_order.get(r.status, 9), r.bucket)


def _sorted_findings(results, show_all):
    visible = [r for r in results if _show_in_table(r, show_all)]
    return sorted(visible, key=_findings_sort_key)


def _has_actionable_result(results):
    return any(
        r.status in ("OPEN", "WRITABLE", "PRIVATE") or r.interesting
        for r in results
    )


def _should_stop_until_found(result):
    """Stop on the first existing bucket or any higher-signal exposure."""
    return result.status in ("OPEN", "WRITABLE", "PRIVATE") or result.interesting


def _scan_rate(start_time, completed):
    elapsed = max(time.monotonic() - start_time, 0.001)
    return completed / elapsed


def _build_candidate_names(
    seed_list,
    affixes,
    *,
    args,
    word_list,
    random_pool,
    seen,
    attempt: int = 0,
    seed_mode: str = "full",
):
    names = set()
    if seed_list:
        if seed_mode == "priority":
            names.update(_seed_source_tokens(seed_list))
        else:
            names.update(generate_names(seed_list, affixes, years=args.years))
    if args.random:
        if args.random_count < 1:
            raise ValueError("--random-count must be at least 1")
        if not random_pool:
            raise ValueError("random word list produced no valid candidates")
        base = args.random_seed if args.random_seed is not None else 0
        rng = random.Random(base + attempt * 10007)
        names.update(generate_random_names(
            word_list,
            args.random_count,
            rng=rng,
            exclude=seen,
            sources=random_pool,
        ))
    names.difference_update(seen)
    return sorted(names)


def _run_probes(names, args, board, seen, progress, task, live=None, stop_event=None):
    start_time = time.monotonic()
    todo = [n for n in names if n not in seen]
    for n in todo:
        seen.add(n)
    if not todo:
        return []
    batch_results = []
    
    # Persistent executor is handled in main() for until-found, 
    # but for compatibility we can still run a batch here if needed.
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(probe, n, args.check_write, args.aws_profile, args.aws): n
            for n in todo
        }
        for fut in cf.as_completed(futures):
            if stop_event and stop_event.is_set():
                break
            try:
                r = fut.result()
                batch_results.append(r)
                board.add(r)
                progress.advance(task, 1)
                if live is not None:
                    live.update(ui.live_scan_group(
                        board.stats_line(
                            len(board.results),
                            rate=_scan_rate(start_time, len(board.results)),
                        ),
                        progress,
                        board.live_hits,
                        MISCONFIG_LABELS,
                    ))
                if args.until_found and _should_stop_until_found(r):
                    if stop_event:
                        stop_event.set()
                    break
            except Exception:
                continue
    return batch_results


def _write_output(path, results):
    with open(path, "w") as fh:
        json.dump([asdict(r) for r in results
                   if r.status in ("OPEN", "WRITABLE", "PRIVATE") or r.interesting],
                  fh, indent=2)
    ui.success(f"Findings written to [bold cyan]{path}[/]")


def _cidr_to_ips(cidr):
    """Generator for IP addresses from CIDR notation without external dependencies."""
    try:
        if "/" not in cidr:
            yield cidr
            return
        base, bits = cidr.split("/")
        bits = int(bits)
        parts = [int(p) for p in base.split(".")]
        if len(parts) != 4 or not (0 <= bits <= 32): return
        
        start = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        net_start = start & mask
        num_hosts = 1 << (32 - bits)
        
        for i in range(num_hosts):
            curr = net_start + i
            yield f"{(curr >> 24) & 0xFF}.{(curr >> 16) & 0xFF}.{(curr >> 8) & 0xFF}.{curr & 0xFF}"
    except Exception:
        return


def main():
    import threading
    args, ap = cli.parse_args()
    if args is None:
        ui.print_cli_help(ap, prog=cli.PROG, version=cli.VERSION)
        return

    if args.audit:
        ui.print_banner(cli.VERSION)
        try:
            r = probe(args.audit, do_write=args.check_write,
                      aws_profile=args.aws_profile, use_aws=args.aws,
                      endpoint=args.endpoint)
            ui.print_audit_report(r, s3_audit.SEVERITY_ORDER)
            if r.url:
                ui.info(f"URL: [cyan underline]{r.url}[/]")
        except (ValueError, RuntimeError) as e:
            ui.die(str(e))
        return

    if args.view and args.download:
        ui.die("use only one of --view or --download")
    if args.view:
        try:
            view_target(args.view)
        except (ValueError, RuntimeError) as e:
            ui.die(str(e))
        return
    if args.download:
        try:
            download_target(args.download, out_dir=args.download_dir,
                            max_bytes=args.max_download)
        except (ValueError, RuntimeError) as e:
            ui.die(str(e))
        return

    # Discovery banner
    ui.print_banner(cli.VERSION)

    if not args.seeds and not args.random and not args.site_url and not args.bucket_file and not args.cidr and not args.endpoint:
        ui.die("provide seeds, --site-url, --random, --bucket-file, --cidr, or --endpoint")
    if args.until_found and not args.random:
        ui.die("--until-found requires --random")

    affixes = list(AFFIXES)
    if args.affixes:
        with open(args.affixes) as fh:
            affixes += [ln.strip() for ln in fh if ln.strip()]

    scraped_seeds = []
    if args.site_url:
        if args.depth < 0:
            ui.die("--depth must be >= 0")
        try:
            scrape_result = site_scrape.scrape_site(
                args.site_url,
                depth=args.depth,
                max_pages=args.max_pages,
                valid_fn=valid_bucket_name,
            )
        except ValueError as e:
            ui.die(str(e))
        scraped_seeds = scrape_result.seeds
        ui.print_scrape_report(
            args.site_url,
            depth=args.depth,
            max_pages=args.max_pages,
            pages_crawled=scrape_result.pages_crawled,
            tokens_seen=scrape_result.tokens_seen,
            seeds=scraped_seeds,
        )
        if args.save_seeds:
            with open(args.save_seeds, "w", encoding="utf-8") as fh:
                fh.write("\n".join(scraped_seeds) + "\n")
            ui.success(f"Seeds saved to [bold cyan]{args.save_seeds}[/]")
        if args.scrape_only:
            return

    osint_seeds = []
    if args.osint:
        ui.info(f"Querying OSINT APIs for domain: [bold cyan]{args.osint}[/]")
        osint_seeds, osint_errors = osint.discover_seeds(args.osint)
        ui.print_osint_report(args.osint, osint_seeds, osint_errors)
        if args.save_seeds:
            with open(args.save_seeds, "a", encoding="utf-8") as fh:
                fh.write("\n".join(osint_seeds) + "\n")
            ui.success(f"OSINT seeds appended to [bold cyan]{args.save_seeds}[/]")

    flat_buckets = []
    if args.bucket_file:
        try:
            with open(args.bucket_file, "r") as fh:
                flat_buckets = [ln.strip() for ln in fh if ln.strip()]
        except OSError as e:
            ui.die(f"failed to read bucket file: {e}")

    compat_endpoints = []
    if args.endpoint:
        compat_endpoints.append(args.endpoint)
    
    if args.cidr:
        ui.info(f"Expanding CIDR [bold cyan]{args.cidr}[/] for S3-compatible endpoints...")
        count = 0
        for ip in _cidr_to_ips(args.cidr):
            for port in [80, 443, 9000, 7480, 8080]:
                scheme = "https" if port == 443 else "http"
                compat_endpoints.append(f"{scheme}://{ip}:{port}")
                count += 1
                if count >= 25000: # 25k endpoints * ~30 bytes ~ 7.5MB
                    break
            if count >= 25000:
                ui.warn("Endpoint list capped at 25,000 for memory safety.")
                break

    board = FindingsBoard(show_all=args.show_all)
    seen = set()
    all_results = []
    word_list = load_word_dictionary(args.words_dict) if args.random else []

    seed_list = list(args.seeds) + scraped_seeds + osint_seeds
    random_sources = None
    if args.random:
        base = args.random_seed if args.random_seed is not None else 0
        random_sources = random_word_pool(
            word_list,
            random.Random(base),
            seed_sources=seed_list,
        )
    if args.until_found:
        mode = (
            f"[bold]repeat until hit[/]  random [bold]{args.random_count}[/] "
            f"workers [bold]{args.threads}[/]"
        )
        if seed_list:
            mode += f"  seeds:{len(seed_list)}"
    else:
        names = _build_candidate_names(
            seed_list,
            affixes,
            args=args,
            word_list=word_list,
            random_pool=random_sources,
            seen=seen,
        )
        if flat_buckets:
            for fb in flat_buckets:
                if fb not in seen:
                    names.append(fb)
                    seen.add(fb)

        mode = f"[bold]{len(names)}[/] candidates"
        if seed_list:
            mode += f"  seeds:{len(seed_list)}"
        if flat_buckets:
            mode += f"  flat:{len(flat_buckets)}"
        if compat_endpoints:
            mode += f"  endpoints:{len(compat_endpoints)}"
        if args.random:
            mode += f"  random:{args.random_count}"

    ui.print_run_config(
        mode,
        threads=args.threads,
        write_probe=args.check_write,
        aws=args.aws,
    )
    ui.rule("Scan")

    progress = ui.make_progress()
    stop_event = threading.Event()
    scan_start = time.monotonic()

    with Live(
        ui.live_scan_group(
            board.stats_line(0, rate=0.0), progress, board.live_hits, MISCONFIG_LABELS,
        ),
        console=ui.console,
        refresh_per_second=8,
        transient=False,
    ) as live:
        if args.until_found:
            all_results = []
            attempt = 0
            task = progress.add_task("probing", total=0)
            # Shared executor for all passes
            with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
                while not stop_event.is_set():
                    attempt += 1
                    names = _build_candidate_names(
                        seed_list,
                        affixes,
                        args=args,
                        word_list=word_list,
                        random_pool=random_sources,
                        seen=seen,
                        attempt=attempt,
                        seed_mode="priority",
                    )
                    if not names:
                        progress.update(task, description=f"pass {attempt}: no new names")
                        if attempt > 20: # Sanity break
                            break
                        continue
                    for n in names:
                        seen.add(n)
                    
                    progress.update(
                        task,
                        total=progress.tasks[task].total + len(names),
                        description=f"pass {attempt}",
                    )
                    
                    seen_batch = set()
                    futures = {
                        ex.submit(probe, n, args.check_write, args.aws_profile, args.aws, TIMEOUT_FAST): n
                        for n in names
                    }
                    for fut in cf.as_completed(futures):
                        if stop_event.is_set():
                            break
                        try:
                            r = fut.result()
                            if r.bucket in seen_batch: continue # safety
                            seen_batch.add(r.bucket)
                            
                            all_results.append(r)
                            board.add(r)
                            progress.advance(task, 1)
                            
                            # Always update UI so stats (probed, speed) stay synced
                            live.update(ui.live_scan_group(
                                board.stats_line(
                                    len(board.results),
                                    rate=_scan_rate(scan_start, len(board.results)),
                                ),
                                progress,
                                board.live_hits,
                                MISCONFIG_LABELS,
                            ))

                            if _should_stop_until_found(r):
                                stop_event.set()
                                # DECISIVE: cancel everything else
                                for f in futures:
                                    f.cancel()
                                break
                        except Exception:
                            continue
                    
                    if stop_event.is_set():
                        break
        else:
            # For custom endpoints, if no seeds are provided, we should at least probe
            # the root to verify the service.
            probe_targets = list(names)
            if not probe_targets and compat_endpoints:
                probe_targets = [""]

            total_tasks = 0
            if names: # Only AWS scan if we have names
                total_tasks += len(names)
            if compat_endpoints:
                total_tasks += len(probe_targets) * len(compat_endpoints)
            
            task = progress.add_task("probing", total=total_tasks)
            
            # 1. Standard AWS scan (only if names exist)
            all_results = []
            if names:
                all_results = _run_probes(
                    names, args, board, set(), progress, task, live=live, stop_event=stop_event
                )
            
            # 2. S3-compatible endpoints — one shared pool for all (endpoint, bucket) pairs
            if compat_endpoints and not stop_event.is_set():
                scan_start = time.monotonic()
                board.results = []
                endpoint_results = []
                progress.update(task, description="probing endpoints")
                with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
                    futures = {
                        ex.submit(
                            probe, n, args.check_write, args.aws_profile, args.aws,
                            timeout=TIMEOUT_FAST, endpoint=endpoint,
                        ): (n, endpoint)
                        for endpoint in compat_endpoints
                        for n in probe_targets
                    }
                    for fut in cf.as_completed(futures):
                        if stop_event.is_set():
                            break
                        try:
                            r = fut.result()
                            endpoint_results.append(r)
                            board.add(r)
                            progress.advance(task, 1)
                            live.update(ui.live_scan_group(
                                board.stats_line(
                                    len(board.results),
                                    rate=_scan_rate(scan_start, len(board.results)),
                                ),
                                progress,
                                board.live_hits,
                                MISCONFIG_LABELS,
                            ))
                        except Exception:
                            progress.advance(task, 1)
                            continue
                all_results.extend(endpoint_results)
    ui.print_findings_stack(
        _sorted_findings(all_results, args.show_all),
        MISCONFIG_LABELS,
    )
    ui.print_summary(all_results, len(all_results))
    if args.output:
        _write_output(args.output, all_results)


if __name__ == "__main__":
    main()
