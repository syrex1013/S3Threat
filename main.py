#!/usr/bin/env python3
"""
S3Threat - target-scoped S3 bucket discovery for authorized assessments.

Generates candidate bucket names from target seeds, anonymously probes the S3
API, classifies each candidate, triages findings by likely sensitivity, and
emits directly-accessible URLs.

    WRITABLE anonymous PUT accepted              -> CRITICAL
    OPEN     anonymous ListBucket succeeds       -> listable (not auto-flagged)
    PRIVATE  bucket exists, access denied (403)  -> confirms existence
    NONE     bucket does not exist (404)

    Also probes: public bucket policy/ACL, anonymous object GET.
    INTERESTING flag only when content, writes, or serious misconfigs warrant review.

Built for scoped engagements: seed it with YOUR target's keywords.

Requires: rich   ->   pip install rich

Usage:
    python3 main.py acme acme-corp acmecorp -o findings.json
    python3 main.py acme --years --check-write -t 80
    python3 main.py --site-url https://www.example.com --depth 3
    python3 main.py --random --until-interesting --batch-size 400
    python3 main.py --view acme-prod-backup
    python3 main.py --download https://bucket.s3.amazonaws.com/key
"""

import argparse
import concurrent.futures as cf
import json
import os
import random
import re
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
import scrape as site_scrape

try:
    from rich.live import Live
except ImportError:
    sys.exit("[!] missing dependency: pip install rich")

import ui

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
    seeds = [s.strip().lower() for s in seeds if s.strip()]
    affix_list = list(dict.fromkeys(affixes))
    extra = YEARS if years else []
    out = set()
    for seed in seeds:
        out.add(seed)
        for affix, sep in product(affix_list + extra, SEPARATORS):
            out.add(f"{seed}{sep}{affix}")
            out.add(f"{affix}{sep}{seed}")
        for a1, a2 in product(["prod", "dev", "stage", "test"],
                              ["backup", "data", "logs", "db", "assets"]):
            out.add(f"{seed}-{a1}-{a2}")
            out.add(f"{seed}.{a1}.{a2}")
    return sorted(n for n in out if valid_bucket_name(n))


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


def random_word_pool(word_list, rng, max_words=6000):
    """Short, plausible bucket stems — not obscure multi-word dictionary combos."""
    short = [w for w in word_list if 4 <= len(w) <= 8 and valid_bucket_name(w)]
    if len(short) > max_words:
        short = rng.sample(short, max_words)
    stems = [w for w in _COMMON_STEMS if valid_bucket_name(w)]
    extra = [w for w in _RANDOM_AFFIXES if valid_bucket_name(w)]
    return list(dict.fromkeys(stems + short + extra))


def generate_random_names(word_list, count, rng=None, exclude=None):
    """Random names biased toward real-world bucket patterns (short words + affixes)."""
    rng = rng or random.SystemRandom()
    pool = random_word_pool(word_list, rng)
    if not pool:
        return []
    exclude = exclude or set()
    affixes = _RANDOM_AFFIXES
    years = _RANDOM_YEARS

    out = set()
    attempts = 0
    limit = max(count * 40, 2000)
    while len(out) < count and attempts < limit:
        attempts += 1
        roll = rng.random()
        if roll < 0.50:
            name = rng.choice(pool)
            if rng.random() < 0.15:
                name = f"{name}{rng.randint(1, 9999)}"
        elif roll < 0.78:
            w, a = rng.choice(pool), rng.choice(affixes)
            sep = rng.choice(["-", "", "."])
            name = f"{w}{sep}{a}" if rng.random() < 0.55 else f"{a}{sep}{w}"
        elif roll < 0.84:
            name = f"{rng.choice(pool)}-{rng.choice(years)}"
        elif roll < 0.94:
            w1, w2 = rng.choice(pool), rng.choice(pool)
            if w1 == w2:
                continue
            sep = rng.choice(["-", ""])
            name = f"{w1}{sep}{w2}"
        else:
            w = rng.choice(pool)
            a1, a2 = rng.sample(affixes, 2)
            name = f"{w}-{a1}-{a2}"
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


# ----------------------------------------------------------------------------
# S3 probing
# ----------------------------------------------------------------------------

UA = "S3Threat/1.0 (authorized-assessment)"
TIMEOUT = 10
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


def _host(bucket, region):
    if region and region != "us-east-1":
        return f"https://{bucket}.s3.{region}.amazonaws.com"
    return f"https://{bucket}.s3.amazonaws.com"


def _object_url(bucket, region, key):
    return f"{_host(bucket, region)}/{urllib.parse.quote(key, safe='/')}"


def _request(url, method="GET"):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    return urllib.request.urlopen(req, timeout=TIMEOUT)


def _region_of(bucket):
    """Detect bucket region. Uses GET — S3 often returns 404 on HEAD for real buckets."""
    urls = (
        f"https://{bucket}.s3.amazonaws.com/?max-keys=1",
        f"https://s3.amazonaws.com/{bucket}/?max-keys=1",
    )
    for url in urls:
        try:
            resp = _request(url)
            resp.read(512)
            reg = resp.headers.get("x-amz-bucket-region", "us-east-1")
            return reg, resp.status
        except urllib.error.HTTPError as e:
            reg = e.headers.get("x-amz-bucket-region", "")
            if e.code == 404:
                continue
            if e.code in (403, 401):
                return reg or "us-east-1", e.code
            if e.code == 400 and reg:
                return reg, 403
            return reg, e.code
        except (urllib.error.URLError, TimeoutError, OSError):
            return "", None
    return "", 404


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


def _fetch_bucket_subresource(host, subresource, max_bytes=65536):
    """Fetch ?policy, ?acl, ?cors, ?website, etc. Returns text or None."""
    try:
        resp = _request(host + f"/?{subresource}")
        body = resp.read(max_bytes)
        if resp.status == 200 and body:
            return body.decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        pass
    return None


def _object_readable(host, key):
    url = host.rstrip("/") + "/" + urllib.parse.quote(key, safe="/")
    try:
        resp = _request(url, method="HEAD")
        return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        return e.code == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _probe_public_reads(host, status, sample_keys):
    keys = list(sample_keys[:8])
    if status != "OPEN":
        keys.extend(k for k in COMMON_PROBE_KEYS if k not in keys)
    readable = []
    for key in keys[:20]:
        if _object_readable(host, key):
            readable.append(key)
    return readable


_WRITE_TEST_KEY = "security-test/s3-threat-write-test.txt"


def check_write(bucket, region):
    url = _object_url(bucket, region, _WRITE_TEST_KEY)
    try:
        req = urllib.request.Request(
            url, method="PUT", data=b"authorized-test",
            headers={"User-Agent": UA, "Content-Type": "text/plain"},
        )
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        return 200 <= resp.status < 300
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return False


def check_delete(bucket, region):
    url = _object_url(bucket, region, _WRITE_TEST_KEY)
    try:
        req = urllib.request.Request(url, method="DELETE", headers={"User-Agent": UA})
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        return 200 <= resp.status < 300
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return False


def _apply_security_audit(r, do_write=False, aws_profile=None, use_aws=False):
    if not r.url or r.status in ("NONE", "ERROR"):
        return
    host = r.url.rstrip("/")
    mc = list(r.misconfigs)
    if r.status in ("OPEN", "WRITABLE"):
        if "listable" not in mc:
            mc.append("listable")

    policy_text = _fetch_bucket_subresource(host, "policy")
    acl_text = _fetch_bucket_subresource(host, "acl")
    cors_text = _fetch_bucket_subresource(host, "cors")
    website_xml = _fetch_bucket_subresource(host, "website")

    if policy_text and ("Statement" in policy_text or '"Effect"' in policy_text):
        mc.append("public-policy")
    if acl_text and ("AllUsers" in acl_text or "AuthenticatedUsers" in acl_text):
        mc.append("public-acl")
    if cors_text and "CORSRule" in cors_text:
        mc.append("public-cors")
    if website_xml and "IndexDocument" in website_xml:
        mc.append("website")

    readable = _probe_public_reads(host, r.status, r.sample_keys)
    if readable:
        mc.append("public-read")

    writable = r.status == "WRITABLE" or "writable" in mc
    deletable = False
    if do_write and writable:
        deletable = check_delete(r.bucket, r.region)
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
    ui.print_banner()
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
    ui.print_banner()
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


def probe(bucket, do_write=False, aws_profile=None, use_aws=False):
    r = Result(bucket=bucket)
    region, code = _region_of(bucket)
    r.region = region

    if code is None:
        r.status, r.note = "ERROR", "request failed / timeout"
        return r
    if code == 404:
        r.status = "NONE"
        return r
    if code in (403, 401):
        r.status = "PRIVATE"
        r.note = "exists, anonymous access denied"
        r.url = _host(bucket, region) + "/"
    else:
        host = _host(bucket, region)
        r.url = host + "/"
        try:
            resp = _request(host + f"/?max-keys={LIST_MAX_KEYS}")
            body = resp.read()
            if resp.status == 200 and b"ListBucketResult" in body:
                keys, sizes, key_count, truncated = _parse_listing(body)
                r.status = "OPEN"
                r.sample_keys = keys
                r.sample_sizes = sizes
                r.sample_bytes = sum(sizes.values())
                r.object_urls = [_object_url(bucket, region, k) for k in keys[:10]]
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
        if check_write(bucket, region):
            r.status = "WRITABLE"
            r.misconfigs = list(dict.fromkeys(r.misconfigs + ["writable"]))
            r.note += "; anonymous PUT accepted"

    _apply_security_audit(r, do_write=do_write, aws_profile=aws_profile, use_aws=use_aws)
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
    return show_all or r.status in ("OPEN", "WRITABLE", "PRIVATE") or r.interesting


class FindingsBoard:
    """Live findings table — append rows across batches without redrawing from scratch."""

    def __init__(self, show_all=False):
        self.show_all = show_all
        self.results = []
        self.table = ui.new_findings_table()
        self._rows_by_bucket = {}

    def add(self, r):
        self.results.append(r)
        if not _show_in_table(r, self.show_all):
            return
        if r.bucket in self._rows_by_bucket:
            return
        self._rows_by_bucket[r.bucket] = len(self.table.rows)
        self.table.add_row(*ui.result_row_cells(r, MISCONFIG_LABELS))

    def stats_line(self, probed, batch=0):
        hits = sum(1 for r in self.results
                   if r.status in ("OPEN", "WRITABLE", "PRIVATE"))
        interesting = sum(r.interesting for r in self.results)
        return ui.stats_line(probed, hits, interesting, batch)


def summary_table(results, show_all):
    board = FindingsBoard(show_all=show_all)
    for r in sorted(results, key=lambda x: (-x.interest, x.bucket)):
        board.add(r)
    return board.table


def _run_probes(names, args, board, seen, progress, task, live=None):
    todo = [n for n in names if n not in seen]
    for n in todo:
        seen.add(n)
    if not todo:
        return []
    batch_results = []
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(probe, n, args.check_write, args.aws_profile, args.aws): n
            for n in todo
        }
        for fut in cf.as_completed(futures):
            r = fut.result()
            batch_results.append(r)
            board.add(r)
            progress.advance(task, 1)
            if live is not None:
                live.update(ui.live_group(
                    board.stats_line(len(seen)), progress, board.table,
                ))
    return batch_results


def _write_output(path, results):
    with open(path, "w") as fh:
        json.dump([asdict(r) for r in results
                   if r.status in ("OPEN", "WRITABLE", "PRIVATE") or r.interesting],
                  fh, indent=2)
    ui.success(f"Findings written to [bold cyan]{path}[/]")


def main():
    ap = argparse.ArgumentParser(description="Target-scoped S3 bucket discovery.")
    ap.add_argument("seeds", nargs="*",
                    help="target keywords (brand, domain stem, products); optional with --random")
    ap.add_argument("--affixes", help="file with extra affix words, one per line")
    ap.add_argument("--years", action="store_true", help="also permute with recent years")
    ap.add_argument("--random", action="store_true",
                    help="add random bucket names from an English word dictionary")
    ap.add_argument("--random-count", type=int, default=5000, metavar="N",
                    help="how many random names to generate (default 5000)")
    ap.add_argument("--random-seed", type=int, default=None,
                    help="RNG seed for reproducible --random name sets")
    ap.add_argument("--until-interesting", action="store_true",
                    help="with --random: keep batching until an interesting bucket is found")
    ap.add_argument("--batch-size", type=int, default=400, metavar="N",
                    help="names per batch for --until-interesting (default 400)")
    ap.add_argument("--words-dict", metavar="FILE",
                    help="word list file (one word per line); default: dict/english.txt")
    ap.add_argument("--site-url", metavar="URL",
                    help="crawl company site and use extracted terms as bucket seeds")
    ap.add_argument("--depth", type=int, default=3, metavar="N",
                    help="max link depth for --site-url crawl (default 3)")
    ap.add_argument("--max-pages", type=int, default=80, metavar="N",
                    help="max pages to fetch when scraping (default 80)")
    ap.add_argument("--scrape-only", action="store_true",
                    help="only crawl --site-url and print seeds; do not probe S3")
    ap.add_argument("--save-seeds", metavar="FILE",
                    help="write scraped seeds to a file (one per line)")
    ap.add_argument("-t", "--threads", type=int, default=60, help="concurrent workers (default 60)")
    ap.add_argument("--check-write", action="store_true",
                    help="non-destructive write probe on OPEN buckets (authorized only)")
    ap.add_argument("-o", "--output", help="write full JSON findings to this path")
    ap.add_argument("--show-all", action="store_true", help="include PRIVATE/NONE in final table")
    ap.add_argument("--view", metavar="TARGET",
                    help="inspect bucket or object (bucket, bucket/key, or S3 URL)")
    ap.add_argument("--download", metavar="TARGET",
                    help="download object or listable bucket (bucket, bucket/key, or S3 URL)")
    ap.add_argument("--download-dir", metavar="DIR", default=DOWNLOAD_DIR,
                    help=f"output directory for --download (default: {DOWNLOAD_DIR})")
    ap.add_argument("--max-download", metavar="BYTES", type=int, default=DOWNLOAD_MAX_BYTES,
                    help="per-file size limit for --download")
    ap.add_argument("--audit", metavar="BUCKET",
                    help="run full security checklist on one bucket and print report")
    ap.add_argument("--aws", action="store_true",
                    help="run authenticated AWS CLI checks (§1, §7–14; requires credentials)")
    ap.add_argument("--aws-profile", metavar="PROFILE",
                    help="AWS CLI profile for --aws / --audit")
    args = ap.parse_args()

    if args.audit:
        ui.print_banner()
        try:
            r = probe(args.audit, do_write=args.check_write,
                      aws_profile=args.aws_profile, use_aws=args.aws)
            ui.print_audit_report(r, s3_audit.SEVERITY_ORDER)
            if r.url:
                ui.info(f"URL: [cyan underline]{r.url}[/]")
        except (ValueError, RuntimeError) as e:
            ui.die(str(e))
        return

    if args.view and args.download:
        ap.error("use only one of --view or --download")
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

    if args.until_interesting and not args.random:
        ap.error("--until-interesting requires --random")
    if not args.seeds and not args.random and not args.site_url:
        ap.error("provide seeds, --site-url, or --random")

    affixes = list(AFFIXES)
    if args.affixes:
        with open(args.affixes) as fh:
            affixes += [ln.strip() for ln in fh if ln.strip()]

    scraped_seeds = []
    if args.site_url:
        if args.depth < 0:
            ap.error("--depth must be >= 0")
        ui.print_banner()
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

    board = FindingsBoard(show_all=args.show_all)
    seen = set()
    all_results = []
    word_list = load_word_dictionary(args.words_dict) if args.random else []
    dict_size = len(word_list) if args.random else 0

    seed_list = list(args.seeds) + scraped_seeds
    if args.until_interesting:
        mode = (
            f"[bold]until interesting[/]  batch [bold]{args.batch_size}[/]  "
            f"dict [bold]{dict_size}[/] words  workers [bold]{args.threads}[/]"
        )
        if seed_list:
            mode += f"  seeds:{len(seed_list)}"
    else:
        names = set()
        if seed_list:
            names.update(generate_names(seed_list, affixes, years=args.years))
        if args.random:
            if args.random_count < 1:
                ap.error("--random-count must be at least 1")
            rng = random.Random(args.random_seed)
            names.update(generate_random_names(
                word_list, args.random_count, rng=rng, exclude=seen,
            ))
        names = sorted(names)
        mode = f"[bold]{len(names)}[/] candidates"
        if seed_list:
            mode += f"  seeds:{len(seed_list)}"
            if scraped_seeds:
                mode += f" (scraped:{len(scraped_seeds)})"
        if args.random:
            mode += f"  random:{args.random_count}"
    ui.print_banner()
    ui.print_run_config(
        mode,
        threads=args.threads,
        write_probe=args.check_write,
        aws=args.aws,
    )
    ui.rule("Scan")

    progress = ui.make_progress()

    with Live(
        ui.live_group(board.stats_line(0), progress, board.table),
        console=ui.console,
        refresh_per_second=6,
    ) as live:
        if args.until_interesting:
            found_interesting = False
            if seed_list:
                pre_names = generate_names(seed_list, affixes, years=args.years)
                task = progress.add_task("seed targets", total=len(pre_names))
                batch_results = _run_probes(
                    pre_names, args, board, seen, progress, task, live=live,
                )
                all_results.extend(batch_results)
                found_interesting = any(r.interesting for r in batch_results)
            if not found_interesting:
                batch_num = 0
                task = progress.add_task("batch 1", total=args.batch_size)
                while True:
                    batch_num += 1
                    base = (args.random_seed if args.random_seed is not None else 0)
                    rng = random.Random(base + batch_num * 10007)
                    raw = generate_random_names(word_list, args.batch_size * 4, rng=rng)
                    batch_names = [n for n in raw if n not in seen][:args.batch_size]
                    if not batch_names:
                        progress.update(
                            task,
                            description=f"[yellow]batch {batch_num}: no new names[/]",
                        )
                        continue
                    progress.update(
                        task, total=len(batch_names), completed=0,
                        description=f"batch {batch_num}",
                    )
                    batch_results = _run_probes(
                        batch_names, args, board, seen, progress, task, live=live,
                    )
                    all_results.extend(batch_results)
                    if any(r.interesting for r in batch_results):
                        found_interesting = True
                        break
            if found_interesting:
                ui.print_found_interesting()
        else:
            task = progress.add_task("probing", total=len(names))
            all_results = _run_probes(
                names, args, board, seen, progress, task, live=live,
            )

    ui.rule("Results")
    ui.console.print(summary_table(all_results, args.show_all))
    ui.print_summary(all_results, len(seen))
    if args.output:
        _write_output(args.output, all_results)


if __name__ == "__main__":
    main()
