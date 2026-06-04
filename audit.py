"""
S3 bucket security audit checks mapped to the S3Threat assessment checklist.

Anonymous checks use unsigned HTTP (equivalent to --no-sign-request).
Authenticated checks require the AWS CLI and appropriate credentials.
"""

from __future__ import annotations

import json
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field

# ---------------------------------------------------------------------------
# Severity (section 18)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class AuditFinding:
    section: str
    check: str
    severity: str
    detail: str
    evidence: str = ""

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# Sensitive object probe paths (checklist §15)
# ---------------------------------------------------------------------------

PROBE_KEYS = [
    "index.html", "robots.txt", "error.html",
    ".env", ".env.production", ".env.local", "config.json", "config.yml",
    "credentials.json", "secrets.json", "settings.py", "application.yml",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "database.sql",
    "db.sql", "data.sql", "prod.sql", "production.sql",
    "id_rsa", "id_dsa", ".pem", "server.key", "private.key", "cert.pem",
    ".kube/config", "wp-config.php", ".git/HEAD", ".git/config",
    "access.log", "debug.log", "app.log", "logs/access.log",
    "terraform.tfstate", "terraform.tfstate.backup",
    "aws_credentials", ".aws/credentials",
    "docker-compose.yml", "docker-compose.yaml",
    "package.json", "composer.json",
]

DANGEROUS_POLICY_ACTIONS = {
    "s3:*", "s3:putobject", "s3:deleteobject", "s3:putobjectacl",
    "s3:putbucketpolicy", "s3:putbucketacl", "s3:getobject", "s3:listbucket",
    "s3:listbucketversions",
}

PUBLIC_PRINCIPALS = ('"*"', '"aws":"*"', '"aws": "*"', "principal.*\\*")


# ---------------------------------------------------------------------------
# Policy & ACL analysis
# ---------------------------------------------------------------------------

def _policy_statements(policy_obj):
    stmts = policy_obj.get("Statement", [])
    if isinstance(stmts, dict):
        return [stmts]
    return stmts if isinstance(stmts, list) else []


def analyze_bucket_policy(text: str) -> list[AuditFinding]:
    findings = []
    try:
        policy = json.loads(text)
    except json.JSONDecodeError:
        return findings

    for stmt in _policy_statements(policy):
        effect = (stmt.get("Effect") or "").lower()
        if effect != "allow":
            continue
        principal = stmt.get("Principal")
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        actions_l = {a.lower() for a in actions}
        cond = stmt.get("Condition") or {}

        public = False
        if principal == "*":
            public = True
        elif isinstance(principal, dict):
            aws_p = principal.get("AWS")
            if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
                public = True

        if not public:
            continue

        if "s3:*" in actions_l or any(a.endswith("s3:*") for a in actions_l):
            findings.append(AuditFinding(
                section="5. Bucket policy risks",
                check="Public Allow with s3:*",
                severity="critical",
                detail='Policy allows Principal "*" with s3:*',
                evidence=str(stmt)[:500],
            ))
        if actions_l & {"s3:putobject", "s3:deleteobject", "s3:putobjectacl"}:
            findings.append(AuditFinding(
                section="5. Bucket policy risks",
                check="Public write actions in policy",
                severity="critical",
                detail=f"Principal * allowed: {', '.join(sorted(actions_l))}",
                evidence=str(stmt)[:500],
            ))
        if "s3:listbucket" in actions_l:
            findings.append(AuditFinding(
                section="2. Anonymous permissions",
                check="Policy allows public ListBucket",
                severity="high",
                detail="Principal * has s3:ListBucket",
            ))
        if "s3:getobject" in actions_l:
            findings.append(AuditFinding(
                section="3. Object-level exposure",
                check="Policy allows public GetObject",
                severity="high",
                detail="Principal * has s3:GetObject",
            ))

        referer = json.dumps(cond).lower()
        if "referer" in referer and "*" in referer:
            findings.append(AuditFinding(
                section="5. Bucket policy risks",
                check="Weak referrer-only condition",
                severity="high",
                detail="Access restricted only by aws:Referer — bypassable",
                evidence=referer[:300],
            ))

    return findings


def analyze_bucket_acl(xml_text: str) -> list[AuditFinding]:
    findings = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings

    ns = root.tag[: root.tag.find("}") + 1] if "}" in root.tag else ""
    risky = {
        "READ": ("high", "AllUsers/AuthenticatedUsers READ"),
        "WRITE": ("critical", "AllUsers/AuthenticatedUsers WRITE"),
        "FULL_CONTROL": ("critical", "AllUsers/AuthenticatedUsers FULL_CONTROL"),
    }
    for grant in root.findall(f".//{ns}Grant"):
        grantee = grant.find(f"{ns}Grantee")
        if grantee is None:
            continue
        uri = grantee.findtext(f"{ns}URI") or ""
        if "AllUsers" not in uri and "AuthenticatedUsers" not in uri:
            continue
        who = "AllUsers" if "AllUsers" in uri else "AuthenticatedUsers"
        perm = grant.findtext(f"{ns}Permission") or ""
        if perm in risky:
            sev, label = risky[perm]
            findings.append(AuditFinding(
                section="6. ACL risks",
                check=f"ACL grant: {who} {perm}",
                severity=sev,
                detail=label,
            ))
    return findings


def analyze_cors_xml(xml_text: str) -> list[AuditFinding]:
    findings = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings
    ns = root.tag[: root.tag.find("}") + 1] if "}" in root.tag else ""
    for rule in root.findall(f"{ns}CORSRule"):
        origins = [o.text for o in rule.findall(f"{ns}AllowedOrigin") if o.text]
        methods = [m.text for m in rule.findall(f"{ns}AllowedMethod") if m.text]
        if "*" in origins and set(methods) & {"PUT", "POST", "DELETE"}:
            findings.append(AuditFinding(
                section="11. CORS policy",
                check="Wildcard origin with write methods",
                severity="high",
                detail=f"AllowedOrigins * with {', '.join(methods)}",
            ))
    return findings


def max_severity(findings: list[AuditFinding]) -> str:
    best = "none"
    for f in findings:
        if SEVERITY_ORDER.index(f.severity) < SEVERITY_ORDER.index(
            best if best in SEVERITY_ORDER else "info"
        ):
            best = f.severity
    return best if best in SEVERITY_ORDER else "none"


# ---------------------------------------------------------------------------
# AWS CLI checks (checklist §1, §7–14, §17) — requires credentials
# ---------------------------------------------------------------------------

def _aws_run(args: list[str], profile: str | None = None) -> tuple[dict | None, str]:
    cmd = ["aws", *args, "--output", "json"]
    if profile:
        cmd.extend(["--profile", profile])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return None, str(e)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout or "aws error").strip()[:300]
    if not proc.stdout.strip():
        return {}, ""
    return json.loads(proc.stdout), ""


def run_aws_audit(bucket: str, profile: str | None = None) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    b = ["--bucket", bucket]

    data, err = _aws_run(["s3api", "get-public-access-block", *b], profile)
    if err and "NoSuchPublicAccessBlockConfiguration" in err:
        findings.append(AuditFinding(
            section="1. Public exposure",
            check="No Public Access Block configuration",
            severity="high",
            detail="Missing PublicAccessBlockConfiguration on bucket",
        ))
    elif data:
        cfg = data.get("PublicAccessBlockConfiguration", data)
        for key, want in (
            ("BlockPublicAcls", True),
            ("IgnorePublicAcls", True),
            ("BlockPublicPolicy", True),
            ("RestrictPublicBuckets", True),
        ):
            if cfg.get(key) is not True:
                findings.append(AuditFinding(
                    section="1. Public exposure",
                    check=f"PublicAccessBlock {key} not true",
                    severity="high",
                    detail=f"{key}={cfg.get(key)}",
                ))

    data, err = _aws_run(["s3api", "get-bucket-policy-status", *b], profile)
    if data and data.get("PolicyStatus", {}).get("IsPublic"):
        findings.append(AuditFinding(
            section="1. Public exposure",
            check="Bucket policy status IsPublic",
            severity="critical",
            detail="get-bucket-policy-status reports IsPublic: true",
        ))

    data, err = _aws_run(["s3api", "get-bucket-encryption", *b], profile)
    if err and "ServerSideEncryptionConfigurationNotFoundError" in err:
        findings.append(AuditFinding(
            section="7. Encryption",
            check="No default encryption",
            severity="medium",
            detail="Bucket has no default encryption configuration",
        ))

    data, _ = _aws_run(["s3api", "get-bucket-versioning", *b], profile)
    if data and data.get("Status") != "Enabled":
        findings.append(AuditFinding(
            section="8. Versioning",
            check="Versioning not enabled",
            severity="medium",
            detail=f"Status={data.get('Status', 'disabled')}",
        ))

    data, _ = _aws_run(["s3api", "get-bucket-logging", *b], profile)
    if not data or not data.get("LoggingEnabled"):
        findings.append(AuditFinding(
            section="9. Logging",
            check="No server access logging",
            severity="medium",
            detail="LoggingEnabled not configured",
        ))

    data, _ = _aws_run(["s3api", "get-bucket-ownership-controls", *b], profile)
    if data:
        rules = data.get("OwnershipControls", {}).get("Rules", [])
        enforced = any(
            r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules
        )
        if not enforced:
            findings.append(AuditFinding(
                section="14. Ownership controls",
                check="BucketOwnerEnforced not set",
                severity="medium",
                detail="Prefer BucketOwnerEnforced to disable ACL reliance",
            ))

    data, err = _aws_run(["s3api", "get-bucket-lifecycle-configuration", *b], profile)
    if err and "NoSuchLifecycleConfiguration" in err:
        findings.append(AuditFinding(
            section="10. Lifecycle rules",
            check="No lifecycle configuration",
            severity="low",
            detail="No lifecycle rules defined",
        ))

    data, _ = _aws_run(["s3api", "get-bucket-replication", *b], profile)
    if data and data.get("ReplicationConfiguration"):
        rules = data["ReplicationConfiguration"].get("Rules", [])
        for rule in rules:
            if rule.get("Status") == "Enabled" and not rule.get("Destination", {}).get(
                "EncryptionConfiguration"
            ):
                findings.append(AuditFinding(
                    section="13. Replication",
                    check="Replication without destination encryption",
                    severity="medium",
                    detail="Review cross-account/region replication scope",
                ))

    return findings


def run_anonymous_audit(
    *,
    status: str,
    sample_keys: list[str],
    readable_keys: list[str],
    policy_text: str | None = None,
    acl_text: str | None = None,
    cors_text: str | None = None,
    website_xml: str | None = None,
    writable: bool = False,
    deletable: bool = False,
) -> list[AuditFinding]:
    """Map unsigned HTTP probe results to checklist findings."""
    findings: list[AuditFinding] = []

    if status in ("OPEN", "WRITABLE"):
        findings.append(AuditFinding(
            section="2. Anonymous permissions",
            check="Anonymous ListBucket",
            severity="critical" if _has_sensitive_keys(sample_keys) else "high",
            detail="ListBucket succeeds without authentication",
        ))

    if writable:
        findings.append(AuditFinding(
            section="4. Write permissions",
            check="Anonymous PutObject",
            severity="critical",
            detail="Unauthorized upload succeeded (test object written)",
        ))
    if deletable:
        findings.append(AuditFinding(
            section="4. Write permissions",
            check="Anonymous DeleteObject",
            severity="critical",
            detail="Unauthorized delete succeeded on test object",
        ))

    if readable_keys:
        sensitive_reads = [k for k in readable_keys if _key_is_sensitive(k)]
        sev = "critical" if sensitive_reads else "high"
        preview = ", ".join(readable_keys[:5])
        if len(readable_keys) > 5:
            preview += f" (+{len(readable_keys) - 5} more)"
        findings.append(AuditFinding(
            section="3. Object-level exposure",
            check="Anonymous GetObject",
            severity=sev,
            detail=f"{len(readable_keys)} object(s) publicly readable: {preview}",
        ))

    if policy_text:
        findings.extend(analyze_bucket_policy(policy_text))
        findings.append(AuditFinding(
            section="1. Public exposure",
            check="Bucket policy readable anonymously",
            severity="high",
            detail="Policy document returned without authentication",
        ))
    if acl_text:
        findings.extend(analyze_bucket_acl(acl_text))
        findings.append(AuditFinding(
            section="6. ACL risks",
            check="Bucket ACL readable anonymously",
            severity="high",
            detail="ACL returned without authentication",
        ))
    if cors_text:
        findings.extend(analyze_cors_xml(cors_text))
    if website_xml:
        findings.append(AuditFinding(
            section="12. Website hosting",
            check="Static website hosting enabled",
            severity="medium",
            detail="Review index/error documents for unintended exposure",
        ))

    sensitive = [k for k in sample_keys if _key_is_sensitive(k)]
    if sensitive and status in ("OPEN", "WRITABLE"):
        findings.append(AuditFinding(
            section="15. Sensitive data discovery",
            check="Sensitive object names in listing",
            severity="critical",
            detail="Listed keys: " + ", ".join(sensitive[:5]),
        ))

    return findings


def _key_is_sensitive(key: str) -> bool:
    kl = key.lower()
    tokens = (
        ".env", ".pem", ".key", ".sql", ".bak", "backup", "dump", "secret",
        "credential", "password", "id_rsa", "tfstate", ".p12", ".kube",
    )
    return any(t in kl for t in tokens)


def _has_sensitive_keys(keys: list[str]) -> bool:
    return any(_key_is_sensitive(k) for k in keys)


def merge_findings(*groups: list[AuditFinding]) -> list[AuditFinding]:
    seen = set()
    out = []
    for group in groups:
        for f in group:
            key = (f.section, f.check, f.detail)
            if key not in seen:
                seen.add(key)
                out.append(f)
    return out
