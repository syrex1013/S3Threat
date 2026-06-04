# S3Threat Security Checklist

This document maps the assessment checklist to S3Threat capabilities.

| § | Topic | Anonymous (`main.py`) | AWS CLI (`--aws`) |
|---|--------|----------------------|-------------------|
| 1 | Public exposure | Policy/ACL readable; policy parser | `get-public-access-block`, `get-bucket-policy-status` |
| 2 | Anonymous permissions | ListBucket, GetObject probes | — |
| 3 | Object-level exposure | HEAD/GET on 40+ sensitive key paths | — |
| 4 | Write permissions | PUT + DELETE test object (`--check-write`) | — |
| 5 | Bucket policy risks | JSON policy analysis (`Principal: *`, `s3:*`, referrer) | `get-bucket-policy` |
| 6 | ACL risks | XML ACL analysis (AllUsers / AuthenticatedUsers) | `get-bucket-acl` |
| 7 | Encryption | — | `get-bucket-encryption` |
| 8 | Versioning | — | `get-bucket-versioning` |
| 9 | Logging | — | `get-bucket-logging` |
| 10 | Lifecycle | — | `get-bucket-lifecycle-configuration` |
| 11 | CORS | `?cors` fetch + wildcard analysis | `get-bucket-cors` |
| 12 | Website hosting | `?website` fetch | `get-bucket-website` |
| 13 | Replication | — | `get-bucket-replication` |
| 14 | Ownership controls | — | `get-bucket-ownership-controls` |
| 15 | Sensitive data discovery | Listing + key pattern triage | — |
| 16 | IAM access paths | — | Manual / `simulate-principal-policy` |
| 17 | Account-level Block Public Access | — | `s3control get-public-access-block` |
| 18 | Severity guide | `severity` field on each finding | Same |

## Severity guide

| Finding | Severity |
|---------|----------|
| Anonymous PutObject / DeleteObject | **Critical** |
| Anonymous ListBucket with sensitive data | **Critical** |
| Public GetObject on secrets/backups | **Critical** |
| Public policy `s3:*` with `Principal: *` | **Critical** |
| ACL AllUsers WRITE / FULL_CONTROL | **Critical** |
| Wildcard CORS with write methods | **High** |
| Public policy List/Get without sensitive listing | **High** |
| Missing encryption / logging / versioning | **Medium** |
| No lifecycle rules | **Low** |

## Commands

```bash
# Full checklist report (anonymous)
python3 main.py --audit BUCKET_NAME

# Include AWS API checks (requires credentials)
python3 main.py --audit BUCKET_NAME --aws --aws-profile your-profile

# Discovery with write + AWS audit on hits
python3 main.py acme --check-write --aws -o findings.json
```
