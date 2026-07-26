# CloudBucket

A Go CLI tool that enumerates publicly exposed cloud storage across **AWS S3**, **Google Cloud Storage**, and **Azure Blob Storage** — using concurrent, unauthenticated probing (no cloud credentials required to run a scan).

## Why this exists

A significant share of cloud storage buckets are left publicly readable, writable, or listable by accident — this class of misconfiguration has caused real breaches (Capital One, Twitch, and others). Existing enumeration tools (cloud_enum, S3Scanner) tend to be AWS-heavy, slower, or don't clearly rank how serious a finding actually is. CloudBucket focuses on being fast, genuinely multi-cloud, and outputting structured findings you can act on.

## What it does

Given a company name or domain, CloudBucket:
1. Generates likely bucket/container name candidates (`company-backups`, `company-prod`, `company-assets`, etc.)
2. Probes each candidate against AWS S3, GCS, and Azure Blob Storage **concurrently** using a goroutine worker pool
3. Reports what it finds as structured JSON — bucket existence, public/private status, and a basic risk level

## Usage

```bash
go build -o cloudbucket .
./cloudbucket -domain example.com
./cloudbucket -domain example.com -output report.json -threads 30
```

Flags:
- `-domain` — target company name or domain (required)
- `-output` — write JSON report to a file instead of stdout (optional)
- `-threads` — number of concurrent probe workers, default 30 (optional)

## Example output

```json
{
  "domain": "flaws.cloud",
  "scan_duration_seconds": 0.73,
  "findings": [
    {
      "bucket_name": "flaws.cloud",
      "provider": "aws_s3",
      "status": "exists_wrong_region",
      "risk": "Low",
      "reason": "Bucket exists in a different AWS region — public/private status not yet checked"
    }
  ],
  "summary": {
    "total_checked": 29,
    "total_found": 1,
    "critical": 0, "high": 0, "medium": 0, "low": 1
  }
}
```

## Current status

| Provider | Status |
|---|---|
| AWS S3 | ✅ Implemented — existence, public/private, region-redirect handling |
| Google Cloud Storage | ✅ Implemented — existence, public/private via JSON API |
| Azure Blob Storage | ✅ Implemented — existence, public/private, handles ambiguous-config (409) responses |

**Planned next:**
- [ ] Risk-scoring refinement — inspect file *contents* (not just filenames) for credential patterns
- [ ] Dangling-bucket / subdomain takeover detection via DNS CNAME cross-referencing
- [ ] Benchmark report vs. cloud_enum / S3Scanner

## How it works (architecture)

- **Concurrency**: a bounded goroutine worker pool pulls jobs from a shared channel, so scans scale without spawning unbounded goroutines. Default 30 workers, tunable via `-threads`.
- **No credentials needed for scanning**: all three providers expose a public HTTPS endpoint per bucket/container — the same URL a browser would hit — so existence and public-access checks don't require any cloud account setup.
- **Timeouts**: each request has a client-side timeout so one slow/unresponsive candidate can't stall the whole scan.

```
cloudbucket/
├── main.go            # CLI entrypoint, worker-pool orchestration
├── permutations.go    # Bucket/container name candidate generation
├── aws.go              # AWS S3 probing + risk classification
├── gcs.go               # GCS probing
├── azure.go             # Azure Blob probing
├── models.go             # Finding/Report data structures
```

## Bugs found and fixed during development

Real issues hit and resolved while building this — kept here because they were genuinely instructive, not just "it worked first try":

1. **SSL certificate mismatch on dotted bucket names (AWS)** — S3's virtual-hosted-style URLs (`bucket.s3.amazonaws.com`) fail certificate validation when the bucket name itself contains a dot, because the resulting hostname has more subdomain levels than the wildcard cert covers. Fixed by switching to path-style URLs (`s3.amazonaws.com/bucket`), which keeps the hostname constant regardless of bucket name.

2. **Silent failure on AWS region-redirect (301) responses** — AWS's path-style endpoint returns `301` (often without a `Location` header) when a bucket exists but lives outside `us-east-1`. Without an explicit case for this, the response fell through to a generic "not found" — silently losing a real existence signal. Fixed by treating `301`/`302` as a confirmed-exists finding with an "access level not yet checked" caveat.

3. **Azure DNS timeout behavior on nonexistent storage accounts** — unlike AWS/GCS, Azure doesn't always fail DNS resolution quickly for storage-account subdomains that don't exist, causing `context deadline exceeded` timeouts rather than fast `404`s. This is expected Azure platform behavior, not a bug — handled by treating timeouts the same as "not found," with the tradeoff being slower scans against Azure specifically.

## Ethical & legal use

This tool is developed and tested only against:
- Cloud storage the developer owns
- Publicly available, intentionally vulnerable practice targets (e.g. [flaws.cloud](http://flaws.cloud))

**Do not run this against third-party organizations without explicit written authorization.**

## License

MIT





