# CloudBucket

A Go CLI tool that enumerates publicly exposed cloud storage across **AWS S3**, **Google Cloud Storage**, and **Azure Blob Storage** — using concurrent, unauthenticated probing (no cloud credentials required to run a scan), with credential-leak detection and subdomain takeover detection.

## Why this exists

A significant share of cloud storage buckets are left publicly readable, writable, or listable by accident — this class of misconfiguration has caused real breaches (Capital One, Twitch, and others). Existing enumeration tools (cloud_enum, S3Scanner) tend to be AWS-heavy, slower, or don't clearly rank how serious a finding actually is. CloudBucket focuses on being fast, genuinely multi-cloud, and — unlike most existing tools — goes past "this bucket is public" to answer "does it actually leak something, and could it be hijacked?"

## What it does

Given a company name or domain, CloudBucket:
1. Generates likely bucket/container name candidates (`company-backups`, `company-prod`, `company-assets`, etc.)
2. Probes each candidate against AWS S3, GCS, and Azure Blob Storage **concurrently** using a goroutine worker pool
3. For any bucket found publicly readable, downloads a few promising-looking files and scans their **contents** for real credential patterns (AWS keys, private key headers, `.env`-style secrets) — not just filenames
4. Optionally checks a list of subdomains for **dangling CNAME records** pointing at cloud storage that no longer exists — a subdomain takeover risk
5. Reports everything as structured JSON, findings ranked by risk level

## Usage

```bash
go build -o cloudbucket .
./cloudbucket -domain example.com
./cloudbucket -domain example.com -output report.json -threads 30
./cloudbucket -domain example.com -subdomains sample_subdomains.txt
```

Flags:
- `-domain` — target company name or domain (required)
- `-output` — write JSON report to a file instead of stdout (optional)
- `-threads` — number of concurrent probe workers, default 30 (optional)
- `-subdomains` — path to a file with one subdomain prefix per line, enables takeover detection (optional)

## Current status

| Feature | Status |
|---|---|
| AWS S3 enumeration | Implemented — existence, public/private, region-redirect handling |
| Google Cloud Storage enumeration | Implemented — existence, public/private via JSON API |
| Azure Blob Storage enumeration | Implemented — existence, public/private, handles ambiguous-config (409) responses |
| Credential content scanning — AWS | Implemented and verified live against a real test bucket |
| Credential content scanning — GCS | Implemented and verified live against a real test bucket |
| Credential content scanning — Azure | Implemented, same pattern as AWS/GCS — not yet live-verified due to Azure account access issues during development |
| Subdomain takeover detection | Implemented — DNS CNAME lookup with timeout handling, cross-referenced against bucket existence. Tested for correctness (no false positives on a real domain); no live positive case confirmed yet |

**Planned next:**
- Live-verify Azure credential scanning once account access is resolved
- Benchmark report vs. cloud_enum / S3Scanner
- Expand default bucket-name and subdomain wordlists

## How it works (architecture)

- **Concurrency**: a bounded goroutine worker pool pulls jobs from a shared channel for bucket enumeration, so scans scale without spawning unbounded goroutines. Default 30 workers, tunable via `-threads`.
- **No credentials needed for scanning**: all three providers expose a public HTTPS endpoint per bucket/container — the same URL a browser would hit — so existence and public-access checks don't require any cloud account setup.
- **Timeouts everywhere**: HTTP requests and DNS lookups both have client-side timeouts, so one slow/unresponsive candidate can't stall the whole scan.
- **Credential scanning**: for public buckets, small text-like files (`.env`, `.json`, `.txt`, `.pem`, `.sql`, etc.) are downloaded (capped at 64KB each) and checked against regex patterns for AWS access keys, private key headers, and generic `.env`-style secret assignments. One confirmed match is enough to upgrade a finding to Critical.
- **Takeover detection**: for each subdomain candidate, resolves its CNAME record; if that CNAME points at a recognized cloud storage domain pattern, checks whether the target bucket actually exists using the same probe logic as regular enumeration. A CNAME pointing at a nonexistent bucket is flagged High risk.

```
cloudbucket/
├── main.go               # CLI entrypoint, worker-pool orchestration, takeover wiring
├── permutations.go       # Bucket/container name candidate generation
├── aws.go                # AWS S3 probing + credential scanning
├── gcs.go                # GCS probing + credential scanning
├── azure.go              # Azure Blob probing + credential scanning
├── credscan.go           # Shared credential pattern matching (all providers)
├── takeover.go           # Subdomain takeover detection via DNS CNAME
├── models.go              # Finding/Report/TakeoverFinding data structures
├── sample_subdomains.txt  # Example wordlist for -subdomains flag
```

## Bugs found and fixed during development

Real issues hit and resolved while building this:

1. **SSL certificate mismatch on dotted bucket names (AWS)** — S3's virtual-hosted-style URLs fail certificate validation when the bucket name itself contains a dot, because the resulting hostname has more subdomain levels than the wildcard cert covers. Fixed by switching to path-style URLs.

2. **Silent failure on AWS region-redirect (301) responses** — AWS's path-style endpoint returns 301, often without a Location header, when a bucket exists but lives outside us-east-1. Fixed by treating 301/302 as a confirmed-exists finding.

3. **Azure DNS timeout behavior on nonexistent storage accounts** — Azure doesn't always fail DNS resolution quickly for nonexistent storage-account subdomains, causing context deadline exceeded timeouts rather than fast 404s. Handled by treating timeouts the same as not-found.

4. **GCS "Public access prevention" org policy overriding bucket-level permissions** — granting allUsers the Storage Object Viewer role wasn't enough to make a bucket public; a separate project-level policy silently blocked it, returning 401 instead of 200. A good example of cloud platforms layering secondary guardrails on top of individual resource permissions.

5. **Unbounded DNS lookups hanging the takeover-detection scan** — net.LookupCNAME has no built-in timeout; slow-to-resolve subdomains could stall the scan indefinitely. Fixed by wrapping the lookup in a context-bound resolver call.

## Ethical & legal use

This tool is developed and tested only against cloud storage the developer owns, and publicly available, intentionally vulnerable practice targets (e.g. flaws.cloud). Do not run this against third-party organizations without explicit written authorization.

## License

MIT


