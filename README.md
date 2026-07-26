# CloudBucket (v0 — Phase 1 skeleton)

Multi-cloud storage bucket recon CLI. This is the working Phase 1 starting
point: AWS S3 is implemented, GCS and Azure are stubbed for you to fill in.

## Run it

```bash
go build -o cloudbucket .
./cloudbucket -domain flaws.cloud
./cloudbucket -domain acmecorp.com -output report.json -threads 30
```

No cloud credentials needed yet — AWS probing uses S3's public
virtual-hosted-style endpoint (`https://<bucket>.s3.amazonaws.com`), the same
URL a browser would hit. That's how bucket *existence* and *public
listability* can be checked with zero auth.

## What's implemented

- [x] Bucket name permutation engine (`permutations.go`)
- [x] Goroutine worker-pool concurrency (`main.go` — `runScan`)
- [x] AWS S3 probing: existence + public-read detection (`aws.go`)
- [x] Basic risk classification by filename pattern (`aws.go` — `classifyRisk`)
- [x] JSON report output
- [ ] GCS probing (`gcs.go` — stub, TODO comment has the endpoint pattern)
- [ ] Azure probing (`azure.go` — stub, TODO comment has the endpoint pattern)
- [ ] Credential-content scanning inside exposed files (differentiator #2)
- [ ] Dangling-bucket / subdomain takeover detection (differentiator #3)

## Next steps (in order)

1. Implement `probeGCS` in `gcs.go` — same shape as `probeAWS`, different URL
   pattern (see the TODO comment in the file for the exact endpoint).
2. Implement `probeAzure` in `azure.go` — note Azure needs an *account* name
   as well as a container name, so your permutation strategy needs a small
   tweak here.
3. Expand `classifyRisk` in `aws.go` to actually download and grep small text
   files (`.env`, config files) for credential patterns, not just filename
   matching.
4. Add DNS CNAME lookup + dangling-bucket detection as a new file (`takeover.go`).
5. Only once all of the above works: wire up authenticated SDK calls
   (`aws-sdk-go-v2`, `cloud.google.com/go/storage`,
   `github.com/Azure/azure-sdk-for-go`) for anything that needs real
   credentials (e.g. testing write-access, listing your *own* private test
   buckets during development).

## Ethical/legal note

Only run this against buckets you own or public legal practice targets like
`flaws.cloud`. Never scan real organizations without written authorization.
