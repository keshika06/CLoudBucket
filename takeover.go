package main

import (
        "context"
        "time"
	"fmt"
	"net"
	"os"
	"strings"
)

// TakeoverFinding represents a subdomain whose CNAME points to a cloud
// storage bucket/container that doesn't currently exist — meaning anyone
// could register that bucket name and hijack the subdomain.
type TakeoverFinding struct {
	Subdomain    string `json:"subdomain"`
	CNAME        string `json:"cname"`
	Provider     string `json:"provider"`
	BucketName   string `json:"bucket_name"`
	Risk         string `json:"risk"`
	Reason       string `json:"reason"`
}

// loadSubdomainPrefixes reads one prefix per line from a file (e.g. "assets",
// "cdn"). Blank lines are skipped.
func loadSubdomainPrefixes(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var prefixes []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			prefixes = append(prefixes, line)
		}
	}
	return prefixes, nil
}

// checkTakeovers walks each subdomain candidate, resolves its CNAME, and if
// that CNAME points at a cloud storage domain, checks whether the target
// bucket actually exists. A CNAME pointing at a nonexistent bucket is a
// takeover opportunity.
func checkTakeovers(domain string, prefixes []string) []TakeoverFinding {
	var findings []TakeoverFinding

	for _, prefix := range prefixes {
		subdomain := fmt.Sprintf("%s.%s", prefix, domain)

		resolver := &net.Resolver{}
                ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                cname, err := resolver.LookupCNAME(ctx, subdomain)
                cancel()
                if err != nil {
			continue // no CNAME record, or subdomain doesn't resolve at all
		}
		cname = strings.TrimSuffix(cname, ".") // DNS returns a trailing dot

		provider, bucketName := identifyCloudTarget(cname)
		if provider == "" {
			continue // CNAME doesn't point at a recognized cloud storage domain
		}

		if bucketExists(provider, bucketName) {
			continue // bucket exists — not a takeover risk
		}

		findings = append(findings, TakeoverFinding{
			Subdomain:  subdomain,
			CNAME:      cname,
			Provider:   provider,
			BucketName: bucketName,
			Risk:       "High",
			Reason:     "CNAME points to a cloud storage target that does not exist — subdomain takeover possible",
		})
	}

	return findings
}

// identifyCloudTarget checks if a CNAME target matches a known cloud storage
// domain pattern and extracts the bucket/account name from it.
func identifyCloudTarget(cname string) (provider, bucketName string) {
	lower := strings.ToLower(cname)

	switch {
	case strings.HasSuffix(lower, ".s3.amazonaws.com"):
		return "aws_s3", strings.TrimSuffix(lower, ".s3.amazonaws.com")
	case strings.HasSuffix(lower, ".storage.googleapis.com"):
		return "gcs", strings.TrimSuffix(lower, ".storage.googleapis.com")
	case strings.HasSuffix(lower, ".blob.core.windows.net"):
		return "azure_blob", strings.TrimSuffix(lower, ".blob.core.windows.net")
	}
	return "", ""
}

// bucketExists does a lightweight existence check by reusing the same
// probe logic already built for each provider — we only care whether it
// exists here, not its access level, so any non-nil result counts.
func bucketExists(provider, bucketName string) bool {
	switch provider {
	case "aws_s3":
		return probeAWS(bucketName) != nil
	case "gcs":
		return probeGCS(bucketName) != nil
	case "azure_blob":
		return probeAzure(bucketName) != nil
	}
	return false
}
