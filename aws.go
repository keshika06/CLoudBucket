package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
	},
}

// probeAWS checks whether an S3 bucket exists and, if so, whether it's
// publicly listable. This uses S3's public virtual-hosted-style endpoint
// directly (https://<bucket>.s3.amazonaws.com) — no AWS credentials
// required for this check, since it's the same endpoint a browser would hit.
func probeAWS(bucketName string) *Finding {
	url := fmt.Sprintf("https://s3.amazonaws.com/%s", bucketName)

	resp, err := httpClient.Get(url)
	if err != nil {
                
		return nil // network error / doesn't resolve -> treat as not found
	}
        
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 404:
		return nil // bucket doesn't exist
        
        case 301, 302:
              // AWS returns this (often without a Location header) when the bucket
              // exists but lives in a region other than us-east-1. No Location means
              // Go can't auto-follow it — but the redirect itself confirms existence.
              return &Finding{
                BucketName: bucketName,
                Provider:   "aws_s3",
                Status:     "exists_wrong_region",
                Risk:       "Low",
                Reason:     "Bucket exists in a different AWS region — public/private status not yet checked",
             }

	case 200:
		// Public listing succeeded — bucket exists and is publicly readable.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		keys := extractS3Keys(string(body))
		return &Finding{
			BucketName: bucketName,
			Provider:   "aws_s3",
			Status:     "public_read",
			Risk:       classifyRisk(keys),
			Reason:     "Bucket listing is publicly accessible",
			SampleKeys: keys,
		}

	case 403:
		// Bucket exists but access is denied — it's private. Still worth
		// recording that it exists, at Low risk, since bucket existence
		// itself is minor recon value (confirms naming convention).
		return &Finding{
			BucketName: bucketName,
			Provider:   "aws_s3",
			Status:     "private",
			Risk:       "Low",
			Reason:     "Bucket exists but is not publicly accessible",
		}

	default:
		return nil
	}
}

// extractS3Keys does a very light-touch parse of S3's XML listing response
// to pull out object keys (filenames). This is intentionally not a full XML
// parser for v1 — swap in encoding/xml if you need it more robust later.
func extractS3Keys(xmlBody string) []string {
	var keys []string
	parts := strings.Split(xmlBody, "<Key>")
	for i := 1; i < len(parts) && i <= 10; i++ { // cap at 10 sample keys
		end := strings.Index(parts[i], "</Key>")
		if end == -1 {
			continue
		}
		keys = append(keys, parts[i][:end])
	}
	return keys
}

// classifyRisk is the v1 risk-scoring rule set (see PRD section 4.4).
// Starts simple — filename pattern matching — and is the natural place to
// plug in the credential-content-scanning differentiator later.
func classifyRisk(keys []string) string {
	criticalPatterns := []string{".env", ".pem", ".sql", "credentials", "secret", ".key"}
	for _, k := range keys {
		lower := strings.ToLower(k)
		for _, pat := range criticalPatterns {
			if strings.Contains(lower, pat) {
				return "Critical"
			}
		}
	}
	if len(keys) > 0 {
		return "Medium" // listing is exposed, nothing obviously sensitive by name yet
	}
	return "Low"
}
