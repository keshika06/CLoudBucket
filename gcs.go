package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// probeGCS checks whether a GCS bucket exists and is publicly listable via
// the public JSON API — no credentials needed for this check, same idea as
// probeAWS.
func probeGCS(bucketName string) *Finding {
	url := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o", bucketName)

	resp, err := httpClient.Get(url)
	if err != nil {
                
		return nil
	}
	defer resp.Body.Close()
        

	switch resp.StatusCode {
	case 404:
		return nil // bucket doesn't exist

	case 200:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		keys := extractGCSKeys(body)
		return &Finding{
			BucketName: bucketName,
			Provider:   "gcs",
			Status:     "public_read",
			Risk:       classifyRisk(keys),
			Reason:     "Bucket listing is publicly accessible",
			SampleKeys: keys,
		}

	case 403:
		return &Finding{
			BucketName: bucketName,
			Provider:   "gcs",
			Status:     "private",
			Risk:       "Low",
			Reason:     "Bucket exists but is not publicly accessible",
		}

	default:
		return nil
	}
}

// extractGCSKeys parses the GCS JSON API's object listing response.
// Unlike S3's XML, this is real JSON, so we can decode it properly instead
// of string-splitting.
func extractGCSKeys(body []byte) []string {
	var parsed struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil
	}

	var keys []string
	for i, item := range parsed.Items {
		if i >= 10 {
			break
		}
		keys = append(keys, item.Name)
	}
	return keys
}
