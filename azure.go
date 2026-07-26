package main

import (
	"encoding/xml"
	"fmt"
	"io"
)

// probeAzure checks whether an Azure Blob Storage container exists and is
// publicly listable. Azure needs both a storage account name and a
// container name — for v1, we try using the same generated name for both,
// since we don't yet have a separate account-name wordlist.
func probeAzure(bucketName string) *Finding {
	url := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", bucketName, bucketName)

	resp, err := httpClient.Get(url)
	if err != nil {
                
		return nil
	}
	defer resp.Body.Close()
        

	switch resp.StatusCode {
	case 404:
		return nil // account or container doesn't exist

	case 200:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		keys := extractAzureKeys(body)
		return &Finding{
			BucketName: bucketName,
			Provider:   "azure_blob",
			Status:     "public_read",
			Risk:       classifyRisk(keys),
			Reason:     "Container listing is publicly accessible",
			SampleKeys: keys,
		}

	case 403:
		return &Finding{
			BucketName: bucketName,
			Provider:   "azure_blob",
			Status:     "private",
			Risk:       "Low",
			Reason:     "Container exists but is not publicly accessible",
		}

	case 409:
		// Container/account exists and is reachable, but this listing
		// method isn't compatible with how it's configured internally
		// (commonly a hierarchical-namespace storage account). Existence
		// is still confirmed, access level is not.
		return &Finding{
			BucketName: bucketName,
			Provider:   "azure_blob",
			Status:     "exists_unknown_config",
			Risk:       "Low",
			Reason:     "Container exists but access level could not be determined",
		}

	default:
		return nil
	}
}

// extractAzureKeys parses Azure's XML container-listing response.
func extractAzureKeys(body []byte) []string {
	var parsed struct {
		Blobs struct {
			Blob []struct {
				Name string `xml:"Name"`
			} `xml:"Blob"`
		} `xml:"Blobs"`
	}
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil
	}

	var keys []string
	for i, b := range parsed.Blobs.Blob {
		if i >= 10 {
			break
		}
		keys = append(keys, b.Name)
	}
	return keys
}
