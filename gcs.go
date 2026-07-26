package main

import "fmt"

// probeGCS checks whether a GCS bucket exists and is publicly listable via
// the public JSON API endpoint (no credentials required for public buckets).
// TODO: implement the same pattern as probeAWS — GET
// https://storage.googleapis.com/storage/v1/b/<bucket>/o
// 200 = exists (check public read); 404 = doesn't exist; 403 = exists, private.
func probeGCS(bucketName string) *Finding {
	_ = fmt.Sprintf // placeholder import use until implemented
	return nil
}
