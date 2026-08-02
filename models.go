package main

import "time"

// Finding represents a single discovered bucket and what we learned about it.
type Finding struct {
	BucketName string   `json:"bucket_name"`
	Provider   string   `json:"provider"` // "aws_s3", "gcs", "azure_blob"
	Status     string   `json:"status"`   // "public_read", "public_write", "public_list", "private"
	Risk       string   `json:"risk"`     // "Critical", "High", "Medium", "Low"
	Reason     string   `json:"reason,omitempty"`
	SampleKeys []string `json:"sample_files,omitempty"`
}

// Report is the top-level JSON output structure.
type Report struct {
	Domain       string    `json:"domain"`
	ScanDuration float64   `json:"scan_duration_seconds"`
	Timestamp    time.Time `json:"timestamp"`
	Findings     []Finding `json:"findings"`
	TakeoverFindings []TakeoverFinding `json:"takeover_findings,omitempty"`
	Summary      Summary   `json:"summary"`
}

// Summary is a quick-glance rollup of the scan.
type Summary struct {
	TotalChecked int `json:"total_checked"`
	TotalFound   int `json:"total_found"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
}

// job is an internal unit of work sent to probe workers.
type job struct {
	bucketName string
	provider   string
}
