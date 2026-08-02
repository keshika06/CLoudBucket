package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

func main() {
	domain := flag.String("domain", "", "target company name or domain, e.g. acmecorp.com")
	outputPath := flag.String("output", "", "write JSON report to this file instead of stdout")
	threads := flag.Int("threads", 30, "number of concurrent probe workers")
	subdomainFile := flag.String("subdomains", "", "path to a file with one subdomain prefix per line, for takeover detection")
	flag.Parse()

	if *domain == "" {
		fmt.Println("usage: cloudbucket -domain acmecorp.com [-output report.json] [-threads 30] [-subdomains subdomains.txt]")
		os.Exit(1)
	}

	start := time.Now()

	candidates := GeneratePermutations(*domain)
	findings := runScan(candidates, *threads)

	var takeoverFindings []TakeoverFinding
	if *subdomainFile != "" {
		prefixes, err := loadSubdomainPrefixes(*subdomainFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not read subdomain file:", err)
		} else {
			takeoverFindings = checkTakeovers(*domain, prefixes)
		}
	}

	report := buildReport(*domain, findings, len(candidates), time.Since(start))
	report.TakeoverFindings = takeoverFindings

	writeReport(report, *outputPath)
}

func runScan(candidates []string, workers int) []Finding {
	jobs := make(chan job, len(candidates)*3)
	results := make(chan *Finding, len(candidates)*3)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if f := probeBucket(j); f != nil {
					results <- f
				}
			}
		}()
	}

	providers := []string{"aws_s3", "gcs", "azure_blob"}
	for _, name := range candidates {
		for _, p := range providers {
			jobs <- job{bucketName: name, provider: p}
		}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	for f := range results {
		findings = append(findings, *f)
	}
	return findings
}

func probeBucket(j job) *Finding {
	switch j.provider {
	case "aws_s3":
		return probeAWS(j.bucketName)
	case "gcs":
		return probeGCS(j.bucketName)
	case "azure_blob":
		return probeAzure(j.bucketName)
	}
	return nil
}

func buildReport(domain string, findings []Finding, totalChecked int, duration time.Duration) Report {
	summary := Summary{TotalChecked: totalChecked, TotalFound: len(findings)}
	for _, f := range findings {
		switch f.Risk {
		case "Critical":
			summary.Critical++
		case "High":
			summary.High++
		case "Medium":
			summary.Medium++
		case "Low":
			summary.Low++
		}
	}

	return Report{
		Domain:       domain,
		ScanDuration: duration.Seconds(),
		Timestamp:    time.Now().UTC(),
		Findings:     findings,
		Summary:      summary,
	}
}

func writeReport(r Report, path string) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to marshal report:", err)
		os.Exit(1)
	}

	if path == "" {
		fmt.Println(string(data))
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		fmt.Fprintln(os.Stderr, "failed to write report:", err)
		os.Exit(1)
	}
	fmt.Printf("Report written to %s (%d findings from %d candidates)\n", path, r.Summary.TotalFound, r.Summary.TotalChecked)
}
