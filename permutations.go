package main

import "strings"

// commonSuffixes are patterns companies frequently append to their base name
// when naming cloud storage buckets. This list drives the base v1 wordlist;
// expand it (or load from config/wordlist.txt) as you learn what hits.
var commonSuffixes = []string{
	"", // bare name itself, e.g. "acmecorp"
	"-backup", "-backups", "-prod", "-production",
	"-data", "-assets", "-static", "-media",
	"-logs", "-log", "-dev", "-development",
	"-staging", "-stage", "-test", "-files",
	"-storage", "-uploads", "-images", "-public",
	"-private", "-internal", "-archive", "-db",
	"-database", "-config", "-configs", "-secrets",
}

// GeneratePermutations takes a company name or domain and produces a list
// of candidate bucket names to probe. Call this once per scan; the result
// is fed into the job queue for concurrent probing.
func GeneratePermutations(seed string) []string {
	base := normalizeSeed(seed)

	seen := make(map[string]bool)
	var candidates []string

	addCandidate := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		candidates = append(candidates, name)
	}

	for _, suffix := range commonSuffixes {
		addCandidate(base + suffix)
	}

	return candidates
}

// normalizeSeed strips protocol/TLD noise and lowercases so
// "https://acmecorp.com" and "AcmeCorp.com" both become "acmecorp".
func normalizeSeed(seed string) string {
	s := strings.ToLower(seed)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")

	// Strip the most common TLDs so "acmecorp.com" -> "acmecorp".
	// This is intentionally simple for v1 — a real TLD list can replace
	// this later if you find it's producing bad candidates.
	for _, tld := range []string{".com", ".io", ".net", ".org", ".co"} {
		s = strings.TrimSuffix(s, tld)
	}

	return s
}
