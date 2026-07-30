package main

import (
	"io"
	"regexp"
	"strings"
)

// Patterns for real credential shapes inside file contents — not just
// filenames. Each has a label used in the finding's Reason field so the
// output says exactly what was matched, not just "looks suspicious."
var credentialPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS secret key assignment", regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"]?[A-Za-z0-9/+=]{40}`)},
	{"private key header", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
	{"generic .env secret", regexp.MustCompile(`(?im)^(SECRET|PASSWORD|API_KEY|TOKEN|DB_PASS)\w*\s*=\s*\S+`)},
}

// candidateForContentScan decides whether a filename is worth downloading
// and scanning. We only want small, text-like files — no point pulling
// images, videos, or large archives just to regex them.
func candidateForContentScan(filename string) bool {
	lower := strings.ToLower(filename)

	skipExt := []string{".jpg", ".jpeg", ".png", ".gif", ".mp4", ".zip", ".tar", ".gz", ".pdf", ".exe", ".dll"}
	for _, ext := range skipExt {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}

	interestingExt := []string{".env", ".yml", ".yaml", ".json", ".txt", ".config", ".ini", ".pem", ".key", ".sql"}
	for _, ext := range interestingExt {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	return false
}

// scanFileContents checks a downloaded file's content against known
// credential patterns and returns a label describing the first match, or
// "" if nothing matched.
func scanFileContents(r io.Reader) string {
	body, err := io.ReadAll(io.LimitReader(r, 65536)) // cap at 64KB per file
	if err != nil {
		return ""
	}
	content := string(body)

	for _, pat := range credentialPatterns {
		if pat.re.MatchString(content) {
			return pat.label
		}
	}
	return ""
}

// downloadAndScan fetches a single file from a public bucket/container URL
// and checks its contents for credential patterns. Returns "" if nothing
// found or the download failed.
func downloadAndScan(fileURL string) string {
	resp, err := httpClient.Get(fileURL)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	return scanFileContents(resp.Body)
}
