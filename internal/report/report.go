// Package report renders a scan: a table for people, JSON for machines.
package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/finding"
)

// Schema names the JSON report format.
const Schema = "authsec-cli.scan/v1"

// Machine describes where the scan ran. ID is the hashed machine id, never
// the OS one.
type Machine struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	User     string `json:"user"`
}

// Summary counts findings and signals.
type Summary struct {
	Findings map[finding.Kind]int `json:"findings"`
	Signals  map[string]int       `json:"signals"`
}

// Report is one scan, the canonical JSON output.
type Report struct {
	Schema           string            `json:"schema"`
	CLIVersion       string            `json:"cli_version"`
	CatalogueVersion string            `json:"catalogue_version"`
	ScannedAt        time.Time         `json:"scanned_at"`
	Machine          Machine           `json:"machine"`
	Home             string            `json:"home"`
	Projects         []string          `json:"projects"`
	FilesRead        []string          `json:"files_read"`
	Findings         []finding.Finding `json:"findings"`
	Summary          Summary           `json:"summary"`
}

// Summarize fills r.Summary from r.Findings.
func (r *Report) Summarize() {
	r.Summary = Summary{Findings: map[finding.Kind]int{}, Signals: map[string]int{}}
	for _, f := range r.Findings {
		r.Summary.Findings[f.Kind]++
		for _, s := range f.Signals {
			r.Summary.Signals[s.ID]++
		}
	}
}

// JSON writes the report, indented.
func JSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
