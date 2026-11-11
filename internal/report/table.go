package report

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/authsec-ai/authsec-cli/internal/finding"
)

var kindLabel = map[finding.Kind]string{
	finding.Agent:      "agent",
	finding.Policy:     "policy",
	finding.Extension:  "extension",
	finding.MCPServer:  "mcp",
	finding.Identity:   "identity",
	finding.SecretRef:  "secret",
	finding.Unreadable: "unreadable",
}

var kindPlural = map[finding.Kind][2]string{
	finding.Agent:      {"agent", "agents"},
	finding.Policy:     {"policy", "policies"},
	finding.Extension:  {"extension", "extensions"},
	finding.MCPServer:  {"MCP server", "MCP servers"},
	finding.Identity:   {"identity", "identities"},
	finding.SecretRef:  {"secret reference", "secret references"},
	finding.Unreadable: {"unreadable file", "unreadable files"},
}

// Table writes the report grouped by tool: one block per agent with its
// policies, extensions and MCP servers, then a summary.
func Table(w io.Writer, r *Report, displayName func(tool string) string) error {
	byTool := map[string][]finding.Finding{}
	var tools []string
	for _, f := range r.Findings {
		if _, ok := byTool[f.Tool]; !ok {
			tools = append(tools, f.Tool)
		}
		byTool[f.Tool] = append(byTool[f.Tool], f)
	}
	sort.Strings(tools)

	fmt.Fprintf(w, "authsec-cli scan · %s (%s/%s) · catalogue %s\n\n", r.Machine.Hostname, r.Machine.OS, r.Machine.Arch, r.CatalogueVersion)
	if len(tools) == 0 {
		fmt.Fprintln(w, "No AI agents found.")
	}
	for _, tool := range tools {
		fs := byTool[tool]
		fmt.Fprintf(w, "%s  (%s)\n", displayName(tool), counts(fs))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  KIND\tNAME\tSCOPE\tWHERE\tSIGNALS")
		for _, f := range fs {
			if f.Kind == finding.Agent {
				continue
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", kindLabel[f.Kind], clip(f.Name, 40), f.Scope, where(f, r.Home), signalIDs(f))
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Read %d files across the home directory and %d projects.\n", len(r.FilesRead), len(r.Projects))
	if len(r.Summary.Signals) > 0 {
		ids := make([]string, 0, len(r.Summary.Signals))
		for id := range r.Summary.Signals {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		parts := make([]string, len(ids))
		for i, id := range ids {
			parts[i] = fmt.Sprintf("%s %d", id, r.Summary.Signals[id])
		}
		fmt.Fprintf(w, "Signals: %s. Run with --json for the reason behind each.\n", strings.Join(parts, " · "))
	}
	return nil
}

func counts(fs []finding.Finding) string {
	n := map[finding.Kind]int{}
	for _, f := range fs {
		n[f.Kind]++
	}
	var parts []string
	for _, k := range finding.Kinds() {
		if k == finding.Agent || n[k] == 0 {
			continue
		}
		label := kindPlural[k][0]
		if n[k] > 1 {
			label = kindPlural[k][1]
		}
		parts = append(parts, fmt.Sprintf("%d %s", n[k], label))
	}
	if len(parts) == 0 {
		return "installed, nothing configured"
	}
	return strings.Join(parts, " · ")
}

// where shows the file, home-relative; for an entry keyed by project inside a
// shared file (~/.claude.json), the project too.
func where(f finding.Finding, home string) string {
	p := Tilde(f.Path, home)
	if f.Project != "" && !strings.HasPrefix(f.Path, f.Project) {
		p += " → " + Tilde(f.Project, home)
	}
	return clipLeft(p, 70)
}

// Tilde shortens a path under home to ~/...
func Tilde(p, home string) string {
	if home != "" {
		if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") {
			if rel == "." {
				return "~"
			}
			return "~" + string(filepath.Separator) + rel
		}
	}
	return p
}

func signalIDs(f finding.Finding) string {
	ids := make([]string, len(f.Signals))
	for i, s := range f.Signals {
		ids[i] = s.ID
	}
	if len(ids) == 0 {
		return "-"
	}
	return strings.Join(ids, ", ")
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func clipLeft(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return "…" + string(r[len(r)-n+1:])
	}
	return s
}
