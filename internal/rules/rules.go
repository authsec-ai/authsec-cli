// Package rules computes risk signals over findings. Each rule is a pure
// function of a finding's attributes, and every signal carries the reason it
// fired, so a report explains itself. The signals are triage hints; AuthSec's
// server-side policy decides what is acceptable.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/parse"
)

// Signal ids.
const (
	AutoApproveShell = "auto_approve_shell"
	BroadAllow       = "broad_allow"
	HookRunsCommand  = "hook_runs_command"
	MCPUnpinned      = "mcp_unpinned"
	SecretInMCPEnv   = "secret_in_mcp_env"
)

// Def describes a signal for `--fail-on`, SARIF and the docs.
type Def struct {
	ID    string
	Title string
	Level string // SARIF level: error, warning, note
}

// Defs lists every signal.
func Defs() []Def {
	return []Def{
		{AutoApproveShell, "The agent may run shell commands without asking", "error"},
		{BroadAllow, "An allow rule pre-approves a whole tool", "warning"},
		{HookRunsCommand, "A hook runs a shell command on agent events", "note"},
		{MCPUnpinned, "An MCP server is fetched without a pinned version", "warning"},
		{SecretInMCPEnv, "An MCP server is given a credential", "warning"},
	}
}

// Known reports whether id is a signal id.
func Known(id string) bool {
	for _, d := range Defs() {
		if d.ID == id {
			return true
		}
	}
	return false
}

// Apply adds signals to findings in place.
func Apply(fs []finding.Finding) {
	for i := range fs {
		f := &fs[i]
		switch f.Kind {
		case finding.Policy:
			policy(f)
		case finding.Extension:
			extension(f)
		case finding.MCPServer:
			mcp(f)
		}
	}
}

func policy(f *finding.Finding) {
	if mode, _ := f.Attrs["default_mode"].(string); mode == "bypassPermissions" {
		f.AddSignal(AutoApproveShell, "defaultMode is bypassPermissions: every tool, shell included, runs without asking")
	}
	if skip, _ := f.Attrs["skip_dangerous_mode_prompt"].(bool); skip {
		f.AddSignal(AutoApproveShell, "bypass-permissions mode was accepted on this machine (skipDangerousModePermissionPrompt): sessions can run every tool without asking")
	}
	allow := strs(f.Attrs["allow"])
	if shell := filter(allow, isShellAll); len(shell) > 0 {
		f.AddSignal(AutoApproveShell, fmt.Sprintf("allow rule %s runs any shell command without asking", quoteList(shell)))
	}
	if broad := filter(allow, isBroad); len(broad) > 0 {
		f.AddSignal(BroadAllow, fmt.Sprintf("allow rule %s pre-approves the whole tool", quoteList(broad)))
	}
}

func extension(f *finding.Finding) {
	if t, _ := f.Attrs["hook_type"].(string); t == "command" {
		cmd, _ := f.Attrs["command"].(string)
		event, _ := f.Attrs["event"].(string)
		f.AddSignal(HookRunsCommand, fmt.Sprintf("runs %q on %s", firstLine(cmd, 100), event))
	}
	allowed := strs(f.Attrs["allowed_tools"])
	if shell := filter(allowed, isShellAll); len(shell) > 0 {
		f.AddSignal(AutoApproveShell, fmt.Sprintf("pre-approves %s while it is active", quoteList(shell)))
	}
	if broad := filter(allowed, isBroad); len(broad) > 0 {
		f.AddSignal(BroadAllow, fmt.Sprintf("pre-approves %s while it is active", quoteList(broad)))
	}
}

func mcp(f *finding.Finding) {
	if pinned, ok := f.Attrs["pinned"].(bool); ok && !pinned {
		launcher, _ := f.Attrs["launcher"].(string)
		pkg, _ := f.Attrs["package"].(string)
		f.AddSignal(MCPUnpinned, fmt.Sprintf("%s runs %s without a pinned version: each start may fetch different code", launcher, pkg))
	}
	creds := append(parse.SensitiveNames(strs(f.Attrs["env_names"])), parse.SensitiveNames(strs(f.Attrs["header_names"]))...)
	sort.Strings(creds)
	if len(creds) > 0 {
		f.AddSignal(SecretInMCPEnv, "given "+strings.Join(creds, ", "))
	}
}

// isShellAll: a rule that lets the agent run any shell command.
func isShellAll(rule string) bool {
	switch strings.ReplaceAll(rule, " ", "") {
	case "*", "Bash", "Bash(*)", "Bash(:*)", "Bash(**)", "Bash(*:*)", "PowerShell", "PowerShell(*)":
		return true
	}
	return false
}

// isBroad: a rule that pre-approves a whole tool rather than specific uses.
func isBroad(rule string) bool {
	r := strings.ReplaceAll(rule, " ", "")
	if isShellAll(r) || r == "mcp__*" {
		return true
	}
	switch r {
	case "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch":
		return true
	}
	for _, suffix := range []string{"(*)", "(:*)", "(**)", "(//**)"} {
		if strings.HasSuffix(r, suffix) && !strings.HasPrefix(r, "Read(") && !strings.HasPrefix(r, "Glob(") && !strings.HasPrefix(r, "Grep(") {
			return true
		}
	}
	return false
}

func strs(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func filter(in []string, keep func(string) bool) []string {
	var out []string
	for _, s := range in {
		if keep(s) {
			out = append(out, s)
		}
	}
	return out
}

func quoteList(in []string) string {
	q := make([]string, len(in))
	for i, s := range in {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ", ")
}

// firstLine shortens a command for a reason: its first line, at most n runes.
func firstLine(s string, n int) string {
	line, rest, _ := strings.Cut(strings.TrimSpace(s), "\n")
	r := []rune(line)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	if rest != "" {
		return line + " …"
	}
	return line
}
