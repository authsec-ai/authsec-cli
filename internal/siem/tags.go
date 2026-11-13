package siem

import (
	"sort"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// OWASP risk tags. IDs and names come from:
//   - OWASP Top 10 for Agentic Applications (OWASP GenAI Security Project,
//     9 December 2025):
//     https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
//   - OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
const (
	asi02 = "owasp-agentic:ASI02-tool-misuse"
	asi03 = "owasp-agentic:ASI03-identity-and-privilege-abuse"
	asi04 = "owasp-agentic:ASI04-agentic-supply-chain-vulnerabilities"
	asi10 = "owasp-agentic:ASI10-rogue-agents"
	llm02 = "owasp-llm:LLM02-sensitive-information-disclosure"
	llm06 = "owasp-llm:LLM06-excessive-agency"
)

// tagRule tags records of a type (and decision kind, "" for any) that are
// blocked (a deny, kill or quarantine decision) when blocked is true.
type tagRule struct {
	typ, kind string
	blocked   bool
	tags      []string
}

var tagRules = []tagRule{
	{events.Decision, "command", true, []string{asi02, llm06}}, // a tool or program the agent may not run
	{events.Decision, "mcp", true, []string{asi02, asi04}},     // an MCP server or tool outside policy
	{events.Decision, "network", true, []string{asi02, llm06}}, // excessive agency, possible exfiltration
	{events.Decision, "web", true, []string{asi02, llm06}},     // same, through the agent's web fetch tool
	{events.Decision, "file", true, []string{llm06}},           // a file outside the agent's scope
	{events.Decision, "agent", true, []string{asi10}},          // an agent quarantined or stopped
	{events.Detection, "", false, []string{asi10}},             // ARTEX, offensive agents
}

// Tags returns the compliance tags of r: OWASP agentic and LLM risk IDs
// and "authsec:<type>". Reading a credential or other sensitive file adds
// sensitive information disclosure and identity and privilege abuse.
func Tags(r events.Record) []string {
	set := map[string]bool{"authsec:" + r.Type: true}
	blocked := r.Action == "deny" || r.Action == "kill" || r.Action == "quarantine"
	for _, t := range tagRules {
		if t.typ != r.Type || (t.kind != "" && t.kind != r.Kind) || (t.blocked && !blocked) {
			continue
		}
		for _, tag := range t.tags {
			set[tag] = true
		}
	}
	if r.Sensitive && (r.Type == events.File || (r.Type == events.Decision && r.Kind == "file")) {
		set[llm02], set[asi03] = true, true
	}
	out := make([]string, 0, len(set))
	for tag := range set {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}
