// Package detect finds offensive AI agents: ARTEX (an open-source LLM
// pentest agent, github.com/BaaRai/ARTEX), agents that run offensive security
// tools, and agents that connect to many destinations quickly (scanning).
//
// Rules see names, paths, ports and flag names only. Evidence never carries
// argument values, environment values or file contents.
package detect

import (
	"fmt"
	"strings"
)

// Rule ids.
const (
	RuleARTEX         = "artex_present"
	RuleOffensiveTool = "offensive_tool"
	RuleFanOut        = "connection_fanout"
)

// Severities.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Detection is one rule match.
type Detection struct {
	Rule     string
	Severity string // high | medium | low
	Title    string
	PID      int
	AgentID  string
	Evidence []string
}

// Process is what a rule sees of one process.
type Process struct {
	PID, PPID int
	Comm, Exe string
	Args      []string // raw argv; only flag names are ever read
	EnvNames  []string // names only, never values
	Listen    []int    // TCP ports it listens on
}

// RuleInfo describes a rule.
type RuleInfo struct {
	ID, Title, Severity, Description string
}

// Rules lists the rules of this package.
func Rules() []RuleInfo {
	return []RuleInfo{
		{ID: RuleARTEX, Title: "ARTEX AI pentest agent present", Severity: High,
			Description: "A process or container of ARTEX, an autonomous LLM penetration testing agent: binary artex, ARTEX_* environment variables, its jwt.key, data/ and skills/ next to the binary, or its compose containers. Listening on 8787 (web UI) or 8788 (traffic proxy) counts only with another indicator."},
		{ID: RuleOffensiveTool, Title: "Agent ran an offensive security tool", Severity: High,
			Description: "An AI agent started a scanner, fuzzer, password cracker, exploitation framework or tunnelling tool (nmap, sqlmap, nuclei, ffuf, hydra, msfconsole, chisel and others), directly or through sudo, env, timeout, a shell or an interpreter."},
		{ID: RuleFanOut, Title: "Agent connected to many destinations quickly", Severity: Medium,
			Description: "An AI agent connected to many distinct ip:port destinations within a short window, as a port or host scan does."},
	}
}

// joinCapped joins up to max items and says how many more there were.
func joinCapped(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:max], ", "), len(items)-max)
}

// baseName returns the last element of a Unix or Windows path, lowercased,
// without a trailing ".exe".
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	p = strings.ToLower(p)
	return strings.TrimSuffix(p, ".exe")
}
