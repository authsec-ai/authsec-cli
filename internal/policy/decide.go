package policy

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

// Decision is the outcome for one action, with the rule that decided it.
type Decision struct {
	Action string `json:"action"` // allow, deny, ask
	Rule   string `json:"rule"`   // e.g. network.deny[0], filesystem.read_only, default
}

// Enforced reports whether a decision blocks in this policy's mode.
func (p *Policy) Enforced(d Decision) bool { return p.Mode == Enforce && d.Action == Deny }

// DecideNetwork decides a connection. host may be empty (unknown name); ip
// may be nil (name only, e.g. when checking a policy).
func (p *Policy) DecideNetwork(host string, ip net.IP, port int) Decision {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for i, r := range p.Network.Deny {
		if r.matches(host, ip, port) {
			return Decision{Deny, fmt.Sprintf("network.deny[%d]", i)}
		}
	}
	for i, r := range p.Network.Allow {
		if r.matches(host, ip, port) {
			return Decision{Allow, fmt.Sprintf("network.allow[%d]", i)}
		}
	}
	return Decision{orAllow(p.Network.Default), "network.default"}
}

func (r Rule) matches(host string, ip net.IP, port int) bool {
	if r.Port != 0 && r.Port != port {
		return false
	}
	if r.Host != "" {
		return HostMatches(r.Host, host)
	}
	if r.CIDR != "" && ip != nil {
		_, n, err := net.ParseCIDR(r.CIDR)
		return err == nil && n.Contains(ip)
	}
	return false
}

// HostMatches matches a host against a pattern: exact, or "*.example.com"
// for example.com's subdomains (not example.com itself).
func HostMatches(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	if host == "" {
		return false
	}
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

// DecideFile decides a file access. Paths must be expanded (Expand).
// System paths (libraries, /proc, /dev) are not decided here: callers skip
// them as the sensor does.
func (p *Policy) DecideFile(path string, write bool) Decision {
	path = filepath.Clean(path)
	for i, d := range p.Filesystem.Deny {
		if under(path, d) {
			return Decision{Deny, fmt.Sprintf("filesystem.deny[%d]", i)}
		}
	}
	for i, rw := range p.Filesystem.ReadWrite {
		if under(path, rw) {
			return Decision{Allow, fmt.Sprintf("filesystem.read_write[%d]", i)}
		}
	}
	for i, ro := range p.Filesystem.ReadOnly {
		if under(path, ro) {
			if write {
				return Decision{Deny, fmt.Sprintf("filesystem.read_only[%d] (read only)", i)}
			}
			return Decision{Allow, fmt.Sprintf("filesystem.read_only[%d]", i)}
		}
	}
	if len(p.Filesystem.ReadWrite) == 0 && len(p.Filesystem.ReadOnly) == 0 && !p.confined {
		return Decision{Allow, "filesystem (no path lists)"}
	}
	return Decision{Deny, "filesystem (outside read_write and read_only)"}
}

// under reports whether path is dir or inside it.
func under(path, dir string) bool {
	dir = strings.TrimSuffix(filepath.Clean(dir), "/")
	path = filepath.Clean(path)
	return path == dir || strings.HasPrefix(path, dir+"/") || dir == ""
}

// DecideCommand decides a shell command line, per simple command (see
// shell.go): any part denied denies the line, any part needing approval
// asks, and the line is allowed by rule only if every part is. A line that
// does not parse is never allowed by rule.
func (p *Policy) DecideCommand(cmdline string) Decision {
	pl, ok := parseLine(cmdline)
	if !ok {
		return p.unparsed()
	}
	return p.decideParsed(pl)
}

// DecideMCP decides whether an MCP server may be loaded.
func (p *Policy) DecideMCP(name string) Decision {
	for i, pat := range p.MCPServers.Deny {
		if GlobMatch(pat, name) {
			return Decision{Deny, fmt.Sprintf("mcp_servers.deny[%d]", i)}
		}
	}
	for i, pat := range p.MCPServers.Allow {
		if GlobMatch(pat, name) {
			return Decision{Allow, fmt.Sprintf("mcp_servers.allow[%d]", i)}
		}
	}
	return Decision{orAllow(p.MCPServers.Default), "mcp_servers.default"}
}

func orAllow(v string) string {
	if v == "" {
		return Allow
	}
	return v
}

// GlobMatch matches text against a pattern where '*' is any run of
// characters (spaces included), '\*' is a literal '*', and everything else
// is literal. Runs of whitespace in either compare as one space.
func GlobMatch(pattern, text string) bool { return globMatch(pattern, text, false) }

// globMatch is GlobMatch, optionally ignoring ASCII case.
func globMatch(pattern, text string, fold bool) bool {
	pattern = strings.Join(strings.Fields(pattern), " ")
	text = strings.Join(strings.Fields(text), " ")
	if fold {
		pattern, text = strings.ToLower(pattern), strings.ToLower(text)
	}
	// Tokens: -1 is a wildcard, anything else a literal byte.
	toks := make([]int, 0, len(pattern))
	for i := 0; i < len(pattern); i++ {
		switch {
		case pattern[i] == '\\' && i+1 < len(pattern) && pattern[i+1] == '*':
			toks = append(toks, '*')
			i++
		case pattern[i] == '*':
			toks = append(toks, -1)
		default:
			toks = append(toks, int(pattern[i]))
		}
	}
	// Iterative match, backtracking to the last wildcard: O(len(p)*len(t)).
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(text) {
		switch {
		case p < len(toks) && toks[p] == -1:
			star, mark = p, t
			p++
		case p < len(toks) && toks[p] == int(text[t]):
			p++
			t++
		case star >= 0:
			p = star + 1
			mark++
			t = mark
		default:
			return false
		}
	}
	for p < len(toks) && toks[p] == -1 {
		p++
	}
	return p == len(toks)
}

// ModelHosts are the model APIs known agents need. Generated policies always
// allow them, and a check warns when an enforced policy blocks them.
var ModelHosts = map[string][]string{
	"claude-code":    {"api.anthropic.com"},
	"claude-desktop": {"api.anthropic.com", "claude.ai"},
	"codex":          {"api.openai.com", "chatgpt.com"},
	"gemini-cli":     {"generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com"},
	"copilot":        {"api.githubcopilot.com", "api.individual.githubcopilot.com", "api.business.githubcopilot.com", "api.enterprise.githubcopilot.com"},
	"vscode":         {"api.githubcopilot.com", "api.individual.githubcopilot.com", "api.business.githubcopilot.com", "api.enterprise.githubcopilot.com"},
	"cursor":         {"api2.cursor.sh"},
	"cursor-agent":   {"api2.cursor.sh"},
	"windsurf":       {"server.codeium.com"},
}
