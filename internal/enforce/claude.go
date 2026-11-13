package enforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/authsec-ai/authsec-cli/internal/policy"
)

// Claude Code PreToolUse hook (code.claude.com/docs hooks; see
// docs/notes/enforcement-formats.md). The hook reads one JSON object on
// stdin and answers with hookSpecificOutput.permissionDecision. It is
// installed with "onFailure": "block": if it crashes or times out, the tool
// call is blocked, never let through.

// HookInput is the part of the PreToolUse input the policy needs.
type HookInput struct {
	SessionID      string         `json:"session_id"`
	Cwd            string         `json:"cwd"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	PermissionMode string         `json:"permission_mode"`
}

// HookDecision is the policy's answer for one tool call.
type HookDecision struct {
	policy.Decision
	Kind string // command, web, file, mcp, or "" when no rule applies
	What string
}

// fileTools are the tools that touch one path, and whether they write.
var fileTools = map[string]bool{"Read": false, "NotebookRead": false, "Edit": true, "MultiEdit": true, "Write": true, "NotebookEdit": true}

// DecideClaudeTool applies a policy to one Claude Code tool call. home and
// the project (the git root of the call's cwd, else the cwd) fill in
// {home} and {project}.
func DecideClaudeTool(p *policy.Policy, in HookInput, home string) HookDecision {
	allow := HookDecision{Decision: policy.Decision{Action: policy.Allow, Rule: "no rule for this tool"}}
	project := ProjectRoot(in.Cwd)
	ep := p.Expand(home, project)
	str := func(k string) string { s, _ := in.ToolInput[k].(string); return s }
	switch {
	case in.ToolName == "Monitor":
		if ws, ok := in.ToolInput["ws"].(map[string]any); ok {
			raw, _ := ws["url"].(string)
			return decideURL(ep, raw, "web")
		}
		cmd := str("command")
		if cmd == "" {
			return HookDecision{Decision: policy.Decision{Action: policy.Deny, Rule: "Monitor call with neither command nor ws"}, Kind: "command"}
		}
		return HookDecision{Decision: ep.DecideCommand(cmd), Kind: "command", What: cmd}
	case in.ToolName == "Bash":
		cmd := str("command")
		if cmd == "" {
			return allow
		}
		return HookDecision{Decision: ep.DecideCommand(cmd), Kind: "command", What: cmd}
	case in.ToolName == "PowerShell":
		// PowerShell is not parsed: with any command rule, it is not let
		// through unseen.
		c := ep.Commands
		if len(c.Deny)+len(c.Ask)+len(c.Allow) > 0 || c.Default == policy.Deny {
			action := policy.Ask
			if c.Default == policy.Deny {
				action = policy.Deny
			}
			return HookDecision{Decision: policy.Decision{Action: action, Rule: "commands (PowerShell is not decided by rule)"}, Kind: "command", What: str("command")}
		}
		return allow
	case in.ToolName == "WebFetch":
		return decideURL(ep, str("url"), "web")
	case strings.HasPrefix(in.ToolName, "mcp__"):
		return HookDecision{Decision: decideMCPTool(ep, in.ToolName), Kind: "mcp", What: in.ToolName}
	}
	if write, ok := fileTools[in.ToolName]; ok {
		path := str("file_path")
		if path == "" {
			path = str("notebook_path")
		}
		if path == "" {
			return allow
		}
		return decidePath(ep, in.Cwd, path, write)
	}
	if in.ToolName == "Grep" || in.ToolName == "Glob" || in.ToolName == "LS" {
		path := str("path")
		if path == "" {
			return allow // the working directory
		}
		return decidePath(ep, in.Cwd, path, false)
	}
	return allow
}

// decidePath decides a file access on the path as given and as resolved
// (symlinks, /proc/<pid>/root, /proc/<pid>/cwd, /dev/fd): both must be
// allowed. System paths are read freely only when they stay system paths.
func decidePath(ep *policy.Policy, cwd, path string, write bool) HookDecision {
	if !filepath.IsAbs(path) && cwd != "" {
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	if magicPath(path) {
		return HookDecision{Decision: policy.Decision{Action: policy.Deny, Rule: "filesystem (paths through /proc/<pid>/root, cwd, fd or /dev/fd are not allowed)"}, Kind: "file", What: path}
	}
	resolved, err := resolvePath(path)
	if err != nil {
		return HookDecision{Decision: policy.Decision{Action: policy.Deny, Rule: "filesystem (the path cannot be resolved: " + err.Error() + ")"}, Kind: "file", What: path}
	}
	if !write && isSystemPath(path) && isSystemPath(resolved) && !magicPath(resolved) {
		return HookDecision{Decision: policy.Decision{Action: policy.Allow, Rule: "system path"}, Kind: "file", What: path}
	}
	d := ep.DecideFile(path, write)
	if resolved != path {
		if r := ep.DecideFile(resolved, write); r.Action != policy.Allow {
			return HookDecision{Decision: policy.Decision{Action: r.Action, Rule: r.Rule + " (via a link to " + resolved + ")"}, Kind: "file", What: path}
		}
	}
	return HookDecision{Decision: d, Kind: "file", What: path}
}

// magicPath: /proc/<pid>/{root,cwd,fd,map_files} and /dev/fd reach any file
// whatever the path says.
func magicPath(p string) bool {
	if within(p, "/dev/fd") || within(p, "/proc/self/fd") || within(p, "/proc/thread-self") {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(parts) >= 3 && parts[0] == "proc" {
		switch parts[2] {
		case "root", "cwd", "fd", "map_files", "exe":
			return true
		}
	}
	return false
}

// resolvePath resolves symlinks of the longest existing prefix and appends
// the rest (a file being created does not exist yet).
func resolvePath(p string) (string, error) {
	rest := ""
	cur := p
	for {
		r, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Clean(filepath.Join(r, rest)), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// decideURL decides a web request: WebFetch upgrades http to https, so
// both are port 443 unless the URL names a port.
func decideURL(ep *policy.Policy, raw, kind string) HookDecision {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return HookDecision{Decision: policy.Decision{Action: policy.Deny, Rule: "network (the URL does not parse)"}, Kind: kind, What: raw}
	}
	port := 443
	switch {
	case u.Port() != "":
		port, _ = strconv.Atoi(u.Port())
	case u.Scheme == "ws":
		port = 80
	}
	host := u.Hostname()
	var ip net.IP
	if ip = net.ParseIP(host); ip != nil {
		host = ""
	}
	return HookDecision{Decision: ep.DecideNetwork(host, ip, port), Kind: kind, What: u.Scheme + "://" + u.Host}
}

// decideMCPTool decides an MCP tool call. Claude Code names tools
// mcp__<server>__<tool>, with the server name normalised (characters other
// than letters, digits, _ and - become _), and plugin servers as
// plugin_<plugin>_<server>: every possible server name is checked, deny
// and ask on any, allow on the server name as written.
func decideMCPTool(ep *policy.Policy, tool string) policy.Decision {
	rest := strings.TrimPrefix(tool, "mcp__")
	parts := strings.Split(rest, "__")
	var cands []string
	for i := 1; i <= len(parts); i++ {
		if i == len(parts) && len(parts) > 1 {
			break // the last part is the tool
		}
		cands = append(cands, strings.Join(parts[:i], "__"))
	}
	if strings.HasPrefix(parts[0], "plugin_") {
		p := strings.TrimPrefix(parts[0], "plugin_")
		for i := 0; i < len(p); i++ {
			if p[i] == '_' && i+1 < len(p) {
				cands = append(cands, p[i+1:])
			}
		}
	}
	norm := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '*' {
				return r
			}
			return '_'
		}, s)
	}
	for i, pat := range ep.MCPServers.Deny {
		for _, c := range cands {
			if policy.GlobMatch(norm(pat), c) {
				return policy.Decision{Action: policy.Deny, Rule: fmt.Sprintf("mcp_servers.deny[%d]", i)}
			}
		}
	}
	for i, pat := range ep.MCPServers.Allow {
		if len(cands) > 0 && policy.GlobMatch(norm(pat), cands[0]) {
			return policy.Decision{Action: policy.Allow, Rule: fmt.Sprintf("mcp_servers.allow[%d]", i)}
		}
	}
	d := ep.MCPServers.Default
	if d == "" {
		d = policy.Allow
	}
	return policy.Decision{Action: d, Rule: "mcp_servers.default"}
}

func isSystemPath(p string) bool {
	for _, s := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc", "/sys", "/dev"} {
		if within(p, s) {
			return true
		}
	}
	return false
}

// ProjectRoot is the git project containing dir, else dir itself.
func ProjectRoot(dir string) string {
	if dir == "" {
		return ""
	}
	for d := filepath.Clean(dir); d != "/" && d != "."; d = filepath.Dir(d) {
		if st, err := os.Stat(filepath.Join(d, ".git")); err == nil && st.IsDir() {
			return d
		}
	}
	return filepath.Clean(dir)
}

// HookOutput is the hook's stdout for a decision in a policy mode. Allowed
// calls (and every call in monitor mode) print nothing, so Claude Code's own
// permission rules still apply.
func HookOutput(d HookDecision, mode string) []byte {
	if mode != policy.Enforce || d.Action == policy.Allow {
		return nil
	}
	reason := fmt.Sprintf("AuthSec policy (%s): %s %s", d.Rule, verb(d), clip(d.What, 200))
	out := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       d.Action, // deny | ask
		"permissionDecisionReason": reason,
	}}
	b, _ := json.Marshal(out)
	return b
}

func verb(d HookDecision) string {
	if d.Action == policy.Ask {
		return "needs approval:"
	}
	switch d.Kind {
	case "command":
		return "does not allow the command"
	case "web":
		return "does not allow connecting to"
	case "mcp":
		return "does not allow the MCP tool"
	case "file":
		return "does not allow access to"
	}
	return "does not allow"
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// ClaudeManagedDir is where Claude Code reads managed settings drop-ins.
func ClaudeManagedDir(goos string) string {
	switch goos {
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.d"
	case "windows":
		return `C:\Program Files\ClaudeCode\managed-settings.d`
	}
	return "/etc/claude-code/managed-settings.d"
}

// ClaudeDropIn is the file authsec-cli owns among the drop-ins.
func ClaudeDropIn() string { return filepath.Join(ClaudeManagedDir(runtime.GOOS), "50-authsec.json") }

var mcpServerName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ClaudeManagedSettings is the drop-in for Claude Code: the PreToolUse hook
// (every tool, fail closed) and, from the claude-code policy, the MCP
// servers Claude Code may load. Notes say what could not be expressed.
func ClaudeManagedSettings(p *policy.Policy, hookCommand string) (map[string]any, []string) {
	var notes []string
	s := map[string]any{
		// "onFailure": "block" needs 2.1.295; older versions would let a
		// failing hook through.
		"requiredMinimumVersion": "2.1.295",
		"hooks": map[string]any{
			"PreToolUse": []any{map[string]any{
				"matcher": "*",
				"hooks": []any{map[string]any{
					"type":      "command",
					"command":   hookCommand,
					"timeout":   15,
					"onFailure": "block",
				}},
			}},
		},
	}
	if p != nil && p.Mode != policy.Enforce {
		notes = append(notes, "the claude-code policy is in monitor mode: the hook logs decisions and blocks nothing, and no MCP lists are set, until mode is enforce (then run this again)")
	}
	if p != nil && p.Mode == policy.Enforce {
		// User and project hooks could run commands the policy does not
		// see: in enforce mode only managed hooks (this one) run.
		s["allowManagedHooksOnly"] = true
		notes = append(notes, "only managed hooks run (allowManagedHooksOnly): users' own Claude Code hooks are switched off while the policy is enforced")
		var allowed, denied []any
		for _, n := range p.MCPServers.Deny {
			if !strings.Contains(n, "*") {
				denied = append(denied, map[string]any{"serverName": n})
			} else {
				notes = append(notes, fmt.Sprintf("mcp_servers.deny %q is a pattern: the hook enforces it, Claude Code's MCP list cannot", n))
			}
		}
		if p.MCPServers.Default == policy.Deny {
			allowed = []any{}
			for _, n := range p.MCPServers.Allow {
				if mcpServerName.MatchString(n) {
					allowed = append(allowed, map[string]any{"serverName": n})
				} else {
					notes = append(notes, fmt.Sprintf("mcp_servers.allow %q is a pattern: the hook enforces it, Claude Code's MCP list cannot", n))
				}
			}
			s["allowedMcpServers"] = allowed
			s["allowManagedMcpServersOnly"] = true // users and projects cannot widen the list
			notes = append(notes, "MCP servers are allowed by name only; a server is not pinned to its command or URL")
		}
		if len(denied) > 0 {
			s["deniedMcpServers"] = denied
		}
	}
	notes = append(notes, "if this machine also gets Claude Code settings from the admin console, MDM or the Windows registry, the drop-in applies only when that source sets managedSourcesBehavior: \"merge\" (Claude Code 2.1.242+)")
	return s, notes
}

// SortedKeys is a helper for stable output.
func SortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
