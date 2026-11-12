package collect

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/authsec-ai/authsec-cli/internal/catalogue"
	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/fsread"
	"github.com/authsec-ai/authsec-cli/internal/parse"
)

// jsonTool is an agent whose configuration is JSON files holding an MCP
// server map and, optionally, permission settings. Cursor, Gemini CLI, VS
// Code, Claude Desktop and Windsurf all fit.
type jsonTool struct {
	tool, name string
	binary     string   // looked up on PATH for the agent finding
	user       []string // catalogue ids read once
	project    []string // catalogue ids read per project
	mcpKeys    []string // object keys holding MCP servers
	// policy turns a settings file into policy attributes; nil or an empty
	// result adds no policy finding.
	policy func(m map[string]any) map[string]any
}

func (t jsonTool) Tool() string        { return t.tool }
func (t jsonTool) DisplayName() string { return t.name }

func (t jsonTool) Collect(env *Env, out *Out) {
	var seen []string
	read := func(id, project string) {
		e := catalogue.Lookup(id)
		for _, p := range e.Resolve(env.Cat, project) {
			m, f, ok := readJSONC(env, out, t.tool, id, e.Scope, p, project)
			if !ok {
				continue
			}
			seen = append(seen, p)
			for _, k := range t.mcpKeys {
				mcpServers(out, t.tool, id, e.Scope, f, parse.Map(m, k), project)
			}
			if t.policy != nil {
				if attrs := t.policy(m); len(attrs) > 0 {
					out.Add(finding.Finding{Kind: finding.Policy, Tool: t.tool, Name: "permissions", Scope: e.Scope,
						Path: f.Path, Project: project, Rule: id, FileSHA256: f.SHA256, Attrs: attrs})
				}
			}
		}
	}
	for _, id := range t.user {
		read(id, "")
	}
	for _, proj := range env.Projects {
		for _, id := range t.project {
			read(id, proj)
		}
	}
	addAgent(env, out, t.tool, t.name, t.binary, seen)
}

// addAgent records that a tool is set up on this machine.
func addAgent(env *Env, out *Out, tool, name, binary string, seen []string) {
	if len(seen) == 0 {
		return
	}
	attrs := map[string]any{"config_files": len(seen)}
	if binary != "" && env.LookPath != nil {
		if bin := env.LookPath(binary); bin != "" {
			attrs["binary"] = bin
		}
	}
	out.Add(finding.Finding{Kind: finding.Agent, Tool: tool, Name: name, Scope: finding.ScopeUser,
		Path: filepath.Dir(seen[0]), Rule: tool + ".presence", Attrs: attrs})
}

// mcpServers adds one finding per server in an MCP server map.
func mcpServers(out *Out, tool, rule, scope string, f *fsread.File, servers map[string]any, project string) {
	for _, name := range parse.Names(servers) {
		s, _ := servers[name].(map[string]any)
		out.Add(finding.Finding{Kind: finding.MCPServer, Tool: tool, Name: name, Scope: scope,
			Path: f.Path, Project: project, Rule: rule, FileSHA256: f.SHA256, Attrs: mcpAttrs(s)})
	}
}

var (
	cursor = jsonTool{tool: "cursor", name: "Cursor", binary: "cursor-agent",
		user: []string{"cursor.mcp.user", "cursor.cli.user"}, project: []string{"cursor.mcp.project", "cursor.cli.project"},
		mcpKeys: []string{"mcpServers"}, policy: allowDenyPolicy}

	gemini = jsonTool{tool: "gemini-cli", name: "Gemini CLI", binary: "gemini",
		user:    []string{"gemini.settings.user", "gemini.settings.managed", "gemini.settings.managed.darwin", "gemini.settings.managed.windows"},
		project: []string{"gemini.settings.project"}, mcpKeys: []string{"mcpServers"}, policy: geminiPolicy}

	vscode = jsonTool{tool: "vscode", name: "VS Code (Copilot, MCP)", binary: "code",
		user:    []string{"vscode.settings.user", "vscode.settings.user.darwin", "vscode.mcp.user", "vscode.mcp.user.darwin"},
		project: []string{"vscode.mcp.project"}, mcpKeys: []string{"servers"}, policy: vscodePolicy}

	claudeDesktop = jsonTool{tool: "claude-desktop", name: "Claude Desktop",
		user: []string{"claude-desktop.config", "claude-desktop.config.darwin"}, mcpKeys: []string{"mcpServers"}}

	windsurf = jsonTool{tool: "windsurf", name: "Windsurf", binary: "windsurf",
		user: []string{"windsurf.mcp.user"}, mcpKeys: []string{"mcpServers"}}
)

// allowDenyPolicy reads {"permissions": {"allow": [...], "deny": [...]}}
// (Cursor CLI).
func allowDenyPolicy(m map[string]any) map[string]any {
	perms := parse.Map(m, "permissions")
	attrs := map[string]any{}
	if v := scrubAll(parse.Strings(perms, "allow")); len(v) > 0 {
		attrs["allow"] = v
	}
	if v := scrubAll(parse.Strings(perms, "deny")); len(v) > 0 {
		attrs["deny"] = v
	}
	return attrs
}

// geminiPolicy reads the tool lists and approval mode, in both the nested
// (tools.*) and the older flat layout.
func geminiPolicy(m map[string]any) map[string]any {
	attrs := map[string]any{}
	tools := parse.Map(m, "tools")
	pick := func(nested, flat string) []string {
		if v := parse.Strings(tools, nested); len(v) > 0 {
			return scrubAll(v)
		}
		return scrubAll(parse.Strings(m, flat))
	}
	if v := pick("allowed", "allowedTools"); len(v) > 0 {
		attrs["allow"] = v
	}
	if v := pick("exclude", "excludeTools"); len(v) > 0 {
		attrs["deny"] = v
	}
	if v := pick("core", "coreTools"); len(v) > 0 {
		attrs["core_tools"] = v
	}
	if v, ok := parse.Bool(tools, "autoAccept"); ok {
		attrs["auto_accept_safe_tools"] = v
	} else if v, ok := parse.Bool(m, "autoAccept"); ok {
		attrs["auto_accept_safe_tools"] = v
	}
	mode := parse.String(parse.Map(m, "general"), "defaultApprovalMode")
	if mode == "" {
		mode = parse.String(tools, "approvalMode")
	}
	if mode != "" {
		attrs["approval_mode"] = mode
		if strings.EqualFold(mode, "yolo") {
			attrs["auto_approve"] = true
			attrs["auto_approve_reason"] = "approval mode is yolo: every tool, shell included, runs without asking"
		}
	}
	if v, ok := parse.Bool(parse.Map(m, "security"), "disableYoloMode"); ok {
		attrs["disable_yolo_mode"] = v
	}
	return attrs
}

// vscodePolicy reads only the chat tool approval settings of VS Code's
// settings.json; nothing else in the file is kept.
func vscodePolicy(m map[string]any) map[string]any {
	attrs := map[string]any{}
	for _, k := range []string{"chat.tools.global.autoApprove", "chat.tools.autoApprove"} {
		if v, ok := parse.Bool(m, k); ok {
			attrs["global_auto_approve"] = v
			if v {
				attrs["auto_approve"] = true
				attrs["auto_approve_reason"] = k + " is on: Copilot agent mode runs every tool, terminal included, without asking"
			}
		}
	}
	terminal := parse.Map(m, "chat.tools.terminal.autoApprove")
	if len(terminal) == 0 {
		terminal = parse.Map(m, "github.copilot.chat.agent.terminal.allowList")
	}
	var allow, deny []string
	for _, k := range parse.Names(terminal) {
		v, _ := terminal[k].(bool)
		rule := "Terminal(" + parse.Text(k) + ")"
		if v {
			allow = append(allow, rule)
			if k == "/.*/" || k == "/.+/" || k == "*" {
				attrs["auto_approve"] = true
				attrs["auto_approve_reason"] = fmt.Sprintf("terminal auto-approve rule %q matches every command", k)
			}
		} else {
			deny = append(deny, rule)
		}
	}
	if len(allow) > 0 {
		attrs["allow"] = allow
	}
	if len(deny) > 0 {
		attrs["deny"] = deny
	}
	return attrs
}

// Codex reads ~/.codex/config.toml and project .codex/config.toml.
type Codex struct{}

func (Codex) Tool() string        { return "codex" }
func (Codex) DisplayName() string { return "Codex" }

// KnownProjects lists the projects Codex has a trust setting for.
func (Codex) KnownProjects(env *Env) []string {
	e := catalogue.Lookup("codex.config.user")
	var out []string
	for _, p := range e.Resolve(env.Cat, "") {
		f, err := env.Reader.ReadFile(p)
		if err != nil {
			continue
		}
		var m map[string]any
		if _, err := toml.Decode(string(f.Data), &m); err != nil {
			continue
		}
		out = append(out, parse.Names(parse.Map(m, "projects"))...)
	}
	return out
}

func (c Codex) Collect(env *Env, out *Out) {
	var seen []string
	read := func(id, project string) {
		e := catalogue.Lookup(id)
		for _, p := range e.Resolve(env.Cat, project) {
			f, err := env.Reader.ReadFile(p)
			if err != nil {
				if !fsread.IsNotExist(err) {
					out.Unreadable(c.Tool(), id, e.Scope, p, project, err)
				}
				continue
			}
			var m map[string]any
			if _, err := toml.Decode(string(f.Data), &m); err != nil {
				out.Unreadable(c.Tool(), id, e.Scope, p, project, fmt.Errorf("not valid TOML"))
				continue
			}
			seen = append(seen, p)
			c.config(out, id, e.Scope, f, m, project)
		}
	}
	read("codex.config.user", "")
	for _, proj := range env.Projects {
		read("codex.config.project", proj)
	}
	addAgent(env, out, c.Tool(), c.DisplayName(), "codex", seen)
}

func (c Codex) config(out *Out, rule, scope string, f *fsread.File, m map[string]any, project string) {
	add := func(name string, attrs map[string]any, proj string) {
		if len(attrs) > 0 {
			out.Add(finding.Finding{Kind: finding.Policy, Tool: c.Tool(), Name: name, Scope: scope,
				Path: f.Path, Project: proj, Rule: rule, FileSHA256: f.SHA256, Attrs: attrs})
		}
	}
	add("permissions", codexPolicy(m), project)
	profiles := parse.Map(m, "profiles")
	for _, name := range parse.Names(profiles) {
		pm, _ := profiles[name].(map[string]any)
		add("profile "+name, codexPolicy(pm), project)
	}
	projects := parse.Map(m, "projects")
	for _, proj := range parse.Names(projects) {
		pm, _ := projects[proj].(map[string]any)
		if trust := parse.String(pm, "trust_level"); trust != "" {
			add("project trust", map[string]any{"trust_level": trust}, proj)
		}
	}
	servers := parse.Map(m, "mcp_servers")
	for _, name := range parse.Names(servers) {
		s, _ := servers[name].(map[string]any)
		attrs := mcpAttrs(s)
		// Codex names env vars to pass through and a bearer token variable.
		names := strs(attrs["env_names"])
		names = append(names, parse.Strings(s, "env_vars")...)
		if v := parse.String(s, "bearer_token_env_var"); v != "" {
			names = append(names, v)
		}
		if len(names) > 0 {
			sort.Strings(names)
			attrs["env_names"] = names
		}
		if h := parse.Names(parse.Map(s, "http_headers")); len(h) > 0 {
			attrs["header_names"] = h
		}
		if v, ok := parse.Bool(s, "enabled"); ok {
			attrs["disabled"] = !v
		}
		out.Add(finding.Finding{Kind: finding.MCPServer, Tool: c.Tool(), Name: name, Scope: scope,
			Path: f.Path, Project: project, Rule: rule, FileSHA256: f.SHA256, Attrs: attrs})
	}
}

func codexPolicy(m map[string]any) map[string]any {
	attrs := map[string]any{}
	approval := parse.String(m, "approval_policy")
	sandbox := parse.String(m, "sandbox_mode")
	if approval != "" {
		attrs["approval_policy"] = approval
	}
	if sandbox != "" {
		attrs["sandbox_mode"] = sandbox
	}
	if v, ok := parse.Bool(parse.Map(m, "sandbox_workspace_write"), "network_access"); ok {
		attrs["sandbox_network_access"] = v
	}
	switch {
	case sandbox == "danger-full-access" && approval == "never":
		attrs["auto_approve"] = true
		attrs["auto_approve_reason"] = "approval_policy is never and sandbox_mode is danger-full-access: any command runs without asking and without a sandbox"
	case approval == "never":
		attrs["auto_approve"] = true
		attrs["auto_approve_reason"] = fmt.Sprintf("approval_policy is never: commands run without asking (sandbox: %s)", orDefault(sandbox, "default"))
	}
	return attrs
}

func strs(v any) []string {
	switch x := v.(type) {
	case []string:
		return append([]string(nil), x...)
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
