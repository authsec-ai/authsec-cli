package collect

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/authsec-ai/authsec-cli/internal/catalogue"
	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/fsread"
	"github.com/authsec-ai/authsec-cli/internal/parse"
)

const claudeTool = "claude-code"

// Claude reads Claude Code's settings, MCP servers and extensions.
// Reference: https://docs.anthropic.com/en/docs/claude-code/settings
type Claude struct{}

func (Claude) Tool() string        { return claudeTool }
func (Claude) DisplayName() string { return "Claude Code" }

var claudeManaged = []string{
	"claude.settings.managed", "claude.settings.managed.darwin", "claude.settings.managed.windows",
}

var claudeManagedMCP = []string{
	"claude.mcp.managed", "claude.mcp.managed.darwin", "claude.mcp.managed.windows",
}

// KnownProjects lists the projects ~/.claude.json has entries for.
func (Claude) KnownProjects(env *Env) []string {
	var out []string
	for _, p := range catalogue.Lookup("claude.state").Resolve(env.Cat, "") {
		f, err := env.Reader.ReadFile(p)
		if err != nil {
			continue
		}
		m, err := parse.JSONC(f.Data)
		if err != nil {
			continue
		}
		for proj := range parse.Map(m, "projects") {
			out = append(out, proj)
		}
	}
	sort.Strings(out)
	return out
}

func (c Claude) Collect(env *Env, out *Out) {
	before := len(out.Findings)
	var seen []string // configuration that shows Claude Code is set up here

	// User and managed settings.
	for _, id := range append([]string{"claude.settings.user"}, claudeManaged...) {
		e := catalogue.Lookup(id)
		for _, p := range e.Resolve(env.Cat, "") {
			if m, f, ok := readJSONC(env, out, claudeTool, id, e.Scope, p, ""); ok {
				seen = append(seen, p)
				c.settings(out, id, e.Scope, f, m, "")
			}
		}
	}

	// ~/.claude.json: user MCP servers and per-project state. Nothing else in
	// the file is read (it also holds account details).
	e := catalogue.Lookup("claude.state")
	for _, p := range e.Resolve(env.Cat, "") {
		m, f, ok := readJSONC(env, out, claudeTool, e.ID, e.Scope, p, "")
		if !ok {
			continue
		}
		seen = append(seen, p)
		c.mcpServers(out, e.ID, finding.ScopeUser, f, parse.Map(m, "mcpServers"), "")
		projects := parse.Map(m, "projects")
		names := parse.Names(projects)
		for _, proj := range names {
			pm, _ := projects[proj].(map[string]any)
			c.mcpServers(out, e.ID, finding.ScopeLocal, f, parse.Map(pm, "mcpServers"), proj)
			if allow := parse.Strings(pm, "allowedTools"); len(allow) > 0 {
				out.Add(finding.Finding{
					Kind: finding.Policy, Tool: claudeTool, Name: "allowed tools", Scope: finding.ScopeLocal,
					Path: f.Path, Project: proj, Rule: e.ID, FileSHA256: f.SHA256,
					Attrs: map[string]any{"allow": scrubAll(allow)},
				})
			}
		}
	}

	// Managed MCP servers.
	for _, id := range claudeManagedMCP {
		e := catalogue.Lookup(id)
		for _, p := range e.Resolve(env.Cat, "") {
			if m, f, ok := readJSONC(env, out, claudeTool, id, e.Scope, p, ""); ok {
				seen = append(seen, p)
				c.mcpServers(out, id, e.Scope, f, parse.Map(m, "mcpServers"), "")
			}
		}
	}

	// User extensions.
	if c.extensions(env, out, "user", "") {
		seen = append(seen, filepath.Join(env.Cat.Home, ".claude"))
	}

	// Per project.
	for _, proj := range env.Projects {
		for _, id := range []string{"claude.settings.project", "claude.settings.local"} {
			e := catalogue.Lookup(id)
			for _, p := range e.Resolve(env.Cat, proj) {
				if m, f, ok := readJSONC(env, out, claudeTool, id, e.Scope, p, proj); ok {
					seen = append(seen, p)
					c.settings(out, id, e.Scope, f, m, proj)
				}
			}
		}
		e := catalogue.Lookup("claude.mcp.project")
		for _, p := range e.Resolve(env.Cat, proj) {
			if m, f, ok := readJSONC(env, out, claudeTool, e.ID, e.Scope, p, proj); ok {
				seen = append(seen, p)
				c.mcpServers(out, e.ID, e.Scope, f, parse.Map(m, "mcpServers"), proj)
			}
		}
		if c.extensions(env, out, "project", proj) {
			seen = append(seen, filepath.Join(proj, ".claude"))
		}
	}

	if len(seen) == 0 && len(out.Findings) == before {
		return
	}
	agent := finding.Finding{
		Kind: finding.Agent, Tool: claudeTool, Name: c.DisplayName(), Scope: finding.ScopeUser,
		Path: filepath.Join(env.Cat.Home, ".claude"), Rule: "claude.presence",
		Attrs: map[string]any{"config_files": len(seen)},
	}
	if env.LookPath != nil {
		if bin := env.LookPath("claude"); bin != "" {
			agent.Attrs["binary"] = bin
		}
	}
	out.Add(agent)
}

// settings turns one settings file into a policy finding and one extension
// finding per hook.
func (c Claude) settings(out *Out, rule, scope string, f *fsread.File, m map[string]any, project string) {
	attrs := map[string]any{}
	perms := parse.Map(m, "permissions")
	if v := scrubAll(parse.Strings(perms, "allow")); len(v) > 0 {
		attrs["allow"] = v
	}
	if v := scrubAll(parse.Strings(perms, "deny")); len(v) > 0 {
		attrs["deny"] = v
	}
	if v := scrubAll(parse.Strings(perms, "ask")); len(v) > 0 {
		attrs["ask"] = v
	}
	if v := parse.String(perms, "defaultMode"); v != "" {
		attrs["default_mode"] = v
	}
	if v := parse.String(perms, "disableBypassPermissionsMode"); v != "" {
		attrs["disable_bypass_permissions_mode"] = v
	}
	if v := parse.Strings(perms, "additionalDirectories"); len(v) > 0 {
		attrs["additional_directories"] = v
	}
	if v, ok := parse.Bool(m, "skipDangerousModePermissionPrompt"); ok {
		attrs["skip_dangerous_mode_prompt"] = v
	}
	if v, ok := parse.Bool(parse.Map(m, "sandbox"), "enabled"); ok {
		attrs["sandbox_enabled"] = v
	}
	if v, ok := parse.Bool(m, "enableAllProjectMcpServers"); ok {
		attrs["enable_all_project_mcp_servers"] = v
	}
	if v := parse.Strings(m, "enabledMcpjsonServers"); len(v) > 0 {
		attrs["enabled_mcpjson_servers"] = v
	}
	if v := parse.Strings(m, "disabledMcpjsonServers"); len(v) > 0 {
		attrs["disabled_mcpjson_servers"] = v
	}
	if parse.String(m, "apiKeyHelper") != "" {
		attrs["api_key_helper"] = true // a command that prints a key; only its presence is kept
	}
	if env := parse.Names(parse.Map(m, "env")); len(env) > 0 {
		attrs["env_names"] = env
	}
	out.Add(finding.Finding{
		Kind: finding.Policy, Tool: claudeTool, Name: "permissions", Scope: scope,
		Path: f.Path, Project: project, Rule: rule, FileSHA256: f.SHA256, Attrs: attrs,
	})

	hooks := parse.Map(m, "hooks")
	for _, event := range parse.Names(hooks) {
		groups, _ := hooks[event].([]any)
		for gi, g := range groups {
			gm, _ := g.(map[string]any)
			matcher := parse.String(gm, "matcher")
			list, _ := gm["hooks"].([]any)
			for hi, h := range list {
				hm, _ := h.(map[string]any)
				name := event
				if matcher != "" {
					name += "[" + matcher + "]"
				}
				if len(groups) > 1 || len(list) > 1 {
					name += "#" + strconv.Itoa(gi+1) + "." + strconv.Itoa(hi+1)
				}
				hookAttrs := map[string]any{"type": "hook", "event": event, "hook_type": parse.String(hm, "type")}
				if matcher != "" {
					hookAttrs["matcher"] = matcher
				}
				if cmd := parse.String(hm, "command"); cmd != "" {
					hookAttrs["command"] = parse.Text(cmd)
				}
				out.Add(finding.Finding{
					Kind: finding.Extension, Tool: claudeTool, Name: "hook " + name, Scope: scope,
					Path: f.Path, Project: project, Rule: rule, FileSHA256: f.SHA256, Attrs: hookAttrs,
				})
			}
		}
	}
}

// mcpServers adds one finding per server in an mcpServers object. Env vars
// and headers are kept by name; arguments, URLs and commands are scrubbed.
func (c Claude) mcpServers(out *Out, rule, scope string, f *fsread.File, servers map[string]any, project string) {
	for _, name := range parse.Names(servers) {
		s, _ := servers[name].(map[string]any)
		out.Add(finding.Finding{
			Kind: finding.MCPServer, Tool: claudeTool, Name: name, Scope: scope,
			Path: f.Path, Project: project, Rule: rule, FileSHA256: f.SHA256, Attrs: mcpAttrs(s),
		})
	}
}

// mcpAttrs is the shared MCP server shape (Claude Code, Cursor, Gemini, VS
// Code and Claude Desktop all write command/args/env or url/headers).
func mcpAttrs(s map[string]any) map[string]any {
	attrs := map[string]any{}
	command := parse.String(s, "command")
	args := parse.Args(parse.Strings(s, "args"))
	rawURL := parse.String(s, "url")
	for _, k := range []string{"serverUrl", "httpUrl"} { // Windsurf, Gemini CLI
		if rawURL == "" {
			rawURL = parse.String(s, k)
		}
	}
	transport := parse.String(s, "type")
	if transport == "" {
		if rawURL != "" {
			transport = "http"
		} else {
			transport = "stdio"
		}
	}
	attrs["transport"] = transport
	if command != "" {
		attrs["command"] = parse.Text(command)
	}
	if len(args) > 0 {
		attrs["args"] = args
	}
	if rawURL != "" {
		attrs["url"] = parse.URL(rawURL)
	}
	if names := parse.Names(parse.Map(s, "env")); len(names) > 0 {
		attrs["env_names"] = names
	}
	if names := parse.Names(parse.Map(s, "headers")); len(names) > 0 {
		attrs["header_names"] = names
	}
	if l, ok := analyzeLaunch(command, args); ok {
		attrs["launcher"] = l.Launcher
		attrs["package"] = l.Package
		attrs["pinned"] = l.Pinned
	}
	if v, ok := parse.Bool(s, "disabled"); ok {
		attrs["disabled"] = v
	}
	return attrs
}

// extensions lists skills, sub-agents and commands under ~/.claude or
// <project>/.claude. It reports whether any were found.
func (c Claude) extensions(env *Env, out *Out, scope, project string) bool {
	found := false
	kinds := []struct {
		id, typ string
		depth   int
		match   func(string) bool
	}{
		{"claude.skills." + scope, "skill", 4, func(n string) bool { return n == "SKILL.md" }},
		{"claude.agents." + scope, "sub_agent", 3, isMarkdown},
		{"claude.commands." + scope, "command", 3, isMarkdown},
	}
	for _, k := range kinds {
		e := catalogue.Lookup(k.id)
		for _, dir := range e.Resolve(env.Cat, project) {
			files, err := env.Reader.Walk(dir, k.depth, k.match)
			if err != nil {
				continue
			}
			for _, p := range files {
				f, err := env.Reader.ReadFile(p)
				if err != nil {
					out.Unreadable(claudeTool, k.id, e.Scope, p, project, err)
					continue
				}
				found = true
				fm, err := readFrontMatter(f.Data)
				if err != nil {
					out.Unreadable(claudeTool, k.id, e.Scope, p, project, err)
					continue
				}
				name := fm.Name
				if name == "" {
					if k.typ == "skill" {
						name = filepath.Base(filepath.Dir(p))
					} else {
						rel, _ := filepath.Rel(dir, p)
						name = strings.TrimSuffix(filepath.ToSlash(rel), ".md")
					}
				}
				attrs := map[string]any{"type": k.typ}
				if fm.Description != "" {
					attrs["description"] = fm.Description
				}
				if len(fm.AllowedTools) > 0 {
					attrs["allowed_tools"] = fm.AllowedTools
				}
				if len(fm.Tools) > 0 {
					attrs["tools"] = fm.Tools
				}
				if fm.Model != "" {
					attrs["model"] = fm.Model
				}
				out.Add(finding.Finding{
					Kind: finding.Extension, Tool: claudeTool, Name: k.typ + " " + name, Scope: e.Scope,
					Path: p, Project: project, Rule: k.id, FileSHA256: f.SHA256, Attrs: attrs,
				})
			}
		}
	}
	return found
}

func isMarkdown(n string) bool { return strings.HasSuffix(strings.ToLower(n), ".md") }
