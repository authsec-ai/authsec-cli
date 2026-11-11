// Package catalogue is the fixed list of files authsec-cli reads, per tool and
// operating system. Collectors find paths only through it, so `authsec-cli
// catalogue` is a complete account of what a scan opens. Changing what is read
// means changing this list and its Version.
package catalogue

import (
	"path/filepath"
	"strings"
)

// Version is the coverage claim a report carries. Bump it with every change
// to Entries.
const Version = "2026.11.0"

// Env holds the directories path templates expand to. Tests point every one
// of them into a fixture tree.
type Env struct {
	GOOS        string
	Home        string // the user's home directory
	ConfigHome  string // Linux $XDG_CONFIG_HOME (default {home}/.config)
	AppData     string // Windows %APPDATA%
	ProgramData string // Windows %ProgramData%
	ProgramFile string // Windows %ProgramFiles%
	SysRoot     string // prefix for absolute system paths ("" in real use)
}

// Entry is one file or directory a collector may read.
type Entry struct {
	ID    string   // stable id collectors ask for
	Tool  string   // tool id, e.g. claude-code
	What  string   // what is taken from it, for `authsec-cli catalogue`
	Scope string   // user, project, local, managed
	Dir   bool     // a directory whose files are listed
	OS    []string // empty: every OS
	Paths []string // templates: {home} {config} {appdata} {programdata} {programfiles} {project}, /abs (under SysRoot)
}

// PerProject reports whether the entry is read once per project.
func (e Entry) PerProject() bool {
	for _, p := range e.Paths {
		if strings.Contains(p, "{project}") {
			return true
		}
	}
	return false
}

// On reports whether the entry applies to goos.
func (e Entry) On(goos string) bool {
	if len(e.OS) == 0 {
		return true
	}
	for _, o := range e.OS {
		if o == goos {
			return true
		}
	}
	return false
}

// Resolve expands the entry's paths for env and, for per-project entries, one
// project. It returns nothing when the entry does not apply to env.GOOS.
func (e Entry) Resolve(env Env, project string) []string {
	if !e.On(env.GOOS) {
		return nil
	}
	var out []string
	for _, t := range e.Paths {
		p := t
		repl := map[string]string{
			"{home}": env.Home, "{config}": env.ConfigHome, "{appdata}": env.AppData,
			"{programdata}": env.ProgramData, "{programfiles}": env.ProgramFile, "{project}": project,
		}
		skip := false
		for k, v := range repl {
			if strings.Contains(p, k) {
				if v == "" {
					skip = true
				}
				p = strings.ReplaceAll(p, k, v)
			}
		}
		if skip {
			continue
		}
		if strings.HasPrefix(t, "/") {
			p = env.SysRoot + p
		}
		out = append(out, filepath.FromSlash(p))
	}
	return out
}

// Lookup returns the entry with id. It panics on an unknown id: that is a
// programming error a test catches, not a runtime condition.
func Lookup(id string) Entry {
	for _, e := range Entries() {
		if e.ID == id {
			return e
		}
	}
	panic("catalogue: unknown entry " + id)
}

// Entries is the catalogue.
func Entries() []Entry {
	return []Entry{
		// Claude Code: https://docs.anthropic.com/en/docs/claude-code/settings
		{ID: "claude.settings.user", Tool: "claude-code", Scope: "user", What: "permissions, hooks, env names, sandbox", Paths: []string{"{home}/.claude/settings.json"}},
		{ID: "claude.state", Tool: "claude-code", Scope: "user", What: "MCP servers (user and per project), allowed tools per project; nothing else in the file", Paths: []string{"{home}/.claude.json"}},
		{ID: "claude.settings.managed", Tool: "claude-code", Scope: "managed", What: "administrator policy", OS: []string{"linux"}, Paths: []string{"/etc/claude-code/managed-settings.json"}},
		{ID: "claude.settings.managed.darwin", Tool: "claude-code", Scope: "managed", What: "administrator policy", OS: []string{"darwin"}, Paths: []string{"/Library/Application Support/ClaudeCode/managed-settings.json"}},
		{ID: "claude.settings.managed.windows", Tool: "claude-code", Scope: "managed", What: "administrator policy", OS: []string{"windows"}, Paths: []string{"{programfiles}/ClaudeCode/managed-settings.json", "{programdata}/ClaudeCode/managed-settings.json"}},
		{ID: "claude.mcp.managed", Tool: "claude-code", Scope: "managed", What: "administrator MCP servers", OS: []string{"linux"}, Paths: []string{"/etc/claude-code/managed-mcp.json"}},
		{ID: "claude.mcp.managed.darwin", Tool: "claude-code", Scope: "managed", What: "administrator MCP servers", OS: []string{"darwin"}, Paths: []string{"/Library/Application Support/ClaudeCode/managed-mcp.json"}},
		{ID: "claude.mcp.managed.windows", Tool: "claude-code", Scope: "managed", What: "administrator MCP servers", OS: []string{"windows"}, Paths: []string{"{programfiles}/ClaudeCode/managed-mcp.json", "{programdata}/ClaudeCode/managed-mcp.json"}},
		{ID: "claude.settings.project", Tool: "claude-code", Scope: "project", What: "permissions, hooks (shared with the team)", Paths: []string{"{project}/.claude/settings.json"}},
		{ID: "claude.settings.local", Tool: "claude-code", Scope: "local", What: "permissions, hooks (this user only)", Paths: []string{"{project}/.claude/settings.local.json"}},
		{ID: "claude.mcp.project", Tool: "claude-code", Scope: "project", What: "MCP servers (shared with the team)", Paths: []string{"{project}/.mcp.json"}},
		{ID: "claude.skills.user", Tool: "claude-code", Scope: "user", Dir: true, What: "skills (SKILL.md front matter)", Paths: []string{"{home}/.claude/skills"}},
		{ID: "claude.agents.user", Tool: "claude-code", Scope: "user", Dir: true, What: "sub-agents (front matter)", Paths: []string{"{home}/.claude/agents"}},
		{ID: "claude.commands.user", Tool: "claude-code", Scope: "user", Dir: true, What: "slash commands (front matter)", Paths: []string{"{home}/.claude/commands"}},
		{ID: "claude.skills.project", Tool: "claude-code", Scope: "project", Dir: true, What: "skills (SKILL.md front matter)", Paths: []string{"{project}/.claude/skills"}},
		{ID: "claude.agents.project", Tool: "claude-code", Scope: "project", Dir: true, What: "sub-agents (front matter)", Paths: []string{"{project}/.claude/agents"}},
		{ID: "claude.commands.project", Tool: "claude-code", Scope: "project", Dir: true, What: "slash commands (front matter)", Paths: []string{"{project}/.claude/commands"}},
	}
}
