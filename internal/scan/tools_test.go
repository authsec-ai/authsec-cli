package scan

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/report"
)

var plantedTools = []string{
	"sk-proj-PLANTEDcodexKEY0123456789abcdefgh",
	"PLANTEDbearerVALUE0123456789abcdefghij",
	"ghp_PLANTEDvscodeTOKEN0123456789abcdefg",
	"PLANTEDcursorSECRETvalue0123456789abcd",
	"AIzaPLANTEDgeminiKEY0123456789abcdefghijk",
	"sk-ant-PLANTEDdesktopKEY0123456789abcdef",
	"PLANTEDwindsurfTOKEN0123456789abcdefghi",
}

// toolsFixture configures Codex, VS Code, Cursor, Gemini CLI, Claude Desktop
// and Windsurf, each with a secret where people put them.
func toolsFixture(t *testing.T) (root, home, project string) {
	t.Helper()
	root = t.TempDir()
	home = filepath.Join(root, "home", "dev")
	project = filepath.Join(root, "work", "api")
	write(t, filepath.Join(project, "README.md"), "x")

	write(t, filepath.Join(home, ".codex", "config.toml"), `
model = "gpt-5"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[profiles.safe]
approval_policy = "on-request"
sandbox_mode = "workspace-write"

[projects."`+project+`"]
trust_level = "trusted"

[mcp_servers.linear]
command = "npx"
args = ["-y", "mcp-remote", "https://mcp.linear.app/sse", "--header", "Authorization: Bearer PLANTEDbearerVALUE0123456789abcdefghij"]

[mcp_servers.openai-docs]
url = "https://developers.openai.com/mcp"
bearer_token_env_var = "DOCS_TOKEN"

[mcp_servers.db]
command = "uvx"
args = ["postgres-mcp==0.3.0"]
env = { OPENAI_API_KEY = "sk-proj-PLANTEDcodexKEY0123456789abcdefgh" }
`)
	write(t, filepath.Join(home, ".config", "Code", "User", "settings.json"), `{
  "editor.fontSize": 14,
  "github.token": "ghp_PLANTEDvscodeTOKEN0123456789abcdefg",
  "chat.tools.autoApprove": true,
  "chat.tools.terminal.autoApprove": {"git status": true, "rm": false}
}`)
	write(t, filepath.Join(home, ".config", "Code", "User", "mcp.json"), `{
  "servers": {"github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": {"Authorization": "Bearer ghp_PLANTEDvscodeTOKEN0123456789abcdefg"}}},
  "inputs": []
}`)
	write(t, filepath.Join(home, ".cursor", "cli-config.json.bak"), "")
	write(t, filepath.Join(home, ".codeium", "windsurf", "unused"), "")
	write(t, filepath.Join(project, ".cursor", "mcp.json"), "  \n") // empty: no settings, not unreadable
	write(t, filepath.Join(project, ".vscode", "mcp.json"), `{"servers": {"fs": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "."]}}}`)
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers": {"sentry": {"command": "npx", "args": ["-y", "@sentry/mcp-server"], "env": {"SENTRY_AUTH_TOKEN": "PLANTEDcursorSECRETvalue0123456789abcd"}}}}`)
	write(t, filepath.Join(home, ".cursor", "cli-config.json"), `{"permissions": {"allow": ["Shell(*)", "Read(**)"], "deny": ["Shell(rm)"]}}`)
	write(t, filepath.Join(home, ".gemini", "settings.json"), `{
  "general": {"defaultApprovalMode": "yolo"},
  "tools": {"allowed": ["run_shell_command(git)"], "exclude": ["web_fetch"]},
  "mcpServers": {"maps": {"httpUrl": "https://maps.example.com/mcp", "headers": {"X-Goog-Api-Key": "AIzaPLANTEDgeminiKEY0123456789abcdefghijk"}}}
}`)
	write(t, filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), `{
  "mcpServers": {"brave": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search", "--key", "sk-ant-PLANTEDdesktopKEY0123456789abcdef"]}}
}`)
	write(t, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), `{
  "mcpServers": {"notion": {"serverUrl": "https://mcp.notion.com/mcp?token=PLANTEDwindsurfTOKEN0123456789abcdefghi"}}
}`)
	return root, home, project
}

func TestOtherTools(t *testing.T) {
	root, home, project := toolsFixture(t)
	r := run(t, root, home) // the project is found through Codex's trust list

	if len(r.Projects) != 1 || r.Projects[0] != project {
		t.Errorf("projects = %v, want Codex's trusted project", r.Projects)
	}
	agents := map[string]bool{}
	signals := map[string][]string{} // tool -> signal ids
	mcp := map[string]finding.Finding{}
	for _, f := range r.Findings {
		switch f.Kind {
		case finding.Agent:
			agents[f.Tool] = true
		case finding.MCPServer:
			mcp[f.Tool+"/"+f.Name] = f
		}
		for _, s := range f.Signals {
			signals[f.Tool] = append(signals[f.Tool], s.ID)
		}
	}
	for _, tool := range []string{"codex", "vscode", "cursor", "gemini-cli", "claude-desktop", "windsurf"} {
		if !agents[tool] {
			t.Errorf("agent %s not found", tool)
		}
	}
	if r.Summary.Findings[finding.Unreadable] != 0 {
		t.Errorf("an empty config file was reported unreadable")
	}
	for _, tool := range []string{"codex", "vscode", "cursor", "gemini-cli"} {
		if !strings.Contains(strings.Join(signals[tool], ","), "auto_approve_shell") {
			t.Errorf("%s: auto_approve_shell missing (signals %v)", tool, signals[tool])
		}
	}
	for _, key := range []string{"codex/linear", "codex/openai-docs", "codex/db", "vscode/github", "vscode/fs", "cursor/sentry",
		"gemini-cli/maps", "claude-desktop/brave", "windsurf/notion"} {
		if _, ok := mcp[key]; !ok {
			t.Errorf("MCP server %s missing", key)
		}
	}
	if f := mcp["codex/openai-docs"]; !strings.Contains(strings.Join(strs(f.Attrs["env_names"]), ","), "DOCS_TOKEN") {
		t.Errorf("codex bearer_token_env_var not kept by name: %+v", f.Attrs)
	}
	if f := mcp["codex/db"]; !f.HasSignal("secret_in_mcp_env") {
		t.Errorf("codex/db: secret_in_mcp_env missing")
	}
	if f := mcp["gemini-cli/maps"]; f.Attrs["transport"] != "http" || !f.HasSignal("secret_in_mcp_env") {
		t.Errorf("gemini httpUrl server = %+v", f.Attrs)
	}
	if f := mcp["vscode/fs"]; f.Project != project || !f.HasSignal("mcp_unpinned") {
		t.Errorf("vscode/fs = %+v", f)
	}

	var b bytes.Buffer
	if err := report.JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if err := report.Table(&b, r, func(s string) string { return s }); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, s := range plantedTools {
		if strings.Contains(out, s) {
			t.Errorf("secret %q in output", s)
		}
	}
	// Nothing of VS Code's settings is kept but the approval settings.
	if strings.Contains(out, "fontSize") || strings.Contains(out, "github.token") {
		t.Error("unrelated VS Code settings kept")
	}
}

func strs(v any) []string {
	var out []string
	b, _ := json.Marshal(v)
	_ = json.Unmarshal(b, &out)
	return out
}
