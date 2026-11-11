package scan

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/report"
)

var shaRE = regexp.MustCompile(`"file_sha256": "[0-9a-f]{64}"`)

var update = flag.Bool("update", false, "rewrite golden files")

// planted are secret values written into the fixture. None may appear in any
// output.
var planted = []string{
	"sk-proj-PLANTEDopenaiKEY0123456789abcdef",
	"ghp_PLANTEDgithubTOKEN0123456789abcdefgh",
	"PLANTEDheaderBEARER9f8e7d6c5b4a39281706",
	"hunter2-PLANTED",
	"PLANTEDhelperSECRET",
	"PLANTEDurlPASSWORD",
	"PLANTEDqueryTOKEN",
	"oauth-PLANTED@example.com",
	"PLANTEDmanagedKEY0123456789abcdefABCDEF",
}

// fixture builds a home with Claude Code configured the way people really
// configure it, one project, and managed settings, all with planted secrets.
func fixture(t *testing.T) (root, home, project string) {
	t.Helper()
	root = t.TempDir()
	home = filepath.Join(root, "home", "dev")
	project = filepath.Join(root, "work", "payments-api")

	write(t, filepath.Join(home, ".claude", "settings.json"), `{
  // user settings (JSONC is accepted)
  "permissions": {
    "allow": ["Bash(git status:*)", "Bash(curl -H \"Authorization: Bearer PLANTEDheaderBEARER9f8e7d6c5b4a39281706\" https://api.example.com/x)", "WebFetch"],
    "deny": ["Bash(rm -rf:*)"],
    "defaultMode": "acceptEdits",
  },
  "env": {"OPENAI_API_KEY": "sk-proj-PLANTEDopenaiKEY0123456789abcdef", "LOG_LEVEL": "debug"},
  "apiKeyHelper": "echo PLANTEDhelperSECRET",
  "hooks": {
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "PGPASSWORD=hunter2-PLANTED psql -c 'select 1'"}]}]
  }
}`)
	write(t, filepath.Join(home, ".claude.json"), `{
  "oauthAccount": {"emailAddress": "oauth-PLANTED@example.com"},
  "mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_PLANTEDgithubTOKEN0123456789abcdefgh"}},
    "remote": {"type": "http", "url": "https://bot:PLANTEDurlPASSWORD@mcp.example.com/mcp?token=PLANTEDqueryTOKEN&region=eu", "headers": {"Authorization": "Bearer PLANTEDheaderBEARER9f8e7d6c5b4a39281706"}}
  },
  "projects": {
    "`+filepath.ToSlash(project)+`": {"allowedTools": ["Bash"], "mcpServers": {"db": {"command": "uvx", "args": ["postgres-mcp==0.3.0", "--dsn", "postgres://u:hunter2-PLANTED@db/x"]}}}
  }
}`)
	write(t, filepath.Join(home, ".claude", "skills", "release", "SKILL.md"), "---\nname: release\ndescription: Cut a release\nallowed-tools: Bash, Read\n---\nbody\n")
	write(t, filepath.Join(home, ".claude", "agents", "reviewer.md"), "---\nname: reviewer\ntools: Read, Grep\nmodel: sonnet\n---\n")
	write(t, filepath.Join(home, ".claude", "commands", "ops", "deploy.md"), "---\nallowed-tools: [\"Bash(kubectl apply:*)\"]\n---\n")

	write(t, filepath.Join(project, ".claude", "settings.json"), `{"permissions": {"defaultMode": "bypassPermissions"}}`)
	write(t, filepath.Join(project, ".mcp.json"), `{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1", "."]}}}`)
	write(t, filepath.Join(project, ".claude", "settings.local.json"), `{"permissions": {`) // broken on purpose

	write(t, filepath.Join(root, "etc", "claude-code", "managed-settings.json"), `{"permissions": {"disableBypassPermissionsMode": "disable", "deny": ["WebFetch"]}, "env": {"CORP_API_KEY": "PLANTEDmanagedKEY0123456789abcdefABCDEF"}}`)
	return root, home, project
}

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, root, home string, projects ...string) *report.Report {
	t.Helper()
	r, err := Run(Options{
		Home: home, Projects: projects, KnownProjects: true, CLIVersion: "test",
		GOOS: "linux", SysRoot: root,
		Now:      func() time.Time { return time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC) },
		Machine:  &report.Machine{ID: "m1", Hostname: "dev-laptop", OS: "linux", Arch: "amd64", User: "dev"},
		LookPath: func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestScanGolden pins the whole report for the fixture.
func TestScanGolden(t *testing.T) {
	root, home, _ := fixture(t)
	r := run(t, root, home)
	var buf bytes.Buffer
	if err := report.JSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	got := strings.ReplaceAll(buf.String(), filepath.ToSlash(root), "$ROOT")
	// Hashes of files that contain the temporary path change every run.
	got = shaRE.ReplaceAllString(got, `"file_sha256": "…"`)

	golden := filepath.Join("testdata", "claude.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/scan -update)", err)
	}
	if got != string(want) {
		t.Errorf("report differs from %s; run go test ./internal/scan -update and review the diff\n%s", golden, got)
	}
}

// TestNoSecretInAnyOutput is the core promise: no planted value reaches the
// JSON or the table.
func TestNoSecretInAnyOutput(t *testing.T) {
	root, home, _ := fixture(t)
	r := run(t, root, home)
	var js, table bytes.Buffer
	if err := report.JSON(&js, r); err != nil {
		t.Fatal(err)
	}
	if err := report.Table(&table, r, func(s string) string { return s }); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{js.String(), table.String()} {
		for _, secret := range planted {
			if strings.Contains(out, secret) {
				t.Errorf("output contains planted secret %q", secret)
			}
		}
	}
}

func TestFindsWhatMatters(t *testing.T) {
	root, home, project := fixture(t)
	r := run(t, root, home)
	if len(r.Projects) != 1 || r.Projects[0] != project {
		t.Fatalf("projects = %v, want the one ~/.claude.json lists", r.Projects)
	}
	get := func(kind finding.Kind, name, path string) *finding.Finding {
		for i := range r.Findings {
			f := &r.Findings[i]
			if f.Kind == kind && f.Name == name && (path == "" || f.Path == path) {
				return f
			}
		}
		t.Fatalf("no %s %q at %s", kind, name, path)
		return nil
	}
	if f := get(finding.Policy, "permissions", filepath.Join(project, ".claude", "settings.json")); !f.HasSignal("auto_approve_shell") {
		t.Error("bypassPermissions in a project is not flagged")
	}
	if f := get(finding.Policy, "allowed tools", ""); !f.HasSignal("auto_approve_shell") || f.Project != project {
		t.Errorf("allowedTools Bash: %+v", f)
	}
	if f := get(finding.MCPServer, "github", ""); !f.HasSignal("mcp_unpinned") || !f.HasSignal("secret_in_mcp_env") {
		t.Errorf("github MCP server signals: %+v", f.Signals)
	}
	if f := get(finding.MCPServer, "fs", ""); f.HasSignal("mcp_unpinned") || f.Scope != finding.ScopeProject {
		t.Errorf("pinned project server: %+v", f)
	}
	if f := get(finding.MCPServer, "remote", ""); f.Attrs["url"] != "https://mcp.example.com/mcp?region=eu&token=<redacted>" || !f.HasSignal("secret_in_mcp_env") {
		t.Errorf("remote server: %+v", f)
	}
	if f := get(finding.Extension, "hook PreToolUse[Bash]", ""); !f.HasSignal("hook_runs_command") {
		t.Error("hook not flagged")
	}
	get(finding.Extension, "command ops/deploy", "")
	get(finding.Policy, "permissions", filepath.Join(root, "etc", "claude-code", "managed-settings.json"))
	if f := get(finding.Unreadable, "settings.local.json", ""); f.Project != project {
		t.Errorf("broken file: %+v", f)
	}
	a := get(finding.Agent, "Claude Code", "")
	if a.Fingerprint != "host:m1:agent:claude-code:"+filepath.ToSlash(filepath.Join(home, ".claude"))+"#Claude Code" {
		t.Errorf("agent fingerprint = %s", a.Fingerprint)
	}
}

// TestFingerprintsAreUnique: two findings with one id would hide each other
// once pushed.
func TestFingerprintsAreUnique(t *testing.T) {
	root, home, _ := fixture(t)
	seen := map[string]bool{}
	for _, f := range run(t, root, home).Findings {
		if seen[f.Fingerprint] {
			t.Errorf("duplicate fingerprint %s", f.Fingerprint)
		}
		seen[f.Fingerprint] = true
	}
}

func TestRefusesFilesOutsideTheRoots(t *testing.T) {
	root, home, _ := fixture(t)
	outside := filepath.Join(t.TempDir(), "elsewhere.json")
	write(t, outside, `{"permissions": {"allow": ["Bash"]}}`)
	p := filepath.Join(home, ".claude", "settings.json")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	r := run(t, root, home)
	for _, f := range r.Findings {
		if f.Path == p {
			if f.Kind != finding.Unreadable || !strings.Contains(f.Attrs["error"].(string), "outside") {
				t.Errorf("symlink out of the home was read: %+v", f)
			}
			return
		}
	}
	t.Error("no finding for the refused symlink")
}

func TestRefusesLargeFiles(t *testing.T) {
	root, home, _ := fixture(t)
	big := `{"x": "` + strings.Repeat("a", 1<<20) + `"}`
	write(t, filepath.Join(home, ".claude", "settings.json"), big)
	for _, f := range run(t, root, home).Findings {
		if strings.HasSuffix(f.Path, filepath.Join(".claude", "settings.json")) && f.Project == "" {
			if f.Kind != finding.Unreadable {
				t.Errorf("large file read: %+v", f)
			}
			return
		}
	}
	t.Error("no finding for the large file")
}

func TestNothingConfigured(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	r := run(t, root, home)
	if len(r.Findings) != 0 {
		t.Errorf("findings on an empty home: %+v", r.Findings)
	}
	b, _ := json.Marshal(r)
	if !bytes.Contains(b, []byte(`"findings":[]`)) {
		t.Errorf("empty findings should be [], got %s", b)
	}
}
