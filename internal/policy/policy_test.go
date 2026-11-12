package policy

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/access"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"gopkg.in/yaml.v3"
)

const good = `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: claude-code}
mode: enforce
network:
  default: deny
  allow:
    - {host: api.anthropic.com, port: 443}
    - {host: "*.github.com"}
    - {cidr: 10.0.0.0/8, port: 5432}
  deny:
    - {host: gist.github.com}
filesystem:
  read_write: ["{project}", /tmp]
  read_only: ["{home}/.claude", /etc]
  deny: ["{home}/.ssh", "{project}/.env"]
commands:
  default: allow
  ask: ["terraform apply*"]
  deny: ["git push --force*", "rm -rf /*"]
mcp_servers:
  default: deny
  allow: [github, "fs-*"]
  deny: [fs-root]
`

func TestDecisions(t *testing.T) {
	p, issues := Parse([]byte(good))
	if p == nil || hasErr(issues) {
		t.Fatalf("issues: %v", issues)
	}
	p = p.Expand("/home/dev", "/work/api")
	for _, c := range []struct {
		got  Decision
		want string
	}{
		{p.DecideNetwork("api.anthropic.com", nil, 443), Allow},
		{p.DecideNetwork("api.anthropic.com", nil, 80), Deny},
		{p.DecideNetwork("api.github.com", nil, 443), Allow},
		{p.DecideNetwork("github.com", nil, 443), Deny}, // *.github.com is subdomains only
		{p.DecideNetwork("gist.github.com", nil, 443), Deny},
		{p.DecideNetwork("API.Anthropic.com.", nil, 443), Allow},
		{p.DecideNetwork("", net.ParseIP("10.1.2.3"), 5432), Allow},
		{p.DecideNetwork("", net.ParseIP("10.1.2.3"), 6379), Deny},
		{p.DecideFile("/work/api/main.go", true), Allow},
		{p.DecideFile("/work/api/.env", false), Deny},
		{p.DecideFile("/work/apiary/x", false), Deny}, // prefix is by path element
		{p.DecideFile("/home/dev/.claude/settings.json", false), Allow},
		{p.DecideFile("/home/dev/.claude/settings.json", true), Deny},
		{p.DecideFile("/home/dev/.ssh/id_ed25519", false), Deny},
		{p.DecideFile("/home/dev/notes.txt", false), Deny},
		{p.DecideCommand("git   push --force origin main"), Deny},
		{p.DecideCommand("git push origin main"), Allow},
		{p.DecideCommand("terraform apply -auto-approve"), Ask},
		{p.DecideCommand("rm -rf /"), Deny},
		{p.DecideMCP("github"), Allow},
		{p.DecideMCP("fs-home"), Allow},
		{p.DecideMCP("fs-root"), Deny},
		{p.DecideMCP("slack"), Deny},
	} {
		if c.got.Action != c.want {
			t.Errorf("%+v, want %s", c.got, c.want)
		}
	}
}

func TestValidationLinesAndMessages(t *testing.T) {
	for name, c := range map[string]struct {
		doc, want string
		line      int
	}{
		"typo key":     {strings.Replace(good, "read_only:", "readonly:", 1), `unknown key "readonly"`, 15},
		"bad mode":     {strings.Replace(good, "mode: enforce", "mode: block", 1), `"block" is not a mode`, 4},
		"bad host":     {strings.Replace(good, "api.anthropic.com, port", "https://api.anthropic.com, port", 1), "is not a host name", 8},
		"ip as host":   {strings.Replace(good, "api.anthropic.com, port", "1.2.3.4, port", 1), "for an address use cidr", 8},
		"bad cidr":     {strings.Replace(good, "10.0.0.0/8", "10.0.0.0/33", 1), "is not an address range", 10},
		"relative":     {strings.Replace(good, "/tmp]", "tmp]", 1), "must be absolute", 14},
		"bad port":     {strings.Replace(good, "port: 5432", "port: 70000", 1), "out of range", 10},
		"not yaml":     {"agent: [", "", 1},
		"bad default":  {strings.Replace(good, "  default: deny\n  allow:\n    - {host: api", "  default: block\n  allow:\n    - {host: api", 1), `"block": use`, 6},
		"wrong kind":   {strings.Replace(good, "kind: AgentPolicy", "kind: Policy", 1), "must be", 2},
		"port as text": {strings.Replace(good, "port: 5432", "port: postgres", 1), "", 10},
	} {
		p, issues := Parse([]byte(c.doc))
		if !hasErr(issues) {
			t.Errorf("%s: no error (policy %+v)", name, p)
			continue
		}
		found := false
		for _, i := range issues {
			if !i.Warning && strings.Contains(i.Message, c.want) && i.Line == c.line {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want line %d %q, got %v", name, c.line, c.want, issues)
		}
	}
}

func TestWarnings(t *testing.T) {
	doc := strings.Replace(good, "    - {host: api.anthropic.com, port: 443}\n", "", 1)
	doc = strings.Replace(doc, `read_write: ["{project}", /tmp]`, `read_write: ["{project}", /tmp, "{home}/.ssh/x"]`, 1)
	_, issues := Parse([]byte(doc))
	var model, inside bool
	for _, i := range issues {
		if !i.Warning {
			t.Errorf("unexpected error %v", i)
		}
		model = model || strings.Contains(i.Message, "model API (api.anthropic.com) is not allowed")
		inside = inside || strings.Contains(i.Message, "is inside denied")
	}
	if !model || !inside {
		t.Errorf("warnings = %v", issues)
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		pat, text string
		want      bool
	}{
		{"git push --force*", "git push --force origin main", true},
		{"git push --force*", "git push origin --force", false},
		{"*DROP TABLE*", "psql -c 'DROP TABLE users'", true},
		{"aws * delete*", "aws s3api delete-bucket --bucket x", true},
		{"aws * delete*", "aws s3 ls", false},
		{"aws * delete*", "aws s3 delete x", true},
		{"rm -rf /*", "rm -rf /", true},
		{"rm -rf /*", "rm -rf ./build", false},
		{"*", "", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "acb", false},
	} {
		if got := GlobMatch(c.pat, c.text); got != c.want {
			t.Errorf("GlobMatch(%q, %q) = %v", c.pat, c.text, got)
		}
	}
}

func TestGenerateRenderRoundTrip(t *testing.T) {
	home := "/home/dev"
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	act := &access.Summary{ID: "claude-code", Name: "Claude Code", FirstSeen: t0, LastSeen: t0.Add(time.Hour),
		Destinations: []access.Destination{
			{Host: "api.anthropic.com", IP: "160.79.104.10", Port: 443, Category: "llm", Count: 40},
			{Host: "github.com", IP: "140.82.112.3", Port: 443, Category: "github", Count: 3},
			{IP: "10.0.0.5", Port: 5432, Category: "postgres", Count: 2},
			{IP: "2001:db8::1", Port: 6379, Category: "redis", Count: 1},
		},
		Files: []access.File{
			{Path: "/work/api/src/main.go", Access: "write", Count: 5},
			{Path: "/work/api/README.md", Access: "read", Count: 1},
			{Path: "/home/dev/.claude/settings.json", Access: "read", Count: 2},
			{Path: "/home/dev/notes/todo.txt", Access: "read", Count: 1},
			{Path: "/home/dev/.config/curlrc", Access: "read", Count: 1},
			{Path: "/home/dev/.config/git/config", Access: "read", Count: 1},
			{Path: "/home/dev/.aws/credentials", Access: "read", Sensitive: true, Count: 1},
			{Path: "/work/api/.env", Access: "read", Sensitive: true, Count: 2},
			{Path: "/home/dev", Access: "read", Count: 1},
			{Path: "/etc/hosts.allow", Access: "read", Count: 1},
		},
		Commands: []access.Command{{Program: "git", Count: 9}},
	}
	g := Generate(GenInput{AgentID: "claude-code", AgentName: "Claude Code", Activity: act, MCPConfigured: []string{"github", "db", "github"},
		Home: home, Now: t0, Version: "test", IsRepo: func(d string) bool { return d == "/work/api" }})
	data := Render(g)
	p, issues := Parse(data)
	if p == nil || hasErr(issues) {
		t.Fatalf("rendered policy does not parse: %v\n%s", issues, data)
	}
	if p.Mode != Monitor || p.Network.Default != Deny || p.Agent.ID != "claude-code" {
		t.Errorf("header fields: %+v", p)
	}
	ep := p.Expand(home, "/work/api")
	for _, c := range []struct {
		d    Decision
		want string
	}{
		{ep.DecideNetwork("api.anthropic.com", nil, 443), Allow},
		{ep.DecideNetwork("github.com", nil, 443), Allow},
		{ep.DecideNetwork("", net.ParseIP("10.0.0.5"), 5432), Allow},
		{ep.DecideNetwork("", net.ParseIP("2001:db8::1"), 6379), Allow},
		{ep.DecideNetwork("example.com", nil, 443), Deny},
		{ep.DecideFile("/work/api/src/new.go", true), Allow},
		{ep.DecideFile("/home/dev/.claude/settings.json", false), Allow},
		{ep.DecideFile("/home/dev/notes/todo.txt", false), Allow},
		{ep.DecideFile("/home/dev/other/x", false), Deny}, // home is never allowed as a whole
		{ep.DecideFile("/home/dev/.config/git/ignore", false), Allow},
		{ep.DecideFile("/home/dev/.config/curlrc", false), Allow},
		{ep.DecideFile("/home/dev/.config/gcloud/credentials.db", false), Deny},
		{ep.DecideFile("/home/dev/.config/other/x", false), Deny}, // ~/.config is not allowed as a whole
		{ep.DecideFile("/home/dev/.aws/credentials", false), Deny},
		{ep.DecideFile("/work/api/.env", false), Deny},
		{ep.DecideMCP("db"), Allow},
		{ep.DecideMCP("slack"), Deny},
		{ep.DecideCommand("git push -f"), Deny},
	} {
		if c.d.Action != c.want {
			t.Errorf("%+v, want %s", c.d, c.want)
		}
	}
	if len(p.MCPServers.Allow) != 2 {
		t.Errorf("mcp allow = %v (duplicates must be removed)", p.MCPServers.Allow)
	}
	text := string(data)
	for _, want := range []string{"# model API", "seen 40 times", "the agent read it once", "credential file the agent opened 2 times", "Seen: programs it ran: git ×9"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered policy lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "'{home}/.config'") {
		t.Errorf("~/.config allowed as a whole:\n%s", text)
	}
	if strings.Contains(text, "'{home}'\n") || strings.Contains(text, "- '{home}'  ") {
		t.Errorf("home allowed as a whole:\n%s", text)
	}
}

func TestDefaultPolicyAndSet(t *testing.T) {
	d := DefaultPolicy("test", time.Now())
	p, issues := Parse(Render(d))
	if p == nil || hasErr(issues) || p.Agent.ID != AnyAgent || p.Network.Default != Allow {
		t.Fatalf("default policy: %+v %v", p, issues)
	}
	dir := t.TempDir()
	write := func(name, doc string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("default.yaml", string(Render(d)))
	write("claude-code.yaml", good)
	write("broken.yaml", "agent: [")
	write("dup.yml", good)
	write("notes.txt", "ignored")
	files, err := LoadDir(dir)
	if err != nil || len(files) != 4 {
		t.Fatalf("files = %d, %v", len(files), err)
	}
	s := NewSet(files)
	cl, err1 := s.For("claude-code")
	cx, err2 := s.For("codex")
	if err1 != nil || err2 != nil || cl.Mode != Enforce || cx.Agent.ID != AnyAgent || s.Len() != 2 {
		t.Errorf("set = %v %v %v", s.SortedIDs(), err1, err2)
	}
	for _, f := range files {
		if filepath.Base(f.Path) == "dup.yml" && f.OK() {
			t.Error("second policy for the same agent accepted")
		}
	}
}

func TestSimulate(t *testing.T) {
	p, _ := Parse([]byte(good))
	cl := &events.Agent{ID: "claude-code", Name: "Claude Code", PID: 1}
	recs := []events.Record{
		{Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "160.79.104.10", Port: 443, Host: "api.anthropic.com"}},
		{Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "1.2.3.4", Port: 443, Host: "evil.example.com"}},
		{Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "1.2.3.4", Port: 443, Host: "evil.example.com"}},
		{Type: events.File, Agent: cl, Path: "/home/dev/.ssh/id_rsa", Access: "read"},
		{Type: events.Process, Agent: cl, Args: []string{"git", "push", "--force"}},
		{Type: events.Process, Agent: cl, Args: []string{"terraform", "apply"}},
		{Type: events.Network, Agent: &events.Agent{ID: "codex"}, Dst: &events.Dst{IP: "1.1.1.1", Port: 53}},
	}
	imp := Simulate(p, recs, func(a events.Agent) bool { return a.ID == "claude-code" }, "/home/dev")
	if imp.Checked != 6 || len(imp.Hits) != 4 {
		t.Fatalf("impact = %+v", imp)
	}
	if imp.Hits[0].Kind != "network" || imp.Hits[0].Count != 2 || imp.Hits[0].What != "evil.example.com:443" {
		t.Errorf("first hit = %+v", imp.Hits[0])
	}
}

func hasErr(issues []Issue) bool {
	for _, i := range issues {
		if !i.Warning {
			return true
		}
	}
	return false
}

func TestExportOpenShell(t *testing.T) {
	doc := strings.Replace(good, "    - {cidr: 10.0.0.0/8, port: 5432}\n", "    - {cidr: 10.0.0.0/8, port: 5432}\n    - {cidr: 127.0.0.1/32, port: 11434}\n    - {host: example.org}\n", 1)
	doc = strings.Replace(doc, `read_only: ["{home}/.claude", /etc]`, `read_only: ["{home}/.claude", /etc, "{home}"]`, 1)
	p, issues := Parse([]byte(doc))
	if p == nil || hasErr(issues) {
		t.Fatalf("%v", issues)
	}
	exp, err := ExportOpenShell(p, OpenShellOptions{Home: "/home/sandbox", Source: "policies/claude-code.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	// Decode strictly into the OpenShell schema: no key outside it.
	dec := yaml.NewDecoder(bytes.NewReader(exp.YAML))
	dec.KnownFields(true)
	var o osPolicy
	if err := dec.Decode(&o); err != nil {
		t.Fatalf("export does not fit the OpenShell schema: %v\n%s", err, exp.YAML)
	}
	if o.Version != 1 || !o.FilesystemPolicy.IncludeWorkdir || o.Landlock.Compatibility != "best_effort" {
		t.Errorf("header fields: %+v", o)
	}
	has := func(list []string, x string) bool {
		for _, v := range list {
			if v == x {
				return true
			}
		}
		return false
	}
	fs := o.FilesystemPolicy
	if !has(fs.ReadOnly, "/home/sandbox/.claude") || !has(fs.ReadOnly, "/usr") || !has(fs.ReadWrite, "/tmp") || has(fs.ReadWrite, "{project}") {
		t.Errorf("filesystem = %+v", fs)
	}
	for _, path := range append(fs.ReadOnly, fs.ReadWrite...) {
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.Contains(path, "{") {
			t.Errorf("path %q is not absolute and literal", path)
		}
	}
	rule, ok := o.NetworkPolicies["authsec_claude_code"]
	if !ok || len(rule.Binaries) == 0 || rule.Binaries[0].Path != "/usr/local/bin/claude" {
		t.Fatalf("network rule = %+v", o.NetworkPolicies)
	}
	var hosts []string
	for _, e := range rule.Endpoints {
		if e.Port == 0 {
			t.Errorf("endpoint without port: %+v", e)
		}
		if e.Host == "" && len(e.AllowedIPs) == 0 {
			t.Errorf("endpoint without host or allowed_ips: %+v", e)
		}
		hosts = append(hosts, e.Host+strings.Join(e.AllowedIPs, ","))
	}
	got := strings.Join(hosts, " ")
	if !strings.Contains(got, "api.anthropic.com") || !strings.Contains(got, "*.github.com") || !strings.Contains(got, "10.0.0.0/8") || strings.Contains(got, "127.0.0.1") {
		t.Errorf("endpoints = %s", got)
	}
	notes := strings.Join(exp.Notes, "\n")
	for _, want := range []string{"which OpenShell never allows", "deny /home/sandbox/.ssh cannot be applied inside read_only /home/sandbox", "network deny rules (gist.github.com)", "no port in the policy; exported as port 443", "commands and mcp_servers have no OpenShell equivalent", "check the real path in the image"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	if !strings.Contains(string(exp.YAML), "# note: ") {
		t.Error("notes not written into the file")
	}
	// The default policy needs a binary; an unknown agent too.
	d, _ := Parse(Render(DefaultPolicy("t", time.Now())))
	if _, err := ExportOpenShell(d, OpenShellOptions{}); err == nil {
		t.Error("default policy exported without a binary")
	}
	if _, err := ExportOpenShell(d, OpenShellOptions{Binaries: []string{"/usr/bin/python3"}}); err != nil {
		t.Errorf("default policy with a binary: %v", err)
	}
}
