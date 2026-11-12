package recognise

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec-cli/internal/proc"
)

const planted = "sk-ant-api03-PLANTEDsecretVALUEdoNOTleak0123456789"

const anthropicIP = "160.79.104.10"

type fake struct{ s *proc.Snapshot }

func newFake() *fake { return &fake{s: &proc.Snapshot{Procs: map[int]*proc.Process{}}} }

func (f *fake) p(pid, ppid int, comm, exe string, args ...string) *proc.Process {
	p := &proc.Process{PID: pid, PPID: ppid, Comm: comm, Exe: exe, Args: args, User: "dev"}
	f.s.Procs[pid] = p
	return p
}

func (f *fake) conn(pid int, ip string, port int) {
	f.s.Conns = append(f.s.Conns, proc.Conn{PID: pid, LocalIP: net.ParseIP("10.0.0.2"), LocalPort: 40000 + len(f.s.Conns),
		RemoteIP: net.ParseIP(ip), RemotePort: port})
}

func (f *fake) recognise(possible bool) []Agent {
	return Recognise(f.s, Options{LLMAddrs: map[string]string{anthropicIP: "api.anthropic.com"}, Possible: possible})
}

func byID(as []Agent, id string) []Agent {
	var out []Agent
	for _, a := range as {
		if a.ID == id {
			out = append(out, a)
		}
	}
	return out
}

func TestClaudeInVSCode(t *testing.T) {
	f := newFake()
	f.p(1, 0, "systemd", "/usr/lib/systemd/systemd")
	f.p(10, 1, "code", "/usr/share/code/code", "/usr/share/code/code", ".")
	f.p(11, 10, "code", "/usr/share/code/code", "/usr/share/code/code", "--type=utility")
	ext := "/home/dev/.vscode/extensions/anthropic.claude-code-2.1.322-linux-x64/resources/native-binary/claude"
	f.p(20, 11, "claude", ext, ext, "--output-format", "stream-json", "--api-key", planted)
	f.p(21, 20, "node", "/usr/bin/node", "node", "/home/dev/.npm/_npx/x/node_modules/.bin/mcp-server-github")
	f.p(22, 20, "npx", "/usr/bin/node", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp")
	f.p(23, 20, "bash", "/usr/bin/bash", "bash", "-c", "git status && grep mcp notes.txt")
	f.p(24, 20, "claude", ext, ext, "--subagent") // same agent: not a new one
	f.conn(20, anthropicIP, 443)
	f.conn(21, "140.82.112.5", 443)
	f.conn(23, "10.0.0.9", 5432)

	as := f.recognise(false)
	cs := byID(as, "claude-code")
	if len(cs) != 1 {
		t.Fatalf("claude agents = %d: %+v", len(cs), as)
	}
	c := cs[0]
	if c.Confidence != Known || c.PID != 20 || c.Version != "2.1.322" || c.Via != "editor extension anthropic.claude-code" {
		t.Errorf("claude = %+v", c)
	}
	roles := map[string]string{}
	for _, ch := range c.Children {
		roles[ch.Name] = ch.Role
	}
	if roles["mcp-server-github"] != "mcp_server" || roles["server-filesystem"] != "mcp_server" || roles["bash"] != "process" || roles["claude"] != "process" {
		t.Errorf("children = %+v", c.Children)
	}
	if !strings.Contains(strings.Join(c.Evidence, ";"), "connects to api.anthropic.com") {
		t.Errorf("evidence = %v", c.Evidence)
	}
	var services []string
	for _, e := range c.Endpoints {
		services = append(services, e.Service)
	}
	if len(c.Endpoints) != 3 || !c.Endpoints[0].LLM || !strings.Contains(strings.Join(services, ","), "postgres") {
		t.Errorf("endpoints = %+v", c.Endpoints)
	}
	if len(byID(as, "vscode")) != 0 {
		t.Error("VS Code reported though its own processes have no LLM traffic")
	}
}

func TestNestedAgents(t *testing.T) {
	f := newFake()
	f.p(5, 1, "zsh", "/bin/zsh", "zsh")
	f.p(10, 5, "codex", "/usr/local/bin/codex", "codex")
	f.p(20, 10, "node", "/usr/bin/node", "node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js")
	as := f.recognise(false)
	if len(as) != 2 {
		t.Fatalf("agents = %+v", as)
	}
	cl := byID(as, "claude-code")[0]
	if cl.ParentAgent != 10 || byID(as, "codex")[0].Via != "terminal (zsh)" {
		t.Errorf("claude = %+v", cl)
	}
	if len(byID(as, "codex")[0].Children) != 0 {
		t.Error("a nested agent must not also be a child process of its parent")
	}
}

func TestUnknownEditorBrowserPossible(t *testing.T) {
	f := newFake()
	f.p(5, 1, "bash", "/bin/bash", "bash")
	py := f.p(30, 5, "python3", "/usr/bin/python3.12", "python3", "agent.py")
	py.EnvNames = []string{"HOME", "OPENAI_API_KEY"}
	f.p(31, 30, "python3", "/usr/bin/python3.12", "python3", "worker.py") // also LLM: merged into 30
	f.conn(30, anthropicIP, 443)
	f.conn(31, anthropicIP, 443)

	f.p(40, 1, "chrome", "/opt/google/chrome/chrome", "chrome")
	f.p(41, 40, "chrome", "/opt/google/chrome/chrome", "chrome", "--type=utility")
	f.conn(41, anthropicIP, 443)

	f.p(50, 1, "cursor", "/opt/Cursor/cursor", "cursor")
	f.p(51, 50, "cursor", "/opt/Cursor/cursor", "cursor", "--type=utility")
	f.conn(51, anthropicIP, 443)

	idle := f.p(60, 5, "node", "/usr/bin/node", "node", "bot.js")
	idle.EnvNames = []string{"ANTHROPIC_API_KEY"}

	f.p(70, 1, "ollama", "/usr/local/bin/ollama", "ollama", "serve")
	f.p(71, 5, "python3", "/usr/bin/python3", "python3", "rag.py")
	f.s.Conns = append(f.s.Conns,
		proc.Conn{PID: 71, LocalIP: net.ParseIP("127.0.0.1"), LocalPort: 50000, RemoteIP: net.ParseIP("127.0.0.1"), RemotePort: 11434},
		proc.Conn{PID: 70, LocalIP: net.ParseIP("127.0.0.1"), LocalPort: 11434, RemoteIP: net.ParseIP("127.0.0.1"), RemotePort: 50000})

	as := f.recognise(false)
	un := byID(as, "unknown")
	if len(un) != 2 {
		t.Fatalf("unknown agents = %+v", un)
	}
	pids := map[int]Agent{}
	for _, a := range un {
		pids[a.PID] = a
	}
	if a, ok := pids[30]; !ok || a.Confidence != Likely || len(a.Children) != 1 || len(a.LLMKeyNames) != 1 {
		t.Errorf("python agent = %+v", pids[30])
	}
	if a, ok := pids[71]; !ok || !strings.Contains(strings.Join(a.Evidence, ";"), "ollama (local)") {
		t.Errorf("ollama client = %+v", pids[71])
	}
	if cur := byID(as, "cursor"); len(cur) != 1 || cur[0].PID != 50 || cur[0].Confidence != Known {
		t.Errorf("cursor = %+v", cur)
	}
	if ol := byID(as, "ollama"); len(ol) != 1 || ol[0].Role != RoleModelServer {
		t.Errorf("ollama = %+v", ol)
	}
	for _, a := range as {
		if a.PID == 40 || a.PID == 41 || a.PID == 60 {
			t.Errorf("reported %+v", a)
		}
	}
	// With --all the idle node holding a key is a possible agent.
	as = f.recognise(true)
	found := false
	for _, a := range as {
		if a.PID == 60 && a.Confidence == Possible {
			found = true
		}
	}
	if !found {
		t.Error("possible agent missing")
	}
}

func TestThreatFirstAndNoSecretInOutput(t *testing.T) {
	f := newFake()
	f.p(10, 1, "codex", "/usr/bin/codex", "codex", "--token="+planted, "OPENAI_API_KEY="+planted)
	f.p(20, 1, "artex", "/opt/artex/artex", "artex")
	as := f.recognise(true)
	if len(as) != 2 || as[0].ID != "artex" || !as[0].Threat {
		t.Fatalf("agents = %+v", as)
	}
	b, _ := json.Marshal(as)
	if strings.Contains(string(b), "PLANTED") {
		t.Fatalf("secret in output: %s", b)
	}
}

func TestResolveLLMHosts(t *testing.T) {
	m := ResolveLLMHosts(context.Background(), func(_ context.Context, h string) ([]string, error) {
		switch h {
		case "api.anthropic.com":
			return []string{anthropicIP, "2607:6bc0::10"}, nil
		case "api.openai.com":
			return []string{"162.159.140.245"}, nil
		}
		return nil, errors.New("nxdomain")
	})
	if m[anthropicIP] != "api.anthropic.com" || m["2607:6bc0::10"] != "api.anthropic.com" || m["162.159.140.245"] != "api.openai.com" || len(m) != 3 {
		t.Errorf("got %v", m)
	}
}

func TestIsLLMHostName(t *testing.T) {
	for name, want := range map[string]bool{
		"api.openai.com.": true, "myco.openai.azure.com": true, "europe-west4-aiplatform.googleapis.com": true,
		"example.com": false, "openai.com.evil.net": false,
	} {
		if IsLLMHostName(name) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
}
