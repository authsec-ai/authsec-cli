package daemon

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/sensor"
)

const planted = "sk-ant-api03-PLANTEDsecretVALUEdoNOTleak0123456789"

type harness struct {
	t       *testing.T
	snap    *proc.Snapshot
	tracked map[int]bool
	recs    []events.Record
	m       *Monitor
	now     time.Time
}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, snap: &proc.Snapshot{Procs: map[int]*proc.Process{}}, tracked: map[int]bool{},
		now: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)}
	h.add(1, 0, "systemd", "/sbin/init")
	h.add(5, 1, "zsh", "/usr/bin/zsh", "zsh")
	h.add(10, 5, "claude", "/home/dev/.local/share/claude/versions/2.1.3", "claude")
	h.add(11, 10, "node", "/usr/bin/node", "node", "/x/node_modules/.bin/mcp-server-github")
	deps := Deps{
		Get: func(pid int) (*proc.Process, bool) { p, ok := h.snap.Procs[pid]; return p, ok },
		Snapshot: func() (*proc.Snapshot, error) {
			cp := *h.snap
			cp.Conns = append([]proc.Conn(nil), h.snap.Conns...)
			return &cp, nil
		},
		Track:   func(pid int) { h.tracked[pid] = true },
		Untrack: func(pid int) { delete(h.tracked, pid) },
		Cwd:     func(int) string { return "/work/api" },
		Now:     func() time.Time { return h.now },
	}
	h.m = NewMonitor(deps, func(r events.Record) { h.recs = append(h.recs, r) }, map[string]string{"160.79.104.10": "api.anthropic.com"})
	return h
}

func (h *harness) add(pid, ppid int, comm, exe string, args ...string) *proc.Process {
	p := &proc.Process{PID: pid, PPID: ppid, Comm: comm, Exe: exe, Args: args, User: "dev"}
	h.snap.Procs[pid] = p
	return p
}

func (h *harness) of(typ string) []events.Record {
	var out []events.Record
	for _, r := range h.recs {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

func TestMonitorFollowsAgentTree(t *testing.T) {
	h := newHarness(t)
	h.m.Seed(h.snap)
	if s := h.of(events.AgentStarted); len(s) != 1 || s[0].Agent.ID != "claude-code" || !h.tracked[10] || !h.tracked[11] {
		t.Fatalf("seed: started %+v tracked %v", s, h.tracked)
	}

	// Claude forks and execs bash with a secret on the command line.
	h.m.Handle(sensor.Event{Type: sensor.Fork, PID: 20, PPID: 10})
	h.add(20, 10, "bash", "/usr/bin/bash", "bash", "-c", "curl -H 'Authorization: Bearer "+planted+"' https://api.github.com")
	h.m.Handle(sensor.Event{Type: sensor.Exec, PID: 20, PPID: 10, Comm: "bash", Path: "/usr/bin/bash"})
	// bash connects to GitHub, named by a DNS answer seen earlier.
	h.m.HandleDNS(sensor.DNSAnswer{Name: "api.github.com", IPs: []net.IP{net.ParseIP("140.82.112.6")}, TTL: time.Minute})
	h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 20, DstIP: net.ParseIP("140.82.112.6"), DstPort: 443})
	h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 20, DstIP: net.ParseIP("140.82.112.6"), DstPort: 443}) // deduplicated
	// Files: a credential file, a relative write, library noise, a directory.
	h.m.Handle(sensor.Event{Type: sensor.Open, PID: 20, Path: "/home/dev/.aws/credentials"})
	h.m.Handle(sensor.Event{Type: sensor.Open, PID: 20, Path: "out/report.txt", Flags: 0x241})
	h.m.Handle(sensor.Event{Type: sensor.Open, PID: 20, Path: "/usr/lib/x86_64-linux-gnu/libc.so.6"})
	h.m.Handle(sensor.Event{Type: sensor.Open, PID: 20, Path: "/home/dev/.aws/credentials"}) // deduplicated

	if p := h.of(events.Process); len(p) != 1 || p[0].Agent.ID != "claude-code" || p[0].Comm != "bash" {
		t.Errorf("process records = %+v", p)
	}
	if n := h.of(events.Network); len(n) != 1 || n[0].Dst.Host != "api.github.com" || n[0].Dst.LLM {
		t.Errorf("network records = %+v", n)
	}
	files := h.of(events.File)
	if len(files) != 2 {
		t.Fatalf("file records = %+v", files)
	}
	if !files[0].Sensitive || files[0].Access != "read" || files[1].Path != "/work/api/out/report.txt" || files[1].Access != "write" {
		t.Errorf("files = %+v", files)
	}

	// Claude starts Codex: a new agent, not a Claude process.
	h.add(30, 10, "codex", "/usr/local/bin/codex", "codex")
	h.m.Handle(sensor.Event{Type: sensor.Fork, PID: 30, PPID: 10})
	h.m.Handle(sensor.Event{Type: sensor.Exec, PID: 30, PPID: 10, Comm: "codex", Path: "/usr/local/bin/codex"})
	started := h.of(events.AgentStarted)
	if len(started) != 2 || started[1].Agent.ID != "codex" || !strings.Contains(strings.Join(started[1].Evidence, ";"), "started by agent Claude Code") {
		t.Errorf("nested agent = %+v", started)
	}

	// Claude exits.
	h.m.Handle(sensor.Event{Type: sensor.Exit, PID: 10})
	if s := h.of(events.AgentStopped); len(s) != 1 || s[0].Agent.ID != "claude-code" || h.tracked[10] {
		t.Errorf("stopped = %+v tracked %v", s, h.tracked)
	}
}

func TestMonitorFindsUnknownAgentByLLMTraffic(t *testing.T) {
	h := newHarness(t)
	h.m.Seed(h.snap)
	h.add(40, 5, "python3", "/usr/bin/python3", "python3", "agent.py", "--key="+planted)
	h.add(41, 1, "chrome", "/opt/google/chrome/chrome", "chrome")
	h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 41, DstIP: net.ParseIP("160.79.104.10"), DstPort: 443}) // browser: ignored
	h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 40, DstIP: net.ParseIP("160.79.104.10"), DstPort: 443})
	h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 40, DstIP: net.ParseIP("160.79.104.10"), DstPort: 443})
	var unknown []events.Record
	for _, r := range h.of(events.AgentStarted) {
		if r.Agent.ID == "unknown" {
			unknown = append(unknown, r)
		}
	}
	if len(unknown) != 1 || unknown[0].Agent.PID != 40 || unknown[0].Agent.Confidence != "likely" {
		t.Fatalf("unknown agents = %+v", unknown)
	}
	if n := h.of(events.Network); len(n) != 1 || !n[0].Dst.LLM || n[0].Dst.Host != "api.anthropic.com" {
		t.Errorf("network = %+v", n)
	}
	// DNS teaches new LLM addresses (Azure OpenAI has no fixed host list).
	h.m.HandleDNS(sensor.DNSAnswer{Name: "contoso.openai.azure.com", IPs: []net.IP{net.ParseIP("20.1.2.3")}})
	if h.m.llm["20.1.2.3"] != "contoso.openai.azure.com" {
		t.Error("LLM address from DNS not learnt")
	}
	for _, r := range h.recs {
		if strings.Contains(strings.Join(r.Args, " "), "PLANTED") {
			t.Fatalf("secret in record %+v", r)
		}
	}
}

func TestReconcilePolling(t *testing.T) {
	h := newHarness(t)
	h.m.deps.Track, h.m.deps.Untrack = nil, nil
	h.m.Seed(h.snap)
	// A child appears and connects; the agent later disappears.
	h.add(12, 10, "git", "/usr/bin/git", "git", "fetch")
	h.snap.Conns = []proc.Conn{{PID: 12, RemoteIP: net.ParseIP("140.82.112.3"), RemotePort: 443}}
	h.m.Reconcile(h.snap, true)
	if len(h.of(events.Process)) != 1 || len(h.of(events.Network)) != 1 {
		t.Fatalf("records = %+v", h.recs)
	}
	delete(h.snap.Procs, 10)
	h.m.Reconcile(h.snap, true)
	if len(h.of(events.AgentStopped)) != 1 {
		t.Errorf("missed exit not reconciled: %+v", h.recs)
	}
}

func TestNoiseAndSensitive(t *testing.T) {
	for path, want := range map[string][2]bool{ // noise, sensitive
		"/proc/self/status":                 {true, false},
		"/home/u/app/node_modules/x.js":     {true, false},
		"/home/u/.ssh/id_ed25519":           {false, true},
		"/home/u/proj/.env.production":      {false, true},
		"/home/u/.kube/config":              {false, true},
		"/home/u/.config/gh/hosts.yml":      {false, true},
		"/home/u/proj/main.go":              {false, false},
		"/home/u/proj/environment.go":       {false, false},
		"/home/u/.claude/.credentials.json": {false, true},
	} {
		if Noise(path) != want[0] || Sensitive(path) != want[1] {
			t.Errorf("%s: noise %v sensitive %v, want %v", path, Noise(path), Sensitive(path), want)
		}
	}
}
