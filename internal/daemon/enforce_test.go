package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/control"
	"github.com/authsec-ai/authsec-cli/internal/enforce"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/policy"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/sensor"
)

type fakeEnforcer struct {
	pol      *policy.Policy
	enforced bool
	started  []events.Agent
	names    map[string]string
}

func (f *fakeEnforcer) AgentStarted(a events.Agent, pids []int) { f.started = append(f.started, a) }
func (f *fakeEnforcer) AgentStopped(int)                        {}
func (f *fakeEnforcer) DNS(string, []net.IP, time.Duration)     {}
func (f *fakeEnforcer) Enforcing(int, string) (bool, *policy.Policy) {
	return f.enforced, f.pol
}
func (f *fakeEnforcer) HostOf(ip string) string { return f.names[ip] }

const claudePolicy = `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: claude-code}
mode: enforce
network:
  default: deny
  allow: [{host: api.github.com, port: 443}]
filesystem:
  read_write: [/work]
  deny: ["{home}/.ssh"]
commands:
  default: allow
  ask: ["terraform apply*"]
  deny: ["git push --force*"]
`

func TestMonitorDecisionsAndKill(t *testing.T) {
	h := newHarness(t)
	p, issues := policy.Parse([]byte(claudePolicy))
	if p == nil {
		t.Fatal(issues)
	}
	fe := &fakeEnforcer{pol: p, enforced: true, names: map[string]string{"140.82.112.6": "api.github.com"}}
	var killed []int
	h.m.deps.Enforcer = fe
	h.m.deps.Kill = func(pid int) error { killed = append(killed, pid); return nil }
	h.m.deps.HomeOf = func(string) string { return "/home/dev" }
	h.m.Seed(h.snap)
	if len(fe.started) != 1 || fe.started[0].ID != "claude-code" {
		t.Fatalf("enforcer not told: %+v", fe.started)
	}
	// A denied command: killed. An asked one: logged, not killed.
	h.add(20, 10, "git", "/usr/bin/git", "git", "-C", ".", "push", "--force")
	h.m.Handle(sensor.Event{Type: sensor.Exec, PID: 20, PPID: 10, Comm: "git", Path: "/usr/bin/git"})
	h.add(21, 10, "terraform", "/usr/bin/terraform", "terraform", "apply")
	h.m.Handle(sensor.Event{Type: sensor.Exec, PID: 21, PPID: 10, Comm: "terraform", Path: "/usr/bin/terraform"})
	// Network: an allowed host known only by address, then a denied one.
	h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 10, DstIP: net.ParseIP("140.82.112.6"), DstPort: 443})
	h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 10, DstIP: net.ParseIP("6.6.6.6"), DstPort: 443})
	// A credential file: logged, not enforced (running agent).
	h.m.Handle(sensor.Event{Type: sensor.Open, PID: 10, Path: "/home/dev/.ssh/id_rsa"})

	if len(killed) != 1 || killed[0] != 20 {
		t.Errorf("killed = %v, want [20]", killed)
	}
	byKind := map[string][]events.Record{}
	for _, r := range h.of(events.Decision) {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}
	if c := byKind["command"]; len(c) != 2 || !c[0].Enforced || c[0].Note != "process killed" || c[1].Action != policy.Ask || c[1].Enforced {
		t.Errorf("command decisions = %+v", c)
	}
	if n := byKind["network"]; len(n) != 1 || n[0].Dst.IP != "6.6.6.6" || !n[0].Enforced {
		t.Errorf("network decisions = %+v (the allowed host must not be logged)", n)
	}
	if f := byKind["file"]; len(f) != 1 || f[0].Enforced || !strings.Contains(f[0].Note, "run --enforce") {
		t.Errorf("file decisions = %+v", f)
	}
	// Monitor mode: decisions logged, nothing killed.
	fe.enforced, killed = false, nil
	h.add(30, 10, "git", "/usr/bin/git", "git", "push", "--force", "origin", "x")
	h.m.Handle(sensor.Event{Type: sensor.Exec, PID: 30, PPID: 10, Comm: "git", Path: "/usr/bin/git"})
	if len(killed) != 0 {
		t.Errorf("monitor mode killed %v", killed)
	}
}

func TestControlPermissions(t *testing.T) {
	eng := enforce.NewEngine(enforce.EngineConfig{}) // inactive
	m := NewMonitor(Deps{Get: func(int) (*proc.Process, bool) { return nil, false }}, func(events.Record) {}, nil)
	var written []events.Record
	write := func(r events.Record) { written = append(written, r) }
	call := func(req control.Request, peer control.Peer) control.Response {
		return handleCall(ctlCall{req: req, peer: peer}, eng, m, write, func() {})
	}
	user := control.Peer{UID: 1000, PID: 4242, Known: true}
	root := control.Peer{UID: 0, PID: 1, Known: true}
	for _, op := range []string{control.OpQuarantine, control.OpRelease, control.OpReload} {
		if r := call(control.Request{Op: op, Agent: "codex"}, user); r.OK || !strings.Contains(r.Error, "needs root") {
			t.Errorf("%s by a user: %+v", op, r)
		}
		if r := call(control.Request{Op: op, Agent: "codex"}, control.Peer{}); r.OK {
			t.Errorf("%s by an unknown peer: %+v", op, r)
		}
	}
	if r := call(control.Request{Op: control.OpQuarantine, Agent: "codex"}, root); r.OK || !strings.Contains(r.Error, "not active") {
		t.Errorf("quarantine on an inactive engine: %+v", r)
	}
	if r := call(control.Request{Op: control.OpEnforcePID, PID: 9999, Agent: "x"}, user); r.OK || !strings.Contains(r.Error, "only enforce itself") {
		t.Errorf("enforce another pid: %+v", r)
	}
	if r := call(control.Request{Op: control.OpReport, Record: &events.Record{Type: events.File}}, user); r.OK {
		t.Errorf("report of a non-decision accepted")
	}
	r := call(control.Request{Op: control.OpReport, Record: &events.Record{Type: events.Decision, Kind: "command", Action: "deny", Source: "forged"}}, user)
	if !r.OK || len(written) != 1 || written[0].Source != "claude-hook" || !strings.Contains(written[0].Note, "uid 1000") {
		t.Errorf("report: %+v %+v", r, written)
	}
	if r := call(control.Request{Op: control.OpStatus}, user); !r.OK {
		t.Errorf("status: %+v", r)
	}
}

func TestControlSocketRoundTrip(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("peer credentials are Linux only")
	}
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "c.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go control.Serve(ctx, path, func(req control.Request, peer control.Peer) control.Response {
		return control.OK(map[string]any{"op": req.Op, "uid": peer.UID, "pid": peer.PID, "known": peer.Known})
	})
	var resp control.Response
	for i := 0; i < 50; i++ {
		if resp, err = control.Call(path, control.Request{Op: "status"}, time.Second); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Op    string
		UID   int
		PID   int
		Known bool
	}
	_ = json.Unmarshal(resp.Data, &got)
	if got.Op != "status" || !got.Known || got.UID != os.Getuid() || got.PID != os.Getpid() {
		t.Errorf("peer = %+v", got)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o666 {
		t.Errorf("socket mode %v", st.Mode().Perm())
	}
}

func TestDetectionsInTheMonitor(t *testing.T) {
	h := newHarness(t)
	var threats []events.Record
	h.m.deps.Detect = true
	h.m.deps.OnThreat = func(r events.Record) { threats = append(threats, r) }
	h.m = NewMonitor(h.m.deps, func(r events.Record) { h.recs = append(h.recs, r) }, nil)
	// A renamed ARTEX: found by its variables, followed as an agent, its
	// child (which inherits the variables) not reported twice.
	art := h.add(70, 1, "server", "/opt/x/server", "/opt/x/server")
	art.EnvNames = []string{"ARTEX_BIND_ADDR", "HOME"}
	kid := h.add(71, 70, "sh", "/bin/sh", "sh")
	kid.EnvNames = []string{"ARTEX_BIND_ADDR"}
	h.m.Seed(h.snap)
	var artexDet, artexAgent int
	for _, r := range h.recs {
		if r.Type == events.Detection && r.Rule == "artex_present" {
			artexDet++
		}
		if r.Type == events.AgentStarted && r.Agent.ID == "artex" {
			artexAgent++
		}
	}
	if artexDet != 1 || artexAgent != 1 {
		t.Fatalf("ARTEX: %d detections, %d agents (want 1, 1): %+v", artexDet, artexAgent, h.recs)
	}
	// Claude runs nmap (through a wrapper script: comm is the tool's name).
	h.add(80, 10, "nmap", "/usr/bin/dash", "/bin/sh", "/opt/tools/nmap", "-sV", "10.0.0.0/24")
	h.m.Handle(sensor.Event{Type: sensor.Exec, PID: 80, PPID: 10, Comm: "nmap", Path: "/usr/bin/dash"})
	found := false
	for _, r := range threats {
		if r.Rule == "offensive_tool" && r.Agent != nil && r.Agent.ID == "claude-code" && r.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Errorf("offensive tool not reported: %+v", threats)
	}
	// Fan-out: many destinations in a minute.
	for i := 0; i < 60; i++ {
		h.m.Handle(sensor.Event{Type: sensor.Connect, PID: 10, DstIP: net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)), DstPort: 22})
	}
	fan := false
	for _, r := range h.recs {
		fan = fan || (r.Type == events.Detection && r.Rule == "connection_fanout")
	}
	if !fan {
		t.Error("connection fan-out not detected")
	}
}

func TestPlantedFilesDoNotMakeARTEX(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"data", "skills"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "jwt.key"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	var threats []events.Record
	h.m.deps.Detect = true
	h.m.deps.OnThreat = func(r events.Record) { threats = append(threats, r) }
	h.m = NewMonitor(h.m.deps, func(r events.Record) { h.recs = append(h.recs, r) }, nil)
	// Files next to an ordinary process: never stat'ed, never ARTEX.
	h.add(90, 1, "kubectl", filepath.Join(dir, "kubectl"), filepath.Join(dir, "kubectl"), "get", "pods")
	h.m.Seed(h.snap)
	if len(threats) != 0 {
		t.Fatalf("planted files made a process ARTEX: %+v", threats)
	}
	// In a directory others may write to, the files do not count either.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if ownedFile(os.Getuid())(filepath.Join(dir, "jwt.key")) {
		t.Error("a file in a world-writable directory counted")
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !ownedFile(os.Getuid())(filepath.Join(dir, "jwt.key")) {
		t.Error("the process's own file did not count")
	}
	if ownedFile(os.Getuid()+12345)(filepath.Join(dir, "jwt.key")) && os.Getuid() != 0 {
		t.Error("another user's file counted")
	}
}

func TestStaleMemberIsNotTheAgents(t *testing.T) {
	h := newHarness(t)
	var threats []events.Record
	h.m.deps.Detect = true
	h.m.deps.OnThreat = func(r events.Record) { threats = append(threats, r) }
	h.m = NewMonitor(h.m.deps, func(r events.Record) { h.recs = append(h.recs, r) }, nil)
	h.m.Seed(h.snap)
	h.m.member[60] = 10 // a child of claude that exited; pid 60 is reused
	p := h.add(60, 5, "nmap", "/usr/bin/nmap", "nmap", "-sS", "10.0.0.0/24")
	p.User = "mallory"
	h.m.Handle(sensor.Event{Type: sensor.Exec, PID: 60, PPID: 5, Comm: "nmap", Path: "/usr/bin/nmap"})
	if len(threats) != 0 {
		t.Errorf("a reused pid of another process was attributed to the agent: %+v", threats)
	}
	if _, ok := h.m.member[60]; ok {
		t.Error("stale membership kept")
	}
}
