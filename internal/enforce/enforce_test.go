package enforce

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/policy"
)

// fakeCG records what the engine asked of cgroups.
type fakeCG struct {
	groups map[string][]int
	frozen map[string]bool
	busy   map[string]bool
}

func newFakeCG() *fakeCG {
	return &fakeCG{groups: map[string][]int{}, frozen: map[string]bool{}, busy: map[string]bool{}}
}
func (f *fakeCG) Ensure(n string) error { f.groups[n] = f.groups[n]; return nil }
func (f *fakeCG) Move(n string, pids []int) (int, error) {
	f.groups[n] = append(f.groups[n], pids...)
	return len(pids), nil
}
func (f *fakeCG) Freeze(n string, on bool) error { f.frozen[n] = on; return nil }
func (f *fakeCG) Remove(n string) (bool, error) {
	if f.busy[n] {
		return true, nil
	}
	delete(f.groups, n)
	return false, nil
}
func (f *fakeCG) Rel(n string) string { return "authsec/" + n }
func (f *fakeCG) List() []string {
	var out []string
	for n := range f.groups {
		out = append(out, n)
	}
	return out
}

type fakeFW struct {
	scripts []string
	removed int
}

func (f *fakeFW) Apply(s string) error { f.scripts = append(f.scripts, s); return nil }
func (f *fakeFW) Remove() error        { f.removed++; return nil }
func (f *fakeFW) last() string {
	if len(f.scripts) == 0 {
		return ""
	}
	return f.scripts[len(f.scripts)-1]
}

func mustPolicy(t *testing.T, doc string) *policy.Policy {
	t.Helper()
	p, issues := policy.Parse([]byte(doc))
	if p == nil {
		t.Fatalf("%v", issues)
	}
	for _, i := range issues {
		if !i.Warning {
			t.Fatalf("%v", issues)
		}
	}
	return p
}

func setOf(t *testing.T, docs ...string) policy.Set {
	t.Helper()
	dir := t.TempDir()
	for i, d := range docs {
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".yaml"), []byte(d), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := policy.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return policy.NewSet(files)
}

const gooseEnforce = `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: goose}
mode: enforce
network:
  default: deny
  allow:
    - {host: api.github.com, port: 443}
    - {host: "*.example.org"}
    - {cidr: 10.0.0.0/8, port: 5432}
  deny:
    - {host: evil.example.org}
`

const codexMonitor = `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: codex}
mode: monitor
network: {default: deny}
`

func TestEngineEnforcesOnlyEnforceMode(t *testing.T) {
	cg, fw := newFakeCG(), &fakeFW{}
	var logged []events.Record
	e := NewEngine(EngineConfig{Cgroups: cg, Firewall: fw, Resolvers: []net.IP{net.ParseIP("127.0.0.53")}, Log: func(r events.Record) { logged = append(logged, r) },
		Members: func(top int) []int { return map[int][]int{100: {100, 101}}[top] }})
	e.SetPolicies(setOf(t, gooseEnforce, codexMonitor))
	e.AgentStarted(events.Agent{ID: "goose", PID: 100}, []int{100, 101})
	e.AgentStarted(events.Agent{ID: "codex", PID: 200}, []int{200})
	e.AgentStarted(events.Agent{ID: "claude-code", PID: 300}, []int{300}) // no policy, no default
	// Addresses learnt from DNS: exact, wildcard, denied and unrelated.
	e.DNS("api.github.com", []net.IP{net.ParseIP("140.82.112.6")}, time.Minute)
	e.DNS("cdn.example.org", []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("2606:2800::1")}, time.Minute)
	e.DNS("evil.example.org", []net.IP{net.ParseIP("6.6.6.6")}, time.Minute)
	e.DNS("unrelated.com", []net.IP{net.ParseIP("1.1.1.1")}, time.Minute)
	if err := e.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(cg.groups) != 1 || len(cg.groups["goose-100"]) != 2 {
		t.Fatalf("groups = %v", cg.groups)
	}
	s := fw.last()
	for _, want := range []string{
		`socket cgroupv2 level 2 "authsec/goose-100" jump g_goose_100`,
		"140.82.112.6 . 443", "93.184.216.34", "2606:2800::1", "10.0.0.0/8 . 5432",
		"6.6.6.6", "127.0.0.53",
		"delete table inet authsec",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "1.1.1.1") || strings.Contains(s, "codex") {
		t.Errorf("unrelated address or monitor-mode agent in the rules:\n%s", s)
	}
	if on, p := e.Enforcing(100, "goose"); !on || p == nil {
		t.Error("goose not enforcing")
	}
	if on, _ := e.Enforcing(200, "codex"); on {
		t.Error("monitor-mode codex enforcing")
	}
	if e.HostOf("140.82.112.6") != "api.github.com" {
		t.Error("HostOf")
	}
	// Stopping: the group goes once empty, the table once nothing is left.
	e.AgentStopped(100)
	e.Tick()
	_ = e.Flush()
	if len(cg.groups) != 0 || fw.removed == 0 {
		t.Errorf("after stop: groups %v, removed %d", cg.groups, fw.removed)
	}
}

func TestQuarantineFreezesPersistsAndReleases(t *testing.T) {
	cg, fw := newFakeCG(), &fakeFW{}
	statePath := filepath.Join(t.TempDir(), "state.json")
	e := NewEngine(EngineConfig{Cgroups: cg, Firewall: fw, StatePath: statePath})
	e.SetPolicies(setOf(t, codexMonitor))
	e.AgentStarted(events.Agent{ID: "codex", PID: 200}, []int{200})
	if n, err := e.Quarantine("codex", 0); err != nil || n != 1 {
		t.Fatalf("quarantine: %d %v", n, err)
	}
	if !cg.frozen["codex-200"] || !strings.Contains(fw.last(), "authsec quarantine g_codex_200") {
		t.Fatalf("not frozen/isolated: %v\n%s", cg.frozen, fw.last())
	}
	// A new engine (daemon restart) remembers; a new instance is quarantined.
	e2 := NewEngine(EngineConfig{Cgroups: cg, Firewall: fw, StatePath: statePath})
	e2.SetPolicies(setOf(t, codexMonitor))
	e2.AgentStarted(events.Agent{ID: "codex", PID: 300}, []int{300})
	_ = e2.Flush()
	if !cg.frozen["codex-300"] {
		t.Error("restarted agent not quarantined after a daemon restart")
	}
	if n, _ := e2.Release("codex", 0); n != 1 || cg.frozen["codex-300"] {
		t.Errorf("release: %d frozen %v", n, cg.frozen)
	}
	b, _ := os.ReadFile(statePath)
	var st state
	_ = json.Unmarshal(b, &st)
	if len(st.QuarantinedAgents) != 0 {
		t.Errorf("state after release: %s", b)
	}
	// Monitor mode after release: no group is left, so the table is removed.
	if fw.removed == 0 {
		t.Errorf("released monitor-mode agent: table not removed (last script:\n%s)", fw.last())
	}
}

func TestBrokenPolicyKeepsLastGood(t *testing.T) {
	cg, fw := newFakeCG(), &fakeFW{}
	e := NewEngine(EngineConfig{Cgroups: cg, Firewall: fw})
	e.SetPolicies(setOf(t, gooseEnforce))
	e.AgentStarted(events.Agent{ID: "goose", PID: 100}, []int{100})
	_ = e.Flush()
	e.SetPolicies(setOf(t, strings.Replace(gooseEnforce, "mode: enforce", "mode: oops", 1)))
	_ = e.Flush()
	if on, p := e.Enforcing(100, "goose"); !on || p == nil {
		t.Error("a broken file lifted enforcement")
	}
	if !strings.Contains(fw.last(), "g_goose_100") {
		t.Error("rules dropped after a broken reload")
	}
}

func TestForceAndInactiveEngine(t *testing.T) {
	cg, fw := newFakeCG(), &fakeFW{}
	e := NewEngine(EngineConfig{Cgroups: cg, Firewall: fw})
	e.SetPolicies(setOf(t, codexMonitor))
	if err := e.Force(555, "codex"); err != nil {
		t.Fatal(err)
	}
	if on, _ := e.Enforcing(555, "codex"); !on || len(cg.groups["codex-555"]) != 1 {
		t.Errorf("forced run not enforced: %v", cg.groups)
	}
	// Forced with no policy at all: nothing goes out.
	if err := e.Force(556, "nobody-knows"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fw.last(), "authsec quarantine g_nobody-knows_556") && !strings.Contains(fw.last(), "g_nobody_knows_556") {
		t.Errorf("forced without a policy:\n%s", fw.last())
	}
	off := NewEngine(EngineConfig{})
	if _, err := off.Quarantine("codex", 0); err == nil {
		t.Error("an inactive engine accepted a quarantine")
	}
	if err := off.Force(1, "x"); err == nil {
		t.Error("an inactive engine accepted a forced run")
	}
}

func TestScriptRules(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.0.0.0/8")
	s := Script([]NetRules{
		{Name: "a-1", Cgroup: "authsec/a-1", Allow: []Elem{{Net: n, PortLo: 443, PortHi: 443}}},
		{Name: "b-2", Cgroup: "authsec/b-2", DefaultAllow: true},
		{Name: "c-3", Cgroup: "authsec/c-3", Quarantine: true},
	})
	for _, want := range []string{"chain g_a_1 {", "10.0.0.0/8 . 443", "ct state established,related accept", "reject with icmpx admin-prohibited",
		"chain g_b_2 {", "\t\taccept\n", "chain g_c_3 {", "authsec quarantine g_c_3", "type filter hook output priority filter; policy accept;"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	if Script(nil) == "" || !strings.Contains(Script(nil), "chain output") {
		t.Error("empty script")
	}
}

func TestGroupNames(t *testing.T) {
	for in, want := range map[string]string{"claude-code": "claude-code-7", "Weird ID!": "weird_id_-7", "": "agent-7"} {
		if got := GroupName(in, 7); got != want || !validName(got) {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestResolvers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(p, []byte("# x\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nsearch lan\n"), 0o644)
	r := Resolvers(p)
	if len(r) != 2 || r[0].String() != "127.0.0.53" || r[1].String() != "fe80::1" {
		t.Errorf("%v", r)
	}
}

func TestClaudeHookDecisions(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "proj")
	_ = os.MkdirAll(filepath.Join(proj, ".git"), 0o755)
	p := mustPolicy(t, `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: claude-code}
mode: enforce
network:
  default: deny
  allow: [{host: docs.example.com, port: 443}]
filesystem:
  read_write: ["{project}"]
  deny: ["{home}/.ssh"]
commands:
  default: allow
  ask: ["terraform apply*"]
  deny: ["git push --force*"]
mcp_servers:
  default: deny
  allow: [github]
`)
	in := func(tool string, input map[string]any) HookInput {
		return HookInput{Cwd: filepath.Join(proj, "sub"), ToolName: tool, ToolInput: input}
	}
	for _, c := range []struct {
		in   HookInput
		want string
	}{
		{in("Bash", map[string]any{"command": "cd x && git push --force"}), policy.Deny},
		{in("Bash", map[string]any{"command": "terraform apply"}), policy.Ask},
		{in("Bash", map[string]any{"command": "ls"}), policy.Allow},
		{in("WebFetch", map[string]any{"url": "https://docs.example.com/a"}), policy.Allow},
		{in("WebFetch", map[string]any{"url": "http://docs.example.com/a"}), policy.Allow}, // WebFetch upgrades to https
		{in("WebFetch", map[string]any{"url": "https://docs.example.com:8443/a"}), policy.Deny},
		{in("WebFetch", map[string]any{"url": "https://evil.com/"}), policy.Deny},
		{in("WebFetch", map[string]any{"url": "::not a url"}), policy.Deny},
		{in("Read", map[string]any{"file_path": "/home/u/.ssh/id_rsa"}), policy.Deny},
		{in("Edit", map[string]any{"file_path": "main.go"}), policy.Allow}, // relative to cwd, inside the project
		{in("Write", map[string]any{"file_path": "/etc/passwd"}), policy.Deny},
		{in("Read", map[string]any{"file_path": "/usr/include/stdio.h"}), policy.Allow},
		{in("Grep", map[string]any{"path": "/home/u/.ssh"}), policy.Deny},
		{in("mcp__github__create_issue", nil), policy.Allow},
		{in("mcp__slack__post", nil), policy.Deny},
		{in("TodoWrite", nil), policy.Allow},
	} {
		d := DecideClaudeTool(p, c.in, "/home/u")
		if d.Action != c.want {
			t.Errorf("%s %v: %+v, want %s", c.in.ToolName, c.in.ToolInput, d, c.want)
		}
	}
	out := HookOutput(HookDecision{Decision: policy.Decision{Action: policy.Deny, Rule: "r"}, Kind: "command", What: "x"}, policy.Enforce)
	var o struct {
		HSO map[string]string `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(out, &o) != nil || o.HSO["permissionDecision"] != "deny" || o.HSO["hookEventName"] != "PreToolUse" {
		t.Errorf("hook output %s", out)
	}
	if HookOutput(HookDecision{Decision: policy.Decision{Action: policy.Deny}}, policy.Monitor) != nil {
		t.Error("monitor mode must print nothing")
	}
	s, _ := ClaudeManagedSettings(p, "/usr/local/bin/authsec-cli hook claude-pretooluse")
	b, _ := json.Marshal(s)
	for _, want := range []string{`"onFailure":"block"`, `"matcher":"*"`, `"allowedMcpServers":[{"serverName":"github"}]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("settings lack %s: %s", want, b)
		}
	}
	p.Mode = policy.Monitor
	s, notes := ClaudeManagedSettings(p, "x")
	if _, ok := s["allowedMcpServers"]; ok || len(notes) == 0 {
		t.Errorf("monitor mode set MCP lists: %v %v", s, notes)
	}
}

func TestPlanSandbox(t *testing.T) {
	p := mustPolicy(t, `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: claude-code}
mode: monitor
network:
  default: deny
  allow: [{host: api.anthropic.com, port: 443}, {cidr: 10.0.0.0/8, port: 5432}]
filesystem:
  read_write: ["{project}"]
  read_only: ["{home}/notes"]
  deny: ["{home}/.ssh", "{project}/.env", "{home}/notes/private"]
`)
	plan := PlanSandbox(p, "/home/u", "/work/app", "")
	has := func(list []string, x string) bool {
		for _, v := range list {
			if v == x {
				return true
			}
		}
		return false
	}
	if !has(plan.Sandbox.ReadWrite, "/work/app") || !has(plan.Sandbox.ReadWrite, "/home/u/.claude") || !has(plan.Sandbox.ReadOnly, "/usr") {
		t.Errorf("sandbox = %+v", plan.Sandbox)
	}
	if !plan.Sandbox.RestrictNet || len(plan.Sandbox.ConnectPorts) != 3 {
		t.Errorf("ports = %v", plan.Sandbox.ConnectPorts)
	}
	w := strings.Join(plan.Warnings, "\n")
	if !strings.Contains(w, "deny /work/app/.env cannot be enforced") || !strings.Contains(w, "deny /home/u/notes/private cannot be enforced") {
		t.Errorf("warnings = %s", w)
	}
	for _, x := range append(plan.Sandbox.ReadOnly, plan.Sandbox.ReadWrite...) {
		if x == "/home/u" || x == "/home/u/.ssh" {
			t.Errorf("home or a denied path allowed: %s", x)
		}
	}
	p.Network.Allow = append(p.Network.Allow, policy.Rule{Host: "x.example.com"})
	if PlanSandbox(p, "/home/u", "/w", "").Sandbox.RestrictNet {
		t.Error("ports restricted although a rule allows any port")
	}
}

func TestCgroupsOnAFakeTree(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "cgroup.controllers"), nil, 0o644)
	c := Cgroups{Root: root}
	if err := c.Available(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ensure("goose-1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Ensure("../escape"); err == nil {
		t.Error("bad name accepted")
	}
	dir := filepath.Join(root, CgroupParent, "goose-1")
	_ = os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("0"), 0o644)
	if err := c.Freeze("goose-1", true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "cgroup.freeze")); string(b) != "1" {
		t.Errorf("freeze = %q", b)
	}
	if got := c.List(); len(got) != 1 || got[0] != "goose-1" {
		t.Errorf("list = %v", got)
	}
	if c.Rel("goose-1") != "authsec/goose-1" {
		t.Error("rel")
	}
}

func TestDay4ReviewEngine(t *testing.T) {
	cg, fw := newFakeCG(), &fakeFW{}
	members := map[int][]int{200: {200, 201, 202}}
	starts := map[int]uint64{200: 7, 300: 9}
	var destroyed [][]int
	e := NewEngine(EngineConfig{Cgroups: cg, Firewall: fw, Resolvers: []net.IP{net.ParseIP("127.0.0.53")},
		Members:        func(top int) []int { return members[top] },
		Alive:          func(pid int) (uint64, bool) { s, ok := starts[pid]; return s, ok },
		DestroySockets: func(p []int) (int, error) { destroyed = append(destroyed, p); return 2, nil }})
	e.SetPolicies(setOf(t, codexMonitor, gooseEnforce))
	e.AgentStarted(events.Agent{ID: "codex", PID: 200}, nil)
	// Quarantine of a monitor-mode agent moves its whole tree and closes
	// its existing connections.
	if n, err := e.Quarantine("codex", 0); n != 1 || err != nil {
		t.Fatalf("quarantine: %d %v", n, err)
	}
	if got := cg.groups["codex-200-7"]; len(got) != 3 {
		t.Fatalf("group = %v, want the whole tree", cg.groups)
	}
	if len(destroyed) != 1 || len(destroyed[0]) != 3 {
		t.Errorf("sockets not closed: %v", destroyed)
	}
	// A child that appears later is moved by Tick.
	members[200] = append(members[200], 203)
	e.Tick()
	if got := cg.groups["codex-200-7"]; got[len(got)-1] != 203 {
		t.Errorf("late child not moved: %v", got)
	}
	// Release by pid while quarantined by id: stays frozen, reported.
	if _, err := e.Release("", 200); err == nil || !cg.frozen["codex-200-7"] {
		t.Errorf("release by pid of an id quarantine: err %v frozen %v", err, cg.frozen["codex-200-7"])
	}
	if n, err := e.Release("codex", 0); n != 1 || err != nil || cg.frozen["codex-200-7"] {
		t.Errorf("release by id: %d %v", n, err)
	}
	// The pid is reused by another process: the old group is retired.
	starts[200] = 99
	e.Tick()
	if _, ok := e.known[200]; ok {
		t.Error("a reused pid kept the old instance")
	}
	// run --enforce keeps the policy it asked for when the agent is recognised.
	members[300] = []int{300}
	if err := e.Force(300, "goose"); err != nil {
		t.Fatal(err)
	}
	e.AgentStarted(events.Agent{ID: "codex", PID: 300}, nil)
	if on, p := e.Enforcing(300, "codex"); !on || p == nil || p.Agent.ID != "goose" {
		t.Errorf("forced policy lost: %v %+v", on, p)
	}
	if err := e.Force(0, "x"); err == nil {
		t.Error("pid 0 accepted")
	}
	// DNS: only answers from the resolvers count.
	if !e.TrustedDNS(net.ParseIP("127.0.0.53")) || !e.TrustedDNS(net.ParseIP("127.0.0.1")) || e.TrustedDNS(net.ParseIP("6.6.6.6")) || e.TrustedDNS(nil) {
		t.Error("TrustedDNS")
	}
}

func TestLeftoverGroupsAreThawedAndBrokenDefaultKept(t *testing.T) {
	cg, fw := newFakeCG(), &fakeFW{}
	cg.groups["codex-9-1"] = []int{9}
	cg.frozen["codex-9-1"] = true
	e := NewEngine(EngineConfig{Cgroups: cg, Firewall: fw})
	if cg.frozen["codex-9-1"] {
		t.Error("a leftover group was not thawed at start")
	}
	def := `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: "*"}
mode: enforce
network: {default: deny}
`
	e.SetPolicies(setOf(t, def))
	e.AgentStarted(events.Agent{ID: "aider", PID: 50}, nil)
	_ = e.Flush()
	e.SetPolicies(setOf(t, strings.Replace(def, "mode: enforce", "mode: oops", 1)))
	if on, p := e.Enforcing(50, "aider"); !on || p == nil {
		t.Error("a broken default lifted enforcement")
	}
}

func TestScriptNormalisesOverlaps(t *testing.T) {
	mk := func(c string, lo, hi int) Elem {
		_, n, _ := net.ParseCIDR(c)
		return Elem{Net: n, PortLo: lo, PortHi: hi}
	}
	s := Script([]NetRules{{Name: "x-1", Cgroup: "authsec/x-1", Allow: []Elem{
		mk("10.0.0.0/8", 443, 443), mk("10.1.0.0/16", 443, 443), mk("10.1.2.3/32", 0, 65535),
		mk("10.0.0.0/8", 443, 443), mk("::ffff:192.0.2.1/128", 80, 80), mk("2001:db8::/32", 0, 65535), mk("2001:db8:1::/48", 22, 22),
	}}})
	for _, want := range []string{"10.0.0.0/8 . 443", "10.1.2.3", "192.0.2.1 . 80", "2001:db8::/32", "auto-merge", "chain in_g_x_1", "ct state established,related accept", "ip daddr @g_x_1_a4any accept"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
	for _, bad := range []string{"10.1.0.0/16 . 443", "2001:db8:1::/48", "::ffff"} {
		if strings.Contains(s, bad) {
			t.Errorf("overlapping or mapped element %q kept:\n%s", bad, s)
		}
	}
}

// A project reached through a symlink (macOS /var -> /private/var, a linked
// home) is still the project; a denied folder behind a link is still denied.
func TestClaudeHookFollowsLinkedProject(t *testing.T) {
	real := t.TempDir()
	proj := filepath.Join(real, "proj")
	secret := filepath.Join(real, "secret")
	for _, d := range []string{filepath.Join(proj, ".git"), secret} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(t.TempDir(), "via")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks: %v", err)
	}
	p := mustPolicy(t, `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: claude-code}
mode: enforce
network: {default: deny}
filesystem:
  read_write: ['`+filepath.Join(link, "proj")+`']
  deny: ['`+filepath.Join(link, "secret")+`']
commands: {default: allow}
mcp_servers: {default: deny}
`)
	in := HookInput{Cwd: filepath.Join(link, "proj"), ToolName: "Edit", ToolInput: map[string]any{"file_path": "main.go"}}
	if d := DecideClaudeTool(p, in, "/home/u"); d.Action != policy.Allow {
		t.Errorf("edit in the linked project: %+v", d)
	}
	in = HookInput{Cwd: proj, ToolName: "Read", ToolInput: map[string]any{"file_path": filepath.Join(secret, "k")}}
	if d := DecideClaudeTool(p, in, "/home/u"); d.Action != policy.Deny {
		t.Errorf("read of the denied folder by its real path: %+v", d)
	}
}
