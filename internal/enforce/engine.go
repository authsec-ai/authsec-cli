package enforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/policy"
)

// CgroupAPI is the part of Cgroups the engine uses (faked in tests).
type CgroupAPI interface {
	Ensure(name string) error
	Move(name string, pids []int) (int, error)
	Freeze(name string, on bool) error
	Remove(name string) (busy bool, err error)
	Rel(name string) string
	List() []string
}

// Limits.
const (
	maxForced = 256              // run --enforce registrations alive at once
	dnsMinTTL = 10 * time.Minute // CDNs rotate addresses: keep recent ones
	dnsMaxTTL = time.Hour        // an answer never vouches for longer
)

// Engine keeps the enforcement state of the running agents and turns it
// into cgroups and nftables rules. It is driven from the daemon's single
// goroutine and is not safe for concurrent use.
type Engine struct {
	cfg EngineConfig

	set      policy.Set
	lastGood map[string]*policy.Policy // agent id ("*" too) -> last usable policy

	known   map[int]instance // running agent instances by top pid
	groups  map[int]*group   // groups of running instances by top pid
	retired []*group         // groups of stopped instances, removed once empty
	forced  map[int]instance // run --enforce registrations (agent.ID is the policy)
	qAgents map[string]bool  // quarantined agent ids (persisted)
	qPIDs   map[int]bool     // quarantined instances
	dns     map[string]map[string]time.Time

	dirty      bool
	tableEmpty bool
	failUntil  time.Time // back off after a failed apply
	failDelay  time.Duration
	LastError  string
}

type instance struct {
	agent events.Agent
	start uint64 // process start time (boot ticks); 0 if unknown
}

type group struct {
	agent       events.Agent
	top         int
	start       uint64
	name        string
	active      bool // in nftables (enforced or quarantined)
	quarantined bool
}

// EngineConfig configures an engine. Without Cgroups and Firewall it decides
// and logs only.
type EngineConfig struct {
	Cgroups   CgroupAPI
	Firewall  Firewall
	Resolvers []net.IP
	StatePath string
	Log       func(events.Record)
	Now       func() time.Time
	// Members returns an instance's processes now (top first); nil means
	// just the top.
	Members func(top int) []int
	// Alive returns a process's start time, false when it is gone.
	Alive func(pid int) (uint64, bool)
	// DestroySockets closes the TCP and UDP sockets the processes hold
	// (they were opened outside the group, so its rules never see them).
	DestroySockets func(pids []int) (int, error)
}

// NewEngine creates an engine, loads the persisted quarantine list and, when
// active, thaws and adopts groups a previous daemon left behind.
func NewEngine(c EngineConfig) *Engine {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = func(events.Record) {}
	}
	e := &Engine{cfg: c, lastGood: map[string]*policy.Policy{}, known: map[int]instance{}, groups: map[int]*group{},
		forced: map[int]instance{}, qAgents: map[string]bool{}, qPIDs: map[int]bool{}, dns: map[string]map[string]time.Time{},
		tableEmpty: true}
	e.loadState()
	if e.Active() {
		for _, name := range c.Cgroups.List() {
			_ = c.Cgroups.Freeze(name, false) // a crashed daemon may have left it frozen
			e.retired = append(e.retired, &group{name: name})
		}
	}
	return e
}

// Active reports whether the engine can enforce (cgroups and firewall).
func (e *Engine) Active() bool { return e.cfg.Cgroups != nil && e.cfg.Firewall != nil }

// SetPolicies installs a new policy set. An agent whose file became broken
// keeps its last usable policy, so a typo never lifts enforcement.
func (e *Engine) SetPolicies(s policy.Set) {
	for _, id := range s.SortedIDs() {
		if p, err := s.For(id); err == nil && p != nil {
			e.lastGood[id] = p
		}
	}
	e.set = s
	for top := range e.known {
		_ = e.evaluate(top, false)
	}
	e.dirty = true
}

// Policy returns the policy that applies to an agent: its own; if that (or
// the default) is broken, the last usable one; else the default.
func (e *Engine) Policy(agentID string) *policy.Policy {
	p, err := e.set.For(agentID)
	if err == nil {
		return p
	}
	if lg := e.lastGood[agentID]; lg != nil {
		return lg
	}
	return e.lastGood[policy.AnyAgent]
}

// policyID is the policy an instance is enforced by: the one a re-run asked
// for, else the recognised agent's.
func (e *Engine) policyID(top int) string {
	if f, ok := e.forced[top]; ok {
		return f.agent.ID
	}
	return e.known[top].agent.ID
}

// Enforcing reports whether an agent instance is enforced (its denials
// block) and the policy that applies.
func (e *Engine) Enforcing(top int, agentID string) (bool, *policy.Policy) {
	f, forced := e.forced[top]
	if forced {
		agentID = f.agent.ID
	}
	p := e.Policy(agentID)
	g := e.groups[top]
	if g == nil || !g.active || !e.Active() {
		return false, p
	}
	return forced || g.quarantined || (p != nil && p.Mode == policy.Enforce), p
}

func (e *Engine) startOf(pid int) uint64 {
	if e.cfg.Alive == nil {
		return 0
	}
	s, _ := e.cfg.Alive(pid)
	return s
}

// AgentStarted puts an agent into enforcement if its policy or a
// quarantine says so.
func (e *Engine) AgentStarted(a events.Agent, _ []int) {
	start := e.startOf(a.PID)
	if f, ok := e.forced[a.PID]; ok && f.start != 0 && start != 0 && f.start != start {
		delete(e.forced, a.PID) // the pid was reused
	}
	if g := e.groups[a.PID]; g != nil && g.start != start {
		e.retire(a.PID)
	}
	e.known[a.PID] = instance{agent: a, start: start}
	_ = e.evaluate(a.PID, false)
}

// AgentStopped forgets an instance; its group is removed once empty.
func (e *Engine) AgentStopped(pid int) {
	delete(e.known, pid)
	delete(e.qPIDs, pid)
	delete(e.forced, pid)
	e.retire(pid)
}

func (e *Engine) retire(top int) {
	if g := e.groups[top]; g != nil {
		delete(e.groups, top)
		e.retired = append(e.retired, g)
		e.dirty = true
	}
}

// Force enforces one process (a re-run agent registering itself before it
// execs) with agentID's policy, whatever its mode.
func (e *Engine) Force(pid int, agentID string) error {
	if !e.Active() {
		return errors.New("enforcement is not active (daemon not root, or no cgroup v2/nftables)")
	}
	if pid <= 0 || agentID == "" {
		return errors.New("enforce_pid needs a pid and an agent id")
	}
	if _, ok := e.forced[pid]; !ok && len(e.forced) >= maxForced {
		return fmt.Errorf("too many processes registered with run --enforce (%d)", maxForced)
	}
	start, alive := uint64(0), true
	if e.cfg.Alive != nil {
		start, alive = e.cfg.Alive(pid)
	}
	if !alive {
		return fmt.Errorf("no process %d", pid)
	}
	a := events.Agent{ID: agentID, Name: agentID, PID: pid}
	e.forced[pid] = instance{agent: a, start: start}
	if k, ok := e.known[pid]; !ok || k.start != start {
		e.known[pid] = instance{agent: a, start: start}
	}
	if err := e.evaluate(pid, true); err != nil {
		delete(e.forced, pid)
		return err
	}
	return e.Flush()
}

// Quarantine freezes and isolates agents: by id (every instance, now and
// later; persisted) or by pid (one instance). It returns how many running
// instances were quarantined.
func (e *Engine) Quarantine(agentID string, pid int) (int, error) {
	if !e.Active() {
		return 0, errors.New("enforcement is not active (daemon not root, or no cgroup v2/nftables)")
	}
	if pid != 0 {
		if _, ok := e.known[pid]; !ok {
			return 0, fmt.Errorf("no running agent with pid %d", pid)
		}
		e.qPIDs[pid] = true
	}
	if agentID != "" {
		e.qAgents[agentID] = true
		e.saveState()
	}
	n := 0
	var errs []string
	for top, inst := range e.known {
		if inst.agent.ID != agentID && top != pid {
			continue
		}
		a := inst.agent
		if err := e.evaluate(top, false); err != nil {
			errs = append(errs, fmt.Sprintf("%s (pid %d): %v", a.ID, top, err))
			continue
		}
		n++
		e.cfg.Log(events.Record{Type: events.Decision, Kind: "agent", Action: "quarantine", Agent: &a, PID: top, Enforced: true, Source: "daemon"})
	}
	if err := e.Flush(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return n, errors.New(strings.Join(errs, "; "))
	}
	return n, nil
}

// Release lifts a quarantine (by id or pid). An instance still quarantined
// another way (its id, when released by pid) stays frozen and is not
// counted.
func (e *Engine) Release(agentID string, pid int) (int, error) {
	if agentID != "" {
		delete(e.qAgents, agentID)
		e.saveState()
	}
	if pid != 0 {
		delete(e.qPIDs, pid)
	}
	n, still := 0, 0
	for top, inst := range e.known {
		if inst.agent.ID != agentID && top != pid {
			continue
		}
		if e.quarantinedInst(top) {
			still++
			continue
		}
		if g := e.groups[top]; g != nil && e.Active() {
			_ = e.cfg.Cgroups.Freeze(g.name, false)
		}
		_ = e.evaluate(top, false)
		n++
		a := inst.agent
		e.cfg.Log(events.Record{Type: events.Decision, Kind: "agent", Action: "release", Agent: &a, PID: top, Source: "daemon"})
	}
	// Groups of stopped instances keep their leftover processes frozen
	// until released.
	for _, g := range e.retired {
		if (agentID != "" && g.agent.ID == agentID) || (pid != 0 && g.top == pid) {
			if e.Active() {
				_ = e.cfg.Cgroups.Freeze(g.name, false)
			}
			g.quarantined = false
			e.dirty = true
		}
	}
	var err error
	if e.Active() {
		err = e.Flush()
	}
	if still > 0 && err == nil {
		err = fmt.Errorf("%d instance(s) stay quarantined by agent id: release the id (%s)", still, e.known[pid].agent.ID)
	}
	return n, err
}

func (e *Engine) quarantinedInst(top int) bool {
	return e.qAgents[e.known[top].agent.ID] || e.qPIDs[top]
}

// evaluate decides whether an instance must be in an enforced group and
// puts its whole current process tree there. beforeExec is a re-run that
// registers before it starts the agent (it has no connections to close).
func (e *Engine) evaluate(top int, beforeExec bool) error {
	if !e.Active() {
		return nil
	}
	inst, ok := e.known[top]
	if !ok {
		return nil
	}
	p := e.Policy(e.policyID(top))
	_, forced := e.forced[top]
	q := e.quarantinedInst(top)
	want := q || forced || (p != nil && p.Mode == policy.Enforce)
	g := e.groups[top]
	if !want {
		if g != nil && g.active {
			g.active = false
			e.dirty = true
		}
		return nil
	}
	if g == nil {
		name := GroupName(e.policyID(top), top)
		if inst.start != 0 {
			name += "-" + strconv.FormatUint(inst.start%1000000, 10)
		}
		if err := e.cfg.Cgroups.Ensure(name); err != nil {
			e.fail("cgroup %s: %v", name, err)
			return err
		}
		g = &group{agent: inst.agent, top: top, start: inst.start, name: name}
		e.groups[top] = g
	}
	g.agent = inst.agent
	pids := e.members(top)
	moved, err := e.cfg.Cgroups.Move(g.name, pids)
	if moved == 0 {
		if err == nil {
			err = errors.New("no process left to move")
		}
		e.fail("move %s into %s: %v", inst.agent.ID, g.name, err)
		return err
	}
	if !beforeExec && !g.active && e.cfg.DestroySockets != nil {
		// Sockets opened before the move keep their old cgroup, so the
		// group's rules never see them: close them.
		if n, err := e.cfg.DestroySockets(pids); err != nil {
			e.cfg.Log(events.Record{Type: events.Sensor, Agent: &g.agent, PID: top,
				Note: fmt.Sprintf("connections opened before enforcement could not be closed (%v): they are not covered by the rules until they end", err)})
		} else if n > 0 {
			e.cfg.Log(events.Record{Type: events.Decision, Kind: "network", Action: "close", Agent: &g.agent, PID: top, Enforced: true, Source: "daemon",
				Note: fmt.Sprintf("%d connections opened before enforcement were closed", n)})
		}
	}
	if err := e.cfg.Cgroups.Freeze(g.name, q); err != nil {
		e.fail("freeze %s: %v", g.name, err)
		return err
	}
	g.quarantined = q
	g.active = true
	e.dirty = true
	return nil
}

func (e *Engine) members(top int) []int {
	if e.cfg.Members != nil {
		if m := e.cfg.Members(top); len(m) > 0 {
			return m
		}
	}
	return []int{top}
}

// TrustedDNS reports whether a DNS answer's source is one of the configured
// resolvers (answers from anywhere else could forge allowed addresses).
// With a loopback stub resolver, answers come from loopback.
func (e *Engine) TrustedDNS(src net.IP) bool {
	if src == nil {
		return false
	}
	for _, r := range e.cfg.Resolvers {
		if r.Equal(src) || (r.IsLoopback() && src.IsLoopback()) {
			return true
		}
	}
	return false
}

// DNS records what a name resolved to, for the host rules of the policies.
// Names no policy names are ignored.
func (e *Engine) DNS(name string, ips []net.IP, ttl time.Duration) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !e.relevant(name) {
		return
	}
	if ttl < dnsMinTTL {
		ttl = dnsMinTTL
	}
	if ttl > dnsMaxTTL {
		ttl = dnsMaxTTL
	}
	m := e.dns[name]
	if m == nil {
		m = map[string]time.Time{}
		e.dns[name] = m
	}
	for _, ip := range ips {
		k := ip.String()
		if v4 := ip.To4(); v4 != nil {
			k = v4.String()
		}
		if _, had := m[k]; !had {
			e.dirty = true
		}
		m[k] = e.cfg.Now().Add(ttl)
	}
}

func (e *Engine) relevant(name string) bool {
	for _, p := range e.allPolicies() {
		for _, r := range append(append([]policy.Rule(nil), p.Network.Allow...), p.Network.Deny...) {
			if r.Host != "" && policy.HostMatches(r.Host, name) {
				return true
			}
		}
	}
	return false
}

// allPolicies are every policy that may apply: the usable ones and the last
// good ones of broken files. Addresses are learnt for all of them, so they
// are ready before an agent starts.
func (e *Engine) allPolicies() []*policy.Policy {
	var out []*policy.Policy
	seen := map[string]bool{}
	for _, id := range e.set.SortedIDs() {
		if p, err := e.set.For(id); err == nil && p != nil {
			out = append(out, p)
			seen[id] = true
		}
	}
	for id, p := range e.lastGood {
		if !seen[id] {
			out = append(out, p)
		}
	}
	return out
}

// HostOf names an address from the resolved hosts ("" if unknown), so
// decisions use the same names as the rules.
func (e *Engine) HostOf(ip string) string {
	best := ""
	for name, ips := range e.dns {
		if _, ok := ips[ip]; ok && (best == "" || name < best) {
			best = name
		}
	}
	return best
}

// Hosts are the exact host names the policies name: the daemon resolves
// them ahead of the agents (wildcards are learnt from DNS answers).
func (e *Engine) Hosts() []string {
	seen := map[string]bool{}
	for _, p := range e.allPolicies() {
		for _, r := range append(append([]policy.Rule(nil), p.Network.Allow...), p.Network.Deny...) {
			if r.Host != "" && !strings.HasPrefix(r.Host, "*.") {
				seen[strings.ToLower(r.Host)] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Tick forgets instances whose process is gone (or was replaced), moves
// processes that joined an enforced instance since the last move, expires
// DNS entries and removes empty groups of stopped instances.
func (e *Engine) Tick() {
	now := e.cfg.Now()
	if e.cfg.Alive != nil {
		for top, inst := range e.known {
			if start, ok := e.cfg.Alive(top); !ok || (inst.start != 0 && start != inst.start) {
				e.AgentStopped(top)
			}
		}
		for pid, f := range e.forced {
			if start, ok := e.cfg.Alive(pid); !ok || (f.start != 0 && start != f.start) {
				e.AgentStopped(pid)
			}
		}
	}
	if e.Active() {
		for top, g := range e.groups {
			if g.active {
				_, _ = e.cfg.Cgroups.Move(g.name, e.members(top))
			}
		}
	}
	for name, m := range e.dns {
		for ip, exp := range m {
			if now.After(exp) {
				delete(m, ip)
				e.dirty = true
			}
		}
		if len(m) == 0 {
			delete(e.dns, name)
		}
	}
	if e.Active() {
		kept := e.retired[:0]
		for _, g := range e.retired {
			if g.quarantined {
				kept = append(kept, g) // frozen leftovers wait for release
				continue
			}
			_ = e.cfg.Cgroups.Freeze(g.name, false)
			if busy, _ := e.cfg.Cgroups.Remove(g.name); busy {
				kept = append(kept, g)
			} else {
				e.dirty = true
			}
		}
		e.retired = kept
	}
}

// Rules builds the nftables rules of the active groups. Groups of stopped
// instances that still hold processes keep their last rules.
func (e *Engine) Rules() []NetRules {
	var out []NetRules
	add := func(g *group, id string) {
		nr := NetRules{Name: g.name, Cgroup: e.cfg.Cgroups.Rel(g.name), Resolvers: e.cfg.Resolvers}
		if g.quarantined {
			nr.Quarantine = true
			out = append(out, nr)
			return
		}
		p := e.Policy(id)
		if p == nil {
			nr.Quarantine = true // enforced with no usable policy: nothing goes out
			out = append(out, nr)
			return
		}
		nr.DefaultAllow = p.Network.Default == policy.Allow
		nr.Allow = e.elems(p.Network.Allow)
		nr.Deny = e.elems(p.Network.Deny)
		out = append(out, nr)
	}
	for top, g := range e.groups {
		if g.active {
			add(g, e.policyID(top))
		}
	}
	for _, g := range e.retired {
		if g.active || g.quarantined {
			add(g, g.agent.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (e *Engine) elems(rules []policy.Rule) []Elem {
	var out []Elem
	for _, r := range rules {
		lo, hi := r.Port, r.Port
		if r.Port == 0 {
			lo, hi = 0, 65535
		}
		if r.CIDR != "" {
			if _, n, err := net.ParseCIDR(r.CIDR); err == nil {
				out = append(out, Elem{Net: n, PortLo: lo, PortHi: hi})
			}
			continue
		}
		for name, ips := range e.dns {
			if !policy.HostMatches(r.Host, name) {
				continue
			}
			for ip := range ips {
				if parsed := net.ParseIP(ip); parsed != nil {
					out = append(out, Elem{Net: hostNet(parsed), PortLo: lo, PortHi: hi})
				}
			}
		}
	}
	return out
}

func hostNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

// Flush applies the rules if anything changed. After a failure it backs off
// (up to a minute) instead of retrying every call.
func (e *Engine) Flush() error {
	if !e.Active() || !e.dirty {
		return nil
	}
	now := e.cfg.Now()
	if now.Before(e.failUntil) {
		return nil
	}
	rules := e.Rules()
	var err error
	if len(rules) == 0 {
		if !e.tableEmpty {
			err = e.cfg.Firewall.Remove()
			e.tableEmpty = err == nil
		}
	} else {
		err = e.cfg.Firewall.Apply(Script(rules))
		e.tableEmpty = false
	}
	if err != nil {
		if e.failDelay == 0 {
			e.failDelay = time.Second
		} else if e.failDelay < time.Minute {
			e.failDelay *= 2
		}
		e.failUntil = now.Add(e.failDelay)
		e.fail("%v", err)
		return err
	}
	e.failDelay, e.failUntil = 0, time.Time{}
	e.dirty = false
	return nil
}

// Shutdown removes the rules and groups. A stopped daemon never leaves a
// machine half-enforced with no way to release it; quarantines by id come
// back when it starts again.
func (e *Engine) Shutdown() {
	if !e.Active() {
		return
	}
	_ = e.cfg.Firewall.Remove()
	for _, g := range append(e.groupList(), e.retired...) {
		_ = e.cfg.Cgroups.Freeze(g.name, false)
		_, _ = e.cfg.Cgroups.Remove(g.name)
	}
}

func (e *Engine) groupList() []*group {
	var out []*group
	for _, g := range e.groups {
		out = append(out, g)
	}
	return out
}

func (e *Engine) fail(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if msg != e.LastError {
		e.cfg.Log(events.Record{Type: events.Sensor, Note: "enforcement error: " + msg})
	}
	e.LastError = msg
}

// Status is what `authsec-cli enforce status` shows.
type Status struct {
	Active      bool          `json:"active"`
	Policies    []string      `json:"policies"`
	Enforced    []GroupStatus `json:"enforced"`
	Quarantined []string      `json:"quarantined_agents"`
	LastError   string        `json:"last_error,omitempty"`
}

// GroupStatus is one enforced instance.
type GroupStatus struct {
	Agent       events.Agent `json:"agent"`
	Group       string       `json:"group"`
	Policy      string       `json:"policy"`
	Quarantined bool         `json:"quarantined"`
	Forced      bool         `json:"forced,omitempty"`
	Allowed     int          `json:"allowed_addresses"`
}

// Status reports the enforcement state.
func (e *Engine) Status() Status {
	s := Status{Active: e.Active(), Policies: e.set.SortedIDs(), LastError: e.LastError}
	if s.Policies == nil {
		s.Policies = []string{}
	}
	rules := map[string]NetRules{}
	for _, r := range e.Rules() {
		rules[r.Name] = r
	}
	for top, g := range e.groups {
		if !g.active {
			continue
		}
		_, forced := e.forced[top]
		r := rules[g.name]
		s.Enforced = append(s.Enforced, GroupStatus{Agent: g.agent, Group: g.name, Policy: e.policyID(top),
			Quarantined: g.quarantined, Forced: forced, Allowed: len(r.Allow)})
	}
	sort.Slice(s.Enforced, func(i, j int) bool { return s.Enforced[i].Group < s.Enforced[j].Group })
	for id := range e.qAgents {
		s.Quarantined = append(s.Quarantined, id)
	}
	sort.Strings(s.Quarantined)
	return s
}

type state struct {
	QuarantinedAgents []string `json:"quarantined_agents"`
}

func (e *Engine) loadState() {
	if e.cfg.StatePath == "" {
		return
	}
	b, err := os.ReadFile(e.cfg.StatePath)
	if err != nil {
		return
	}
	var s state
	if json.Unmarshal(b, &s) == nil {
		for _, id := range s.QuarantinedAgents {
			e.qAgents[id] = true
		}
	}
}

func (e *Engine) saveState() {
	if e.cfg.StatePath == "" {
		return
	}
	var s state
	for id := range e.qAgents {
		s.QuarantinedAgents = append(s.QuarantinedAgents, id)
	}
	sort.Strings(s.QuarantinedAgents)
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.MkdirAll(filepath.Dir(e.cfg.StatePath), 0o700)
	tmp := e.cfg.StatePath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, e.cfg.StatePath)
	}
}
