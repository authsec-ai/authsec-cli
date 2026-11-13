// Package daemon is the background sensor: it keeps the set of running agents
// and their processes, and turns kernel events (or, without eBPF, process
// table polls) into agent records in the event log.
package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/policy"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
	"github.com/authsec-ai/authsec-cli/internal/sensor"
)

// Deps are the monitor's view of the machine, injected for tests.
type Deps struct {
	Get      func(pid int) (*proc.Process, bool)
	Snapshot func() (*proc.Snapshot, error)
	Track    func(pid int) // nil when polling
	Untrack  func(pid int)
	Cwd      func(pid int) string
	Now      func() time.Time
	// Enforcer applies policies (nil: activity is logged, nothing decided).
	Enforcer Enforcer
	// Kill stops a process that ran a denied command in an enforced agent.
	Kill func(pid int) error
	// HomeOf is a user's home directory, for {home} in policies.
	HomeOf func(user string) string
}

// Enforcer is what the monitor needs from the enforcement engine
// (*enforce.Engine).
type Enforcer interface {
	AgentStarted(a events.Agent, pids []int)
	AgentStopped(pid int)
	DNS(name string, ips []net.IP, ttl time.Duration)
	Enforcing(top int, agentID string) (bool, *policy.Policy)
	HostOf(ip string) string
}

const decisionWindow = 10 * time.Minute

// Dedupe windows: the same file or destination of the same agent is logged
// at most once per window.
const (
	fileWindow = time.Hour
	netWindow  = 10 * time.Minute
	recheck    = 10 * time.Minute // an untracked process with LLM traffic is re-examined after this
)

type dnsEntry struct {
	name    string
	expires time.Time
}

// Monitor holds the state of the running agents. It is not safe for
// concurrent use: the daemon drives it from one goroutine.
type Monitor struct {
	deps    Deps
	out     func(events.Record)
	llm     map[string]string // ip -> LLM host
	dns     map[string]dnsEntry
	agents  map[int]*events.Agent // agent top pid -> agent
	kernel  map[int]bool          // agent top pids tracked in the kernel
	member  map[int]int           // pid -> agent top pid
	checked map[int]time.Time
	seen    map[string]time.Time
}

// NewMonitor returns a monitor writing records to out. llm maps LLM API
// addresses to their host names.
func NewMonitor(deps Deps, out func(events.Record), llm map[string]string) *Monitor {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Cwd == nil {
		deps.Cwd = func(pid int) string {
			d, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "cwd"))
			return d
		}
	}
	if llm == nil {
		llm = map[string]string{}
	}
	return &Monitor{deps: deps, out: out, llm: llm, dns: map[string]dnsEntry{},
		agents: map[int]*events.Agent{}, kernel: map[int]bool{}, member: map[int]int{},
		checked: map[int]time.Time{}, seen: map[string]time.Time{}}
}

// Agents returns the agents being followed.
func (m *Monitor) Agents() []events.Agent {
	out := make([]events.Agent, 0, len(m.agents))
	for _, a := range m.agents {
		out = append(out, *a)
	}
	return out
}

// Members are the processes of an agent instance the monitor follows: its
// top process first, then the processes it started.
func (m *Monitor) Members(top int) []int {
	out := []int{top}
	for pid, root := range m.member {
		if root == top && pid != top {
			out = append(out, pid)
		}
	}
	return out
}

// Seed records the agents running now.
func (m *Monitor) Seed(snap *proc.Snapshot) {
	for _, a := range recognise.Recognise(snap, recognise.Options{LLMAddrs: m.llm}) {
		m.start(a, "running when the sensor started")
	}
}

// Reconcile compares the followed agents with a fresh process table: agents
// whose exit was missed are stopped, agents not seen yet are started. When
// polling (no eBPF) it also logs the connections of agent processes and the
// programs they started.
func (m *Monitor) Reconcile(snap *proc.Snapshot, polling bool) {
	for pid, a := range m.agents {
		if _, ok := snap.Procs[pid]; !ok {
			m.stop(pid, a)
		}
	}
	for _, a := range recognise.Recognise(snap, recognise.Options{LLMAddrs: m.llm}) {
		if _, ok := m.agents[a.PID]; !ok {
			m.start(a, "found by process scan")
			continue
		}
		if polling {
			for _, c := range a.Children {
				if _, ok := m.member[c.PID]; !ok {
					m.member[c.PID] = a.PID
					if p := snap.Procs[c.PID]; p != nil {
						m.process(a.PID, p)
					}
				}
			}
		}
	}
	if polling {
		for _, c := range snap.Conns {
			if root, ok := m.member[c.PID]; ok && !c.Listen && c.RemoteIP != nil {
				m.network(root, c.PID, c.RemoteIP, c.RemotePort)
			}
		}
	}
	// Forget dedupe keys and checks that have expired.
	now := m.deps.Now()
	for k, t := range m.seen {
		if now.Sub(t) > fileWindow {
			delete(m.seen, k)
		}
	}
	for pid, t := range m.checked {
		if now.Sub(t) > recheck {
			delete(m.checked, pid)
		}
	}
	for pid := range m.member {
		if _, ok := snap.Procs[pid]; !ok {
			delete(m.member, pid)
		}
	}
}

// Handle processes one kernel event.
func (m *Monitor) Handle(ev sensor.Event) {
	switch ev.Type {
	case sensor.Exec:
		m.exec(ev)
	case sensor.Fork:
		if root, ok := m.member[ev.PPID]; ok {
			m.member[ev.PID] = root
		}
	case sensor.Exit:
		root, ok := m.member[ev.PID]
		delete(m.member, ev.PID)
		if ok && root == ev.PID {
			if a := m.agents[root]; a != nil {
				m.stop(root, a)
			}
		}
	case sensor.Connect:
		if ev.DstIP == nil {
			return
		}
		if root, ok := m.member[ev.PID]; ok {
			m.network(root, ev.PID, ev.DstIP, ev.DstPort)
			return
		}
		if d := m.dst(ev.DstIP, ev.DstPort); d.LLM {
			m.unknown(ev.PID, ev.DstIP, ev.DstPort, d.Host)
		}
	case sensor.Open:
		if root, ok := m.member[ev.PID]; ok {
			m.file(root, ev)
		}
	}
}

// HandleDNS remembers which name an address was looked up as.
func (m *Monitor) HandleDNS(a sensor.DNSAnswer) {
	ttl := a.TTL
	if ttl < time.Minute {
		ttl = time.Minute
	}
	llm := recognise.IsLLMHostName(a.Name)
	for _, ip := range a.IPs {
		m.dns[ip.String()] = dnsEntry{name: a.Name, expires: m.deps.Now().Add(ttl + time.Hour)}
		if llm {
			m.llm[ip.String()] = a.Name
		}
	}
	if m.deps.Enforcer != nil {
		m.deps.Enforcer.DNS(a.Name, a.IPs, a.TTL)
	}
}

func (m *Monitor) exec(ev sensor.Event) {
	root, isMember := m.member[ev.PID]
	if !isMember {
		if r, ok := m.member[ev.PPID]; ok {
			root, isMember = r, true
			m.member[ev.PID] = r
		}
	}
	p, ok := m.deps.Get(ev.PID)
	if !ok {
		p = &proc.Process{PID: ev.PID, PPID: ev.PPID, UID: ev.UID, Comm: ev.Comm, Exe: ev.Path}
	}
	if p.Exe == "" {
		p.Exe = ev.Path
	}
	sig, why := recognise.Match(p.Exe, p.Comm, p.Args)
	if isMember {
		parent := m.agents[root]
		if sig != nil && parent != nil && sig.ID != parent.ID {
			// An agent started another agent: the new one is followed on
			// its own, with its processes.
			delete(m.member, ev.PID)
			m.startProcess(p, sig, why+fmt.Sprintf("; started by agent %s (pid %d)", parent.Name, root))
			return
		}
		if ev.PID != root {
			m.process(root, p)
		}
		return
	}
	if sig != nil {
		m.startProcess(p, sig, why)
	}
}

// startProcess starts following a process that matched a signature at exec.
func (m *Monitor) startProcess(p *proc.Process, sig *recognise.Signature, why string) {
	a := recognise.Agent{ID: sig.ID, Name: sig.Name, Role: sig.Role, Confidence: recognise.Known, Threat: sig.Threat,
		PID: p.PID, User: p.User, Exe: p.Exe, Args: recognise.ScrubArgs(p.Args), Started: p.Started,
		Evidence: []string{why}}
	if parent, ok := m.deps.Get(p.PPID); ok {
		a.Via = parent.Comm
	}
	m.start(a, "started")
}

func (m *Monitor) start(a recognise.Agent, note string) {
	if _, ok := m.agents[a.PID]; ok {
		return
	}
	ref := &events.Agent{ID: a.ID, Name: a.Name, PID: a.PID, User: a.User, Confidence: a.Confidence}
	m.agents[a.PID] = ref
	m.member[a.PID] = a.PID
	// Editors are followed for their network only: tracking every editor
	// process's file opens would log all editing.
	editor := strings.HasSuffix(a.Name, "(AI features)")
	if m.deps.Track != nil && !editor {
		m.deps.Track(a.PID)
		m.kernel[a.PID] = true
	}
	for _, c := range a.Children {
		m.member[c.PID] = a.PID
		if m.deps.Track != nil && !editor {
			m.deps.Track(c.PID)
		}
	}
	m.out(events.Record{Time: m.deps.Now(), Type: events.AgentStarted, Agent: ref, PID: a.PID, Exe: a.Exe, Args: a.Args,
		Via: a.Via, Version: a.Version, Evidence: a.Evidence, Threat: a.Threat, Note: note})
	if m.deps.Enforcer != nil {
		pids := []int{a.PID}
		for _, c := range a.Children {
			pids = append(pids, c.PID)
		}
		m.deps.Enforcer.AgentStarted(*ref, pids)
	}
}

func (m *Monitor) stop(pid int, a *events.Agent) {
	delete(m.agents, pid)
	delete(m.member, pid)
	if m.kernel[pid] && m.deps.Untrack != nil {
		m.deps.Untrack(pid)
	}
	delete(m.kernel, pid)
	m.out(events.Record{Time: m.deps.Now(), Type: events.AgentStopped, Agent: a, PID: pid})
	if m.deps.Enforcer != nil {
		m.deps.Enforcer.AgentStopped(pid)
	}
}

func (m *Monitor) process(root int, p *proc.Process) {
	a := m.agents[root]
	if a == nil {
		return
	}
	args := recognise.ScrubArgs(p.Args)
	m.out(events.Record{Time: m.deps.Now(), Type: events.Process, Agent: a, PID: p.PID, Comm: p.Comm,
		Exe: p.Exe, Args: args})
	if m.deps.Enforcer == nil || len(p.Args) == 0 {
		return
	}
	enforced, pol := m.deps.Enforcer.Enforcing(root, a.ID)
	if pol == nil {
		return
	}
	d := pol.DecideArgv(p.Args)
	if p.Exe != "" && d.Action != policy.Deny {
		// A renamed copy or link of a denied program: decide on the real
		// binary's name too.
		if alt := pol.DecideArgv(append([]string{filepath.Base(p.Exe)}, p.Args[1:]...)); alt.Action == policy.Deny || (alt.Action == policy.Ask && d.Action == policy.Allow) {
			d = alt
		}
	}
	if d.Action == policy.Allow {
		return
	}
	r := events.Record{Time: m.deps.Now(), Type: events.Decision, Kind: "command", Action: d.Action, Rule: d.Rule,
		Agent: a, PID: p.PID, Comm: p.Comm, Args: args, Source: "daemon"}
	switch {
	case d.Action == policy.Deny && enforced && m.deps.Kill != nil:
		if err := m.deps.Kill(p.PID); err == nil {
			r.Enforced, r.Note = true, "process killed"
		} else {
			r.Note = "could not stop the process: " + err.Error()
		}
	case d.Action == policy.Ask:
		r.Note = "needs approval: only an agent hook can ask a person; logged"
	}
	if r.Enforced || m.once("d|c|"+strconv.Itoa(root)+"|"+strings.Join(args, " "), decisionWindow) {
		m.out(r)
	}
}

// decideNetwork logs a destination the agent's policy does not allow.
// Blocking is done by nftables for enforced agents; this records it.
func (m *Monitor) decideNetwork(root, pid int, d events.Dst) {
	a := m.agents[root]
	if a == nil || m.deps.Enforcer == nil {
		return
	}
	enforced, pol := m.deps.Enforcer.Enforcing(root, a.ID)
	if pol == nil {
		return
	}
	dec := pol.DecideNetwork(d.Host, net.ParseIP(d.IP), d.Port)
	if dec.Action == policy.Allow {
		return
	}
	if !m.once(fmt.Sprintf("d|n|%d|%s|%d", root, d.IP, d.Port), decisionWindow) {
		return
	}
	dst := d
	m.out(events.Record{Time: m.deps.Now(), Type: events.Decision, Kind: "network", Action: dec.Action, Rule: dec.Rule,
		Agent: a, PID: pid, Dst: &dst, Enforced: enforced, Source: "daemon"})
}

// decideFile logs a file access the agent's policy does not allow. A
// running agent cannot be confined after it started; `authsec-cli run
// --enforce` confines files.
func (m *Monitor) decideFile(root, pid int, path, access string) {
	a := m.agents[root]
	if a == nil || m.deps.Enforcer == nil {
		return
	}
	_, pol := m.deps.Enforcer.Enforcing(root, a.ID)
	if pol == nil {
		return
	}
	home := ""
	if m.deps.HomeOf != nil {
		home = m.deps.HomeOf(a.User)
	}
	dec := pol.Expand(home, policy.GitRoot(path)).DecideFile(path, access == "write")
	if dec.Action == policy.Allow {
		return
	}
	if !m.once("d|f|"+strconv.Itoa(root)+"|"+access+"|"+path, decisionWindow) {
		return
	}
	m.out(events.Record{Time: m.deps.Now(), Type: events.Decision, Kind: "file", Action: dec.Action, Rule: dec.Rule,
		Agent: a, PID: pid, Path: path, Access: access, Source: "daemon",
		Note: "logged: a running agent's files are confined only by 'authsec-cli run --enforce'"})
}

func (m *Monitor) network(root, pid int, ip net.IP, port int) {
	a := m.agents[root]
	if a == nil {
		return
	}
	d := m.dst(ip, port)
	m.decideNetwork(root, pid, d)
	key := fmt.Sprintf("n|%d|%s|%d", root, d.IP, d.Port)
	if !m.once(key, netWindow) {
		return
	}
	m.out(events.Record{Time: m.deps.Now(), Type: events.Network, Agent: a, PID: pid, Dst: &d})
}

func (m *Monitor) file(root int, ev sensor.Event) {
	a := m.agents[root]
	if a == nil || ev.Path == "" || sensor.OpensDirectory(ev.Flags) {
		return
	}
	path := ev.Path
	if !filepath.IsAbs(path) {
		cwd := m.deps.Cwd(ev.PID)
		if cwd == "" {
			return
		}
		path = filepath.Join(cwd, path)
	}
	path = filepath.Clean(path)
	if Noise(path) {
		return
	}
	access := "read"
	if sensor.Writes(ev.Flags) {
		access = "write"
	}
	m.decideFile(root, ev.PID, path, access)
	if !m.once("f|"+strconv.Itoa(root)+"|"+access+"|"+path, fileWindow) {
		return
	}
	m.out(events.Record{Time: m.deps.Now(), Type: events.File, Agent: a, PID: ev.PID, Comm: ev.Comm,
		Path: path, Access: access, Sensitive: Sensitive(path)})
}

// unknown examines a process that is not followed but talks to an LLM API.
func (m *Monitor) unknown(pid int, ip net.IP, port int, host string) {
	if _, ok := m.checked[pid]; ok {
		return
	}
	m.checked[pid] = m.deps.Now()
	snap, err := m.deps.Snapshot()
	if err != nil {
		return
	}
	// The connection may still be opening, so it is added by hand.
	snap.Conns = append(snap.Conns, proc.Conn{PID: pid, LocalIP: net.IPv4zero, RemoteIP: ip, RemotePort: port})
	llm := make(map[string]string, len(m.llm)+1)
	for k, v := range m.llm {
		llm[k] = v
	}
	llm[ip.String()] = host
	for _, a := range recognise.Recognise(snap, recognise.Options{LLMAddrs: llm}) {
		if _, ok := m.agents[a.PID]; ok {
			continue
		}
		if a.PID == pid || isAncestor(snap, a.PID, pid) {
			m.start(a, "talks to an LLM API")
			if root, ok := m.member[pid]; ok {
				m.network(root, pid, ip, port)
			} else {
				m.member[pid] = a.PID
				m.network(a.PID, pid, ip, port)
			}
			return
		}
	}
}

// dst names a destination from DNS answers and the LLM host table.
func (m *Monitor) dst(ip net.IP, port int) events.Dst {
	d := events.Dst{IP: ip.String(), Port: port, Service: recognise.Services[port]}
	if e, ok := m.dns[d.IP]; ok && m.deps.Now().Before(e.expires) {
		d.Host = e.name
	}
	if h, ok := m.llm[d.IP]; ok {
		d.LLM = true
		if d.Host == "" {
			d.Host = h
		}
	} else if d.Host != "" && recognise.IsLLMHostName(d.Host) {
		d.LLM = true
	}
	if ip.IsLoopback() && port == 11434 {
		d.LLM, d.Host = true, "ollama (local)"
	}
	if d.Host == "" && m.deps.Enforcer != nil {
		d.Host = m.deps.Enforcer.HostOf(d.IP)
	}
	return d
}

func (m *Monitor) once(key string, window time.Duration) bool {
	now := m.deps.Now()
	if t, ok := m.seen[key]; ok && now.Sub(t) < window {
		return false
	}
	m.seen[key] = now
	return true
}

func isAncestor(s *proc.Snapshot, anc, pid int) bool {
	for _, p := range s.Ancestors(pid) {
		if p.PID == anc {
			return true
		}
	}
	return false
}

var (
	noisePrefixes = []string{"/proc/", "/sys/", "/dev/", "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/snap/", "/run/", "/etc/ld.so", "/etc/localtime", "/etc/nsswitch.conf", "/etc/resolv.conf", "/etc/hosts", "/etc/ssl/", "/etc/ca-certificates"}
	noiseParts    = []string{"/node_modules/", "/.git/objects/", "/__pycache__/", "/site-packages/", "/.cache/"}
	sensitiveRE   = regexp.MustCompile(`(?i)(/\.ssh/|/\.aws/|/\.kube/|/\.azure/|/\.config/gcloud/|/\.docker/config\.json$|/\.netrc$|/\.git-credentials$|/\.npmrc$|/\.pypirc$|(^|/)\.env(\.[^/]*)?$|/etc/shadow$|/etc/sudoers|\.pem$|\.p12$|\.pfx$|\.key$|/id_(rsa|ecdsa|ed25519)|/\.gnupg/|/\.password-store/|/\.vault-token$|/\.terraform\.d/credentials|/\.config/gh/hosts\.yml$|/\.claude/\.credentials\.json$|/\.codex/auth\.json$)`)
)

// Noise reports whether a file open is runtime plumbing (libraries, /proc,
// caches) rather than an access worth reviewing.
func Noise(path string) bool {
	for _, p := range noisePrefixes {
		if strings.HasPrefix(path, p) || path == strings.TrimSuffix(p, "/") {
			return true
		}
	}
	for _, p := range noiseParts {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

// Sensitive reports whether a path holds credentials or keys.
func Sensitive(path string) bool { return sensitiveRE.MatchString(path) }
