package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/control"
	"github.com/authsec-ai/authsec-cli/internal/detect"
	"github.com/authsec-ai/authsec-cli/internal/enforce"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/link"
	"github.com/authsec-ai/authsec-cli/internal/policy"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
	"github.com/authsec-ai/authsec-cli/internal/sensor"
)

// Options configures the daemon.
type Options struct {
	LogPath     string
	PolicyDir   string        // agent policies; "" disables decisions and enforcement
	NoEBPF      bool          // poll the process table even where eBPF works
	NoEnforce   bool          // decide and log, never block (even for mode: enforce)
	Rescan      time.Duration // process table check with eBPF (default 60s)
	Poll        time.Duration // process table poll without eBPF (default 5s)
	Status      io.Writer     // human-readable progress
	SocketPath  string        // control socket (default control.SocketPath())
	StatePath   string        // persisted quarantine list
	CgroupRoot  string        // default /sys/fs/cgroup
	ResolvConf  string        // default /etc/resolv.conf
	EnforceHook func(*enforce.Engine)
	// Detect turns on threat detections; QuarantineThreats quarantines an
	// agent on a high-severity detection (needs enforcement).
	Detect            bool
	QuarantineThreats bool
	// SIEM receives every record of the types it forwards (siem.Open).
	SIEM []Sink
	// Tee receives every record (SIEM forwarding, control plane).
	Tee func(events.Record)
	// Link connects the machine to the AuthSec console (nil: not connected):
	// the console link (internal/link) or the v2 collector
	// (internal/collector). Its policies are written to ConsolePolicyDir and
	// win over a local policy for the same agent.
	Link             Uplink
	ConsolePolicyDir string
}

// Uplink is a connection to a control plane. It receives every record and
// the running agents, and hands the loop work that touches the engine.
type Uplink interface {
	Tee(events.Record)
	SetAgents(agents []events.Agent, runtime map[string]any)
	Commands() <-chan link.Command
	Run(ctx context.Context, log func(events.Record))
}

// Sink forwards records (internal/siem).
type Sink interface{ Send(events.Record) }

type ctlCall struct {
	req   control.Request
	peer  control.Peer
	reply chan control.Response
}

type resolved struct {
	host string
	ips  []net.IP
}

// Run follows agents until ctx is done.
func Run(ctx context.Context, opt Options) error {
	if opt.Rescan == 0 {
		opt.Rescan = time.Minute
	}
	if opt.Poll == 0 {
		opt.Poll = 5 * time.Second
	}
	if opt.Status == nil {
		opt.Status = io.Discard
	}
	if opt.SocketPath == "" {
		opt.SocketPath = control.SocketPath()
	}
	if opt.StatePath == "" {
		opt.StatePath = filepath.Join(filepath.Dir(opt.LogPath), "state.json")
	}
	if opt.CgroupRoot == "" {
		opt.CgroupRoot = "/sys/fs/cgroup"
	}
	if opt.ResolvConf == "" {
		opt.ResolvConf = "/etc/resolv.conf"
	}
	debug.SetMemoryLimit(64 << 20) // footprint: GC harder before growing past 64 MiB

	unlock, err := lockInstance(filepath.Dir(opt.SocketPath))
	if err != nil {
		return err
	}
	defer unlock()
	w, err := events.Open(opt.LogPath)
	if err != nil {
		return fmt.Errorf("event log: %w", err)
	}
	defer w.Close()
	w.Tee = func(r events.Record) {
		for _, s := range opt.SIEM {
			s.Send(r)
		}
		if opt.Tee != nil {
			opt.Tee(r)
		}
		if opt.Link != nil {
			opt.Link.Tee(r)
		}
	}
	write := func(r events.Record) {
		if err := w.Write(r); err != nil {
			fmt.Fprintln(opt.Status, "event log:", err)
		}
	}

	llm := recognise.ResolveLLMHosts(ctx, nil)
	var s sensor.Sensor
	mode := "polling"
	if !opt.NoEBPF {
		s, err = sensor.Start()
		if err != nil {
			if !errors.Is(err, sensor.ErrUnsupported) {
				return err
			}
			fmt.Fprintf(opt.Status, "%v; falling back to polling every %s\n", err, opt.Poll)
		} else {
			mode = "ebpf"
			defer s.Close()
		}
	}

	// Enforcement: root, Linux, cgroup v2 and nft. Otherwise decisions are
	// still logged.
	var m *Monitor // set below; the engine asks it for an instance's processes
	engCfg := enforce.EngineConfig{Resolvers: enforce.Resolvers(opt.ResolvConf), StatePath: opt.StatePath, Log: write,
		Alive: proc.StartTime, DestroySockets: enforce.DestroySockets,
		Members: func(top int) []int {
			if m == nil {
				return nil
			}
			return m.Members(top)
		}}
	havePolicies := opt.PolicyDir != "" || opt.ConsolePolicyDir != ""
	enforcing := "off (no policy folder)"
	if havePolicies {
		enforcing = "decisions logged, nothing blocked"
		switch {
		case opt.NoEnforce:
			enforcing += " (--no-enforce)"
		case runtime.GOOS != "linux":
			enforcing += " (blocking is Linux only)"
		case os.Geteuid() != 0:
			enforcing += " (blocking needs root)"
		default:
			cg := enforce.Cgroups{Root: opt.CgroupRoot}
			if ns := foreignNamespaces(); ns != "" {
				enforcing += " (" + ns + ")"
			} else if err := cg.Available(); err != nil {
				enforcing += " (" + err.Error() + ")"
			} else if err := (enforce.NFT{}).Remove(); err != nil {
				enforcing += " (nftables: " + err.Error() + ")"
			} else {
				engCfg.Cgroups, engCfg.Firewall = cg, enforce.NFT{}
				enforcing = "on (policies in mode: enforce are blocked)"
			}
		}
	}
	eng := enforce.NewEngine(engCfg)
	defer eng.Shutdown()
	var policyStamp string
	stamp := func() string { return dirStamp(opt.PolicyDir) + "|" + dirStamp(opt.ConsolePolicyDir) }
	loadPolicies := func(reason string) {
		if !havePolicies {
			return
		}
		// Console policies first: the first good policy of an agent wins.
		var files []*policy.File
		for _, dir := range []string{opt.ConsolePolicyDir, opt.PolicyDir} {
			if dir == "" {
				continue
			}
			fs, err := policy.LoadDir(dir)
			if err != nil {
				if dir == opt.ConsolePolicyDir && errors.Is(err, os.ErrNotExist) {
					continue
				}
				write(events.Record{Type: events.Sensor, Note: "policies: " + err.Error()})
				if dir == opt.PolicyDir {
					return
				}
				continue
			}
			files = append(files, fs...)
		}
		bad := 0
		for _, f := range files {
			if !f.OK() {
				bad++
				write(events.Record{Type: events.Sensor, Note: fmt.Sprintf("policy %s has errors and is not applied (the last good one is kept): %v", f.Path, f.Issues)})
			}
		}
		eng.SetPolicies(policy.NewSet(files))
		if err := eng.Flush(); err != nil {
			fmt.Fprintln(opt.Status, "enforcement:", err)
		}
		write(events.Record{Type: events.Sensor, Note: fmt.Sprintf("policies loaded (%s): %d files, %d with errors", reason, len(files), bad)})
	}
	if havePolicies {
		policyStamp = stamp()
		loadPolicies("start")
	}
	if opt.EnforceHook != nil {
		opt.EnforceHook(eng)
	}

	threats := make(chan events.Record, 16)
	released := map[int]uint64{} // instances an admin released: pid -> start time
	deps := Deps{Get: proc.Get, Snapshot: proc.Take, HomeOf: homeOf, Detect: opt.Detect,
		OnThreat: func(r events.Record) {
			if opt.QuarantineThreats && r.Severity == "high" && r.Agent != nil {
				select {
				case threats <- r:
				default:
				}
			}
		},
		Kill: func(pid int) error {
			pr, err := os.FindProcess(pid)
			if err != nil {
				return err
			}
			return pr.Kill()
		}}
	if havePolicies {
		deps.Enforcer = eng
	}
	if s != nil {
		deps.Track = func(pid int) { _ = s.Track(pid) }
		deps.Untrack = s.Untrack
	}
	m = NewMonitor(deps, write, llm)
	write(events.Record{Type: events.Sensor, Note: "started (" + mode + "); enforcement " + enforcing})
	fmt.Fprintf(opt.Status, "authsec-cli daemon: %s mode, writing %s\nenforcement: %s\n", mode, opt.LogPath, enforcing)

	// Control socket.
	calls := make(chan ctlCall)
	go func() {
		err := control.Serve(ctx, opt.SocketPath, func(req control.Request, peer control.Peer) control.Response {
			c := ctlCall{req: req, peer: peer, reply: make(chan control.Response, 1)}
			select {
			case calls <- c:
			case <-time.After(5 * time.Second):
				return control.Fail("daemon busy")
			}
			select {
			case r := <-c.reply:
				return r
			case <-time.After(8 * time.Second):
				return control.Fail("daemon busy")
			}
		})
		if err != nil {
			fmt.Fprintln(opt.Status, "control socket:", err)
		}
	}()

	// Exact host names of enforced policies are resolved ahead of the agent.
	resolvedCh := make(chan resolved, 64)
	resolveHosts := func() {
		hosts := eng.Hosts()
		go func() {
			for _, h := range hosts {
				rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
				addrs, err := net.DefaultResolver.LookupIPAddr(rctx, h)
				cancel()
				if err != nil {
					continue
				}
				r := resolved{host: h}
				for _, a := range addrs {
					r.ips = append(r.ips, a.IP)
				}
				select {
				case resolvedCh <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	snap, err := proc.Take()
	if err != nil {
		return err
	}
	m.Seed(snap)
	resolveHosts()
	fmt.Fprintf(opt.Status, "following %d agents\n", len(m.Agents()))

	var linkCmds <-chan link.Command
	shareAgents := func() {}
	if opt.Link != nil {
		linkCmds = opt.Link.Commands()
		shareAgents = func() {
			opt.Link.SetAgents(m.Agents(), map[string]any{"sensor": mode, "enforcement": enforcing})
		}
		shareAgents()
		go opt.Link.Run(ctx, write)
	}
	reloadAll := func(reason string) { policyStamp = stamp(); loadPolicies(reason); resolveHosts() }

	every := opt.Rescan
	if s == nil {
		every = opt.Poll
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	flush := time.NewTicker(300 * time.Millisecond)
	defer flush.Stop()
	slow := time.NewTicker(5 * time.Minute)
	defer slow.Stop()
	var evs <-chan sensor.Event
	var dns <-chan sensor.DNSAnswer
	if s != nil {
		evs, dns = s.Events(), s.DNS()
	}
	var dropped uint64
	containers := make(chan []string, 1)
	listContainers := func() {
		if !opt.Detect {
			return
		}
		go func() {
			select {
			case containers <- detect.Containers():
			default:
			}
		}()
	}
	listContainers()
	for {
		select {
		case names := <-containers:
			m.containerDetections(names)
		case r := <-threats:
			if start, ok := released[r.Agent.PID]; ok {
				if now, alive := proc.StartTime(r.Agent.PID); alive && now == start {
					continue // an admin released this instance: no automatic quarantine again
				}
				delete(released, r.Agent.PID)
			}
			if _, err := eng.Quarantine("", r.Agent.PID); err != nil {
				write(events.Record{Type: events.Sensor, Agent: r.Agent, Note: "could not quarantine after detection " + r.Rule + ": " + err.Error()})
			}
		case <-ctx.Done():
			write(events.Record{Type: events.Sensor, Note: "stopped; enforcement lifted"})
			return nil
		case ev, ok := <-evs:
			if !ok {
				return errors.New("sensor stopped")
			}
			m.Handle(ev)
		case a, ok := <-dns:
			// Only answers from the configured resolvers name addresses:
			// anyone can send a packet from port 53.
			if ok && eng.TrustedDNS(a.Src) {
				m.HandleDNS(a)
			}
		case r := <-resolvedCh:
			eng.DNS(r.host, r.ips, 10*time.Minute)
		case c := <-calls:
			resp := handleCall(c, eng, m, write, func() { reloadAll("reload") })
			if c.req.Op == control.OpRelease && resp.OK {
				for _, a := range m.Agents() {
					if a.PID == c.req.PID || (c.req.Agent != "" && a.ID == c.req.Agent) {
						if st, ok := proc.StartTime(a.PID); ok {
							released[a.PID] = st
						}
					}
				}
			}
			c.reply <- resp
		case lc := <-linkCmds:
			lc.Reply <- linkCommand(lc, eng, m, released, reloadAll)
		case <-flush.C:
			if err := eng.Flush(); err != nil {
				fmt.Fprintln(opt.Status, "enforcement:", err)
			}
		case <-tick.C:
			if snap, err := proc.Take(); err == nil {
				m.Reconcile(snap, s == nil)
			}
			eng.Tick()
			shareAgents()
			if havePolicies {
				if st := stamp(); st != policyStamp {
					reloadAll("files changed")
				}
			}
			if s != nil {
				if d := s.Dropped(); d > dropped {
					write(events.Record{Type: events.Sensor, Note: fmt.Sprintf("%d kernel events lost (ring buffer full)", d-dropped)})
					dropped = d
				}
			}
		case <-slow.C:
			listContainers()
			for ip, h := range recognise.ResolveLLMHosts(ctx, nil) {
				m.llm[ip] = h
			}
			resolveHosts()
		}
	}
}

// linkCommand carries out what the console asked for.
func linkCommand(c link.Command, eng *enforce.Engine, m *Monitor, released map[int]uint64, reload func(string)) link.Result {
	switch c.Op {
	case "reload":
		reload("console")
		return link.Result{}
	case "quarantine":
		n, err := eng.Quarantine(c.Agent, 0)
		return link.Result{Instances: n, Err: err}
	case "release":
		n, err := eng.Release(c.Agent, 0)
		if err == nil {
			// No automatic quarantine of these instances again.
			for _, a := range m.Agents() {
				if a.ID == c.Agent {
					if st, ok := proc.StartTime(a.PID); ok {
						released[a.PID] = st
					}
				}
			}
		}
		return link.Result{Instances: n, Err: err}
	}
	return link.Result{Err: fmt.Errorf("unknown command %q", c.Op)}
}

// handleCall runs one control request in the daemon's loop.
func handleCall(c ctlCall, eng *enforce.Engine, m *Monitor, write func(events.Record), reload func()) control.Response {
	req, peer := c.req, c.peer
	switch req.Op {
	case control.OpStatus:
		return control.OK(map[string]any{"enforcement": eng.Status(), "agents": m.Agents()})
	case control.OpReport:
		r := req.Record
		if r == nil || r.Type != events.Decision {
			return control.Fail("report takes one decision record")
		}
		if !reports.allow(peer.UID) {
			return control.Fail("too many reports")
		}
		// Only what a hook decides is kept, clipped; who reported it is
		// added, never taken from the record.
		rec := events.Record{Time: time.Now(), Type: events.Decision, Source: "claude-hook",
			Kind: clean(r.Kind, 20), Action: clean(r.Action, 20), Rule: clean(r.Rule, 200),
			Path: clean(r.Path, 400), Note: clean(r.Note, 400), Enforced: r.Enforced}
		if r.Agent != nil {
			rec.Agent = &events.Agent{ID: clean(r.Agent.ID, 64), Name: clean(r.Agent.Name, 64), PID: r.Agent.PID}
		}
		if peer.Known {
			rec.Note = strings.TrimSpace(rec.Note + fmt.Sprintf(" (reported by uid %d)", peer.UID))
		}
		write(rec)
		return control.OK(nil)
	case control.OpEnforcePID:
		// A process may put itself under enforcement; root may put anyone.
		if !(peer.Privileged() || (peer.Known && peer.PID == req.PID)) {
			return control.Fail("enforce_pid: a process may only enforce itself")
		}
		if err := eng.Force(req.PID, req.Agent); err != nil {
			return control.Fail("%v", err)
		}
		write(events.Record{Type: events.Decision, Kind: "agent", Action: "enforce", PID: req.PID,
			Agent: &events.Agent{ID: req.Agent, Name: req.Agent, PID: req.PID}, Enforced: true, Source: "run"})
		return control.OK(nil)
	case control.OpQuarantine, control.OpRelease, control.OpReload:
		if !peer.Privileged() {
			return control.Fail("%s needs root (sudo)", req.Op)
		}
		switch req.Op {
		case control.OpReload:
			reload()
			return control.OK(eng.Status())
		case control.OpQuarantine:
			n, err := eng.Quarantine(req.Agent, req.PID)
			if err != nil {
				return control.Fail("%v", err)
			}
			return control.OK(map[string]int{"instances": n})
		default:
			n, err := eng.Release(req.Agent, req.PID)
			if err != nil {
				return control.Fail("%v", err)
			}
			return control.OK(map[string]int{"instances": n})
		}
	}
	return control.Fail("unknown op %q", req.Op)
}

// clean clips text and removes control characters.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '\u2028' || r == '\u2029' || r == '\u0085' {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// rateLimiter allows a burst of reports per uid, refilled per second.
type rateLimiter struct {
	tokens map[int]float64
	last   map[int]time.Time
}

var reports = &rateLimiter{tokens: map[int]float64{}, last: map[int]time.Time{}}

func (r *rateLimiter) allow(uid int) bool {
	const rate, burst = 20.0, 100.0
	now := time.Now()
	t, ok := r.tokens[uid]
	if !ok {
		t = burst
	} else {
		t += now.Sub(r.last[uid]).Seconds() * rate
		if t > burst {
			t = burst
		}
	}
	r.last[uid] = now
	if t < 1 {
		r.tokens[uid] = t
		return false
	}
	r.tokens[uid] = t - 1
	return true
}

// dirStamp changes when a file in dir is added, removed or modified.
func dirStamp(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "missing"
	}
	var b []byte
	for _, e := range ents {
		if info, err := e.Info(); err == nil {
			b = append(b, fmt.Sprintf("%s|%d|%d;", e.Name(), info.Size(), info.ModTime().UnixNano())...)
		}
	}
	return string(b)
}

func homeOf(name string) string {
	if name != "" {
		if u, err := user.Lookup(name); err == nil {
			return u.HomeDir
		}
	}
	h, _ := os.UserHomeDir()
	return h
}

// foreignNamespaces says why rules made here would not reach the machine's
// agents: a container that sees the host's processes (--pid host) but has
// its own network or cgroup namespace. "" when they would.
func foreignNamespaces() string {
	var differ []string
	for _, ns := range []string{"net", "cgroup"} {
		host, err1 := os.Readlink("/proc/1/ns/" + ns)
		self, err2 := os.Readlink("/proc/self/ns/" + ns)
		if err1 == nil && err2 == nil && host != self {
			differ = append(differ, ns)
		}
	}
	if len(differ) == 0 {
		return ""
	}
	return "this process has its own " + strings.Join(differ, " and ") +
		" namespace, so it cannot block the machine's agents: run the container with --network host --cgroupns host"
}
