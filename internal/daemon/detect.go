package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/detect"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
)

const detectionWindow = time.Hour

// detection writes a detection record (once per rule and process per hour)
// and tells the daemon, which may quarantine the agent.
func (m *Monitor) detection(d *detect.Detection, a *events.Agent) {
	if d == nil {
		return
	}
	if !m.once("x|"+d.Rule+"|"+strconv.Itoa(d.PID), detectionWindow) {
		return
	}
	r := events.Record{Time: m.deps.Now(), Type: events.Detection, Rule: d.Rule, Severity: d.Severity, Agent: a,
		PID: d.PID, Evidence: d.Evidence, Note: d.Title, Threat: true}
	m.out(r)
	if m.deps.OnThreat != nil {
		m.deps.OnThreat(r)
	}
}

// detectProcess checks a program an agent started (an offensive tool).
// It is attributed to the agent only for a process of the agent's user: a
// reused pid or another user's process must never quarantine the agent.
func (m *Monitor) detectProcess(a *events.Agent, p *proc.Process) {
	if a.User != "" && p.User != "" && a.User != p.User {
		return
	}
	tool, ok := detect.OffensiveTool(p.Args)
	if !ok && p.Comm != "" && len(p.Args) > 0 {
		// A wrapper script or a link: the kernel's process name is the tool's.
		tool, ok = detect.OffensiveTool(append([]string{p.Comm}, p.Args[1:]...))
	}
	if ok {
		m.detection(&detect.Detection{Rule: detect.RuleOffensiveTool, Severity: detect.High, PID: p.PID, AgentID: a.ID,
			Title:    a.Name + " ran the offensive security tool " + tool,
			Evidence: []string{"program " + tool, "started by agent " + a.Name + " (pid " + strconv.Itoa(a.PID) + ")"}}, a)
	}
}

// detectConnection feeds the fan-out rule (scanning many destinations).
func (m *Monitor) detectConnection(a *events.Agent, ip string, port int) {
	if m.fanout == nil {
		return
	}
	if d := m.fanout.Observe(a.PID, ip, port, m.deps.Now()); d != nil {
		d.AgentID = a.ID
		m.detection(d, a)
	}
}

// sweepARTEX looks for ARTEX among all processes (a renamed binary is still
// found by its ARTEX_* variables, ports and files) and follows each top-most
// ARTEX process as an agent.
func (m *Monitor) sweepARTEX(snap *proc.Snapshot) {
	listen := map[int][]int{}
	for _, c := range snap.Conns {
		if c.Listen {
			listen[c.PID] = append(listen[c.PID], c.LocalPort)
		}
	}
	found := map[int]*detect.Detection{}
	for pid, p := range snap.Procs {
		dp := detect.Process{PID: pid, PPID: p.PPID, Comm: p.Comm, Exe: p.Exe, Args: p.Args, EnvNames: p.EnvNames, Listen: listen[pid]}
		// First without touching the filesystem: only a process that
		// already looks like ARTEX (name, variables, ports, flags) gets its
		// files checked. Ordinary processes are never stat'ed, and files
		// planted next to someone else's binary cannot make it "ARTEX".
		if detect.ARTEXProcess(dp, nil) == nil {
			continue
		}
		if d := detect.ARTEXProcess(dp, ownedFile(p.UID)); d != nil {
			found[pid] = d
		}
	}
	for pid, d := range found {
		// ARTEX's own children inherit its variables: report the top one.
		if _, parentToo := found[snap.Procs[pid].PPID]; parentToo {
			continue
		}
		root, followed := m.member[pid]
		if followed && m.agents[root] != nil && m.agents[root].User != "" && snap.Procs[pid].User != "" && m.agents[root].User != snap.Procs[pid].User {
			followed = false // a reused pid of another user: not the agent's process
			delete(m.member, pid)
		}
		if !followed && d.Severity == detect.High {
			p := snap.Procs[pid]
			m.start(recognise.Agent{ID: "artex", Name: "ARTEX (AI pentest agent)", Role: recognise.RoleAgent,
				Confidence: recognise.Known, Threat: true, PID: pid, User: p.User, Exe: p.Exe, Args: recognise.ScrubArgs(p.Args),
				Started: p.Started, Evidence: d.Evidence}, "found by the ARTEX detection")
			root = pid
		}
		m.detection(d, m.agents[root])
	}
}

// containerDetections reports ARTEX containers (the daemon lists them in
// the background).
func (m *Monitor) containerDetections(names []string) {
	if d := detect.ARTEXContainers(names); d != nil {
		m.detection(d, nil)
	}
}

// ownedFile checks a file next to a process's binary: it counts only when
// it and its directory belong to the process's user (or root) and the
// directory is not writable by others.
func ownedFile(uid int) func(string) bool {
	return func(path string) bool {
		if !strings.HasPrefix(path, "/") && !strings.Contains(path, `:\`) {
			return false
		}
		st, err := os.Lstat(path)
		if err != nil || !ownedBy(st, uid) {
			return false
		}
		dir, err := os.Lstat(filepath.Dir(path))
		if err != nil || !ownedBy(dir, uid) || dir.Mode().Perm()&0o022 != 0 || dir.Mode()&os.ModeSticky != 0 {
			return false
		}
		return true
	}
}
