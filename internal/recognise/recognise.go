// Package recognise finds the AI agents among running processes.
//
// A process is an agent when it matches a known signature (binary, install
// path, npm package), when it is an editor whose processes talk to an LLM
// API, or when it talks to an LLM API itself ("likely"). Holding an LLM key
// variable alone makes an interpreter a "possible" agent. The processes an
// agent starts (MCP servers, tools) belong to it.
package recognise

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/parse"
	"github.com/authsec-ai/authsec-cli/internal/proc"
)

// Confidence levels.
const (
	Known    = "known"    // matched a signature or a known editor
	Likely   = "likely"   // talks to an LLM API
	Possible = "possible" // an interpreter holding an LLM key variable
)

// Agent is one running agent and the processes it started.
type Agent struct {
	ID          string     `json:"id"` // signature id, editor id, or "unknown"
	Name        string     `json:"name"`
	Role        Role       `json:"role"`
	Confidence  string     `json:"confidence"`
	Threat      bool       `json:"threat,omitempty"`
	PID         int        `json:"pid"`
	User        string     `json:"user,omitempty"`
	Exe         string     `json:"exe,omitempty"`
	Args        []string   `json:"args,omitempty"` // scrubbed
	Started     time.Time  `json:"started,omitempty"`
	Version     string     `json:"version,omitempty"`
	Via         string     `json:"via,omitempty"` // what started it: an editor extension, a terminal, a service
	ParentAgent int        `json:"parent_agent_pid,omitempty"`
	Evidence    []string   `json:"evidence"`
	LLMKeyNames []string   `json:"llm_key_names,omitempty"`
	Children    []Child    `json:"children,omitempty"`
	Endpoints   []Endpoint `json:"endpoints,omitempty"`
	Listening   []int      `json:"listening,omitempty"`
}

// Child is a process an agent started.
type Child struct {
	PID  int      `json:"pid"`
	Role string   `json:"role"` // mcp_server | process
	Name string   `json:"name"`
	Args []string `json:"args,omitempty"` // scrubbed
}

// Endpoint is a remote address an agent's processes are connected to.
type Endpoint struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Host    string `json:"host,omitempty"`
	Service string `json:"service,omitempty"`
	LLM     bool   `json:"llm,omitempty"`
}

// Options tunes recognition.
type Options struct {
	// LLMAddrs maps an IP to the LLM host it belongs to (ResolveLLMHosts).
	LLMAddrs map[string]string
	// Possible includes "possible" agents (key variable only).
	Possible bool
}

// Recognise returns the agents in a snapshot, known first.
func Recognise(s *proc.Snapshot, opt Options) []Agent {
	r := &run{s: s, opt: opt, sig: map[int]*Signature{}, why: map[int]string{}, owner: map[int]int{}}
	for pid, p := range s.Procs {
		if sig, why := match(p.Exe, p.Comm, p.Args); sig != nil {
			r.sig[pid], r.why[pid] = sig, why
		}
	}
	llmPIDs := r.llmProcesses()

	var agents []Agent
	// 1. Known agents: the top process of each signature's tree.
	for pid := range s.Procs {
		if r.ownerOf(pid) == pid {
			agents = append(agents, r.known(pid))
		}
	}
	// 2. Editors and unknown processes with LLM traffic.
	editors := map[int][]int{} // editor root -> its processes with LLM traffic
	for pid := range llmPIDs {
		if r.ownerOf(pid) != 0 {
			continue
		}
		if root := r.editorRoot(pid); root != 0 {
			editors[root] = append(editors[root], pid)
			continue
		}
		if r.inBrowser(pid) {
			continue
		}
		if parent := s.Procs[s.Procs[pid].PPID]; parent != nil && llmPIDs[parent.PID] && r.ownerOf(parent.PID) == 0 {
			continue // its parent is reported, with this one as a child
		}
		agents = append(agents, r.unknown(pid, llmPIDs))
	}
	for root, pids := range editors {
		agents = append(agents, r.editor(root, pids))
	}
	// 3. Interpreters holding an LLM key, without LLM traffic.
	if opt.Possible {
		for pid, p := range s.Procs {
			if r.ownerOf(pid) != 0 || llmPIDs[pid] || !interpreters.MatchString(baseName(p.Comm)) {
				continue
			}
			if keys := llmKeys(p); len(keys) > 0 && !r.parentHasKeys(p) {
				a := r.base(p, "unknown", fmt.Sprintf("%s (unknown)", baseName(p.Comm)), RoleAgent, Possible)
				a.Evidence = append(a.Evidence, "has LLM key variable "+strings.Join(keys, ", ")+" (name only)")
				agents = append(agents, a)
			}
		}
	}
	sortAgents(agents)
	return agents
}

type run struct {
	s     *proc.Snapshot
	opt   Options
	sig   map[int]*Signature
	why   map[int]string
	owner map[int]int // pid -> pid of the agent that owns it (0: none); memo
}

// ownerOf returns the pid of the known agent a process belongs to: itself
// when it matches a signature that its owning ancestor does not share,
// otherwise its parent's owner.
func (r *run) ownerOf(pid int) int {
	if o, ok := r.owner[pid]; ok {
		return o
	}
	r.owner[pid] = 0 // cycle guard
	p := r.s.Procs[pid]
	if p == nil {
		return 0
	}
	parentOwner := 0
	if p.PPID != pid {
		parentOwner = r.ownerOf(p.PPID)
	}
	o := parentOwner
	if sig := r.sig[pid]; sig != nil && (parentOwner == 0 || r.sig[parentOwner].ID != sig.ID) {
		o = pid
	}
	r.owner[pid] = o
	return o
}

// llmProcesses returns the processes with a connection to an LLM endpoint.
func (r *run) llmProcesses() map[int]bool {
	out := map[int]bool{}
	for _, c := range r.s.Conns {
		if _, ok := r.llmHost(c); ok {
			out[c.PID] = true
		}
	}
	return out
}

func (r *run) llmHost(c proc.Conn) (string, bool) {
	if c.Listen || c.RemoteIP == nil {
		return "", false
	}
	if h, ok := r.opt.LLMAddrs[c.RemoteIP.String()]; ok {
		return h, true
	}
	if c.RemoteIP.IsLoopback() {
		if name, ok := localModelPorts[c.RemotePort]; ok {
			// The model server itself also has loopback sockets on this
			// port; only the client side counts.
			if c.LocalPort != c.RemotePort {
				return name + " (local)", true
			}
		}
	}
	return "", false
}

func (r *run) known(pid int) Agent {
	p := r.s.Procs[pid]
	sig := r.sig[pid]
	a := r.base(p, sig.ID, sig.Name, sig.Role, Known)
	if a.Role == "" {
		a.Role = RoleAgent
	}
	a.Threat = sig.Threat
	a.Evidence = append(a.Evidence, r.why[pid])
	for _, anc := range r.s.Ancestors(pid) {
		if o := r.ownerOf(anc.PID); o != 0 {
			a.ParentAgent = o
			a.Evidence = append(a.Evidence, fmt.Sprintf("started by agent %s (pid %d)", r.sig[o].Name, o))
			break
		}
	}
	tree := map[int]bool{pid: true}
	for _, d := range r.s.Descendants(pid) {
		if r.ownerOf(d.PID) != pid {
			continue
		}
		tree[d.PID] = true
		role, name := "process", baseName(d.Comm)
		if isMCP(d) {
			role = "mcp_server"
			if pkg := mcpName(d.Args); pkg != "" {
				name = pkg
			}
		}
		a.Children = append(a.Children, Child{PID: d.PID, Role: role, Name: name, Args: scrubArgs(d.Args)})
	}
	r.addNetwork(&a, tree)
	return a
}

func (r *run) editor(root int, llm []int) Agent {
	p := r.s.Procs[root]
	key := baseName(p.Comm)
	if _, ok := Editors[key]; !ok {
		key = baseName(p.Exe)
	}
	a := r.base(p, editorIDs[key], Editors[key]+" (AI features)", RoleAgent, Known)
	sort.Ints(llm)
	tree := map[int]bool{}
	for _, pid := range llm {
		tree[pid] = true
	}
	a.Evidence = append(a.Evidence, "editor processes talk to an LLM API")
	r.addNetwork(&a, tree)
	return a
}

func (r *run) unknown(pid int, llm map[int]bool) Agent {
	p := r.s.Procs[pid]
	a := r.base(p, "unknown", baseName(p.Comm)+" (unknown agent)", RoleAgent, Likely)
	tree := map[int]bool{pid: true}
	for _, d := range r.s.Descendants(pid) {
		if r.ownerOf(d.PID) != 0 {
			continue
		}
		tree[d.PID] = true
		role := "process"
		if isMCP(d) {
			role = "mcp_server"
		}
		a.Children = append(a.Children, Child{PID: d.PID, Role: role, Name: baseName(d.Comm), Args: scrubArgs(d.Args)})
	}
	if keys := llmKeys(p); len(keys) > 0 {
		a.Evidence = append(a.Evidence, "has LLM key variable "+strings.Join(keys, ", ")+" (name only)")
	}
	r.addNetwork(&a, tree)
	return a
}

// base fills the fields every agent has.
func (r *run) base(p *proc.Process, id, name string, role Role, conf string) Agent {
	a := Agent{ID: id, Name: name, Role: role, Confidence: conf, PID: p.PID, User: p.User,
		Exe: p.Exe, Args: scrubArgs(p.Args), Started: p.Started, LLMKeyNames: llmKeys(p)}
	where := p.Exe
	if where == "" && len(p.Args) > 0 {
		where = p.Args[0]
	}
	if m := extensionPath.FindStringSubmatch(strings.ToLower(where)); m != nil {
		a.Version = m[2]
		a.Via = "editor extension " + m[1]
	} else if m := claudeVersion.FindStringSubmatch(where); m != nil {
		a.Version = m[1]
	}
	if a.Via == "" {
		a.Via = r.via(p)
	}
	return a
}

// via says what started a process: an editor, a terminal, or the system.
func (r *run) via(p *proc.Process) string {
	for _, anc := range r.s.Ancestors(p.PID) {
		n := baseName(anc.Comm)
		if ed, ok := Editors[n]; ok {
			return ed
		}
		if shells[n] {
			return "terminal (" + n + ")"
		}
	}
	if p.PPID <= 1 {
		return "system service"
	}
	return ""
}

func (r *run) editorRoot(pid int) int {
	root := 0
	chain := append([]*proc.Process{r.s.Procs[pid]}, r.s.Ancestors(pid)...)
	for _, p := range chain {
		if _, ok := Editors[baseName(p.Comm)]; ok {
			root = p.PID
		} else if _, ok := Editors[baseName(p.Exe)]; ok && p.Exe != "" {
			root = p.PID
		}
	}
	return root
}

func (r *run) inBrowser(pid int) bool {
	chain := append([]*proc.Process{r.s.Procs[pid]}, r.s.Ancestors(pid)...)
	for _, p := range chain {
		if browsers[baseName(p.Comm)] || browsers[baseName(p.Exe)] {
			return true
		}
	}
	return false
}

func (r *run) parentHasKeys(p *proc.Process) bool {
	parent := r.s.Procs[p.PPID]
	return parent != nil && interpreters.MatchString(baseName(parent.Comm)) && len(llmKeys(parent)) > 0
}

// addNetwork records the endpoints and listening ports of an agent's tree.
func (r *run) addNetwork(a *Agent, tree map[int]bool) {
	seen := map[string]bool{}
	llmHosts := map[string]bool{}
	listen := map[int]bool{}
	for _, c := range r.s.ConnsOf(tree) {
		if c.Listen {
			listen[c.LocalPort] = true
			continue
		}
		key := net.JoinHostPort(c.RemoteIP.String(), fmt.Sprint(c.RemotePort))
		if seen[key] {
			continue
		}
		seen[key] = true
		e := Endpoint{IP: c.RemoteIP.String(), Port: c.RemotePort, Service: Services[c.RemotePort]}
		if h, ok := r.llmHost(c); ok {
			e.Host, e.LLM = h, true
			llmHosts[h] = true
		}
		a.Endpoints = append(a.Endpoints, e)
	}
	sort.Slice(a.Endpoints, func(i, j int) bool {
		x, y := a.Endpoints[i], a.Endpoints[j]
		if x.LLM != y.LLM {
			return x.LLM
		}
		if x.IP != y.IP {
			return x.IP < y.IP
		}
		return x.Port < y.Port
	})
	for p := range listen {
		a.Listening = append(a.Listening, p)
	}
	sort.Ints(a.Listening)
	hosts := make([]string, 0, len(llmHosts))
	for h := range llmHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		a.Evidence = append(a.Evidence, "connects to "+h)
	}
}

func llmKeys(p *proc.Process) []string {
	var out []string
	for _, n := range p.EnvNames {
		if LLMKeyNames[n] {
			out = append(out, n)
		}
	}
	return out
}

// isMCP reports whether a child process is an MCP server: its program or
// the package or script it runs names MCP. Shells never count, whatever
// their script mentions.
func isMCP(p *proc.Process) bool {
	if shells[baseName(p.Comm)] {
		return false
	}
	head := p.Args
	if len(head) > 4 {
		head = head[:4]
	}
	for _, a := range head {
		if !strings.HasPrefix(a, "-") && len(a) < 300 && mcpWord.MatchString(a) {
			return true
		}
	}
	return mcpWord.MatchString(p.Comm)
}

// mcpName picks the package or script that names an MCP server.
func mcpName(args []string) string {
	for _, a := range args[min(1, len(args)):] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if mcpWord.MatchString(a) {
			return baseName(strings.TrimSuffix(a, "/"))
		}
	}
	return ""
}

// scrubArgs removes credentials and keeps the command line short.
func scrubArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	const maxArgs, maxLen = 16, 160
	out := parse.Args(args)
	if len(out) > maxArgs {
		out = append(out[:maxArgs:maxArgs], fmt.Sprintf("…(+%d)", len(args)-maxArgs))
	}
	for i, a := range out {
		if len(a) > maxLen {
			out[i] = a[:maxLen] + "…"
		}
	}
	return out
}

func sortAgents(as []Agent) {
	rank := map[string]int{Known: 0, Likely: 1, Possible: 2}
	sort.SliceStable(as, func(i, j int) bool {
		x, y := as[i], as[j]
		if x.Threat != y.Threat {
			return x.Threat
		}
		if rank[x.Confidence] != rank[y.Confidence] {
			return rank[x.Confidence] < rank[y.Confidence]
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		return x.PID < y.PID
	})
}

// ResolveLLMHosts looks up every LLM host and maps each address to its host.
// Lookups run in parallel with a deadline; a host that fails is skipped.
func ResolveLLMHosts(ctx context.Context, lookup func(ctx context.Context, host string) ([]string, error)) map[string]string {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := map[string]string{}
	for _, h := range LLMHosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			addrs, err := lookup(ctx, h)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, a := range addrs {
				if ip := net.ParseIP(a); ip != nil {
					if _, taken := out[ip.String()]; !taken {
						out[ip.String()] = h
					}
				}
			}
		}(h)
	}
	wg.Wait()
	return out
}
