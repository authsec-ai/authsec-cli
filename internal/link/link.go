package link

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/access"
	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/policy"
	"github.com/authsec-ai/authsec-cli/internal/siem"
)

// SourceKind is the discovery source kind of a machine.
const SourceKind = "vm_sensor"

// Command is work the link hands to the daemon's loop, which owns the
// enforcement engine.
type Command struct {
	Op    string // quarantine | release | reload
	Agent string
	Reply chan Result
}

// Result is how a command went.
type Result struct {
	Instances int
	Err       error
}

// Options configures a link.
type Options struct {
	Version    string
	ConsoleDir string        // where console policies are written
	LogPath    string        // the daemon's event log (access summaries)
	Status     func(string)  // progress for people; may be nil
	Every      time.Duration // heartbeat (default 60s)
}

// Link is a running connection.
type Link struct {
	cfg    *Config
	opt    Options
	client *Client
	host   string
	mid    string

	cmds chan Command
	recs chan events.Record

	mu      sync.Mutex
	agents  []events.Agent
	runtime map[string]any
	dropped int

	// Loop state (one goroutine).
	source    string
	actuation string // off | pending | on
	actToken  string
	sightings int64
	reported  map[string]bool // agent ids reported running
	etag      string
	log       func(events.Record)
}

// New builds a link. It does nothing until Run.
func New(cfg *Config, opt Options) *Link {
	if opt.Every == 0 {
		opt.Every = time.Minute
	}
	if opt.Status == nil {
		opt.Status = func(string) {}
	}
	host, _ := os.Hostname()
	if cfg.Name != "" {
		host = cfg.Name
	}
	return &Link{cfg: cfg, opt: opt, client: NewClient(cfg, opt.Version), host: host, mid: MachineID(),
		cmds: make(chan Command), recs: make(chan events.Record, 5000), reported: map[string]bool{}}
}

// Commands is what the daemon's loop must carry out.
func (l *Link) Commands() <-chan Command { return l.cmds }

// forwarded are the record types the console keeps.
var forwarded = map[string]bool{events.Decision: true, events.Detection: true,
	events.AgentStarted: true, events.AgentStopped: true, events.Sensor: true}

// Tee queues a record for the console. It never blocks.
func (l *Link) Tee(r events.Record) {
	if !forwarded[r.Type] {
		return
	}
	select {
	case l.recs <- r:
	default:
		l.mu.Lock()
		l.dropped++
		l.mu.Unlock()
	}
}

// SetAgents tells the link which agents run and how the daemon is doing.
func (l *Link) SetAgents(agents []events.Agent, rt map[string]any) {
	cp := append([]events.Agent(nil), agents...)
	l.mu.Lock()
	l.agents, l.runtime = cp, rt
	l.mu.Unlock()
}

func (l *Link) snapshot() ([]events.Agent, map[string]any, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.dropped
	l.dropped = 0
	return l.agents, l.runtime, d
}

// bearer is the credential calls use: the actuation credential once the
// console holds it, else the ingest token.
func (l *Link) bearer() string {
	if l.actuation == "on" && l.actToken != "" {
		return l.actToken
	}
	return l.cfg.IngestToken
}

func (l *Link) actuationPath() string { return filepath.Join(Dir(), "actuation.token") }

var actTokenRe = regexp.MustCompile(`^authsec_act_[A-Za-z0-9_-]{43,128}$`)

// loadActuation reads the machine's actuation credential, if it made one.
func (l *Link) loadActuation() {
	b, err := os.ReadFile(l.actuationPath())
	if err != nil {
		return
	}
	if st, err := os.Stat(l.actuationPath()); err != nil || st.Mode().Perm()&0o077 != 0 {
		l.opt.Status("ignoring " + l.actuationPath() + ": readable by others")
		return
	}
	if t := strings.TrimSpace(string(b)); actTokenRe.MatchString(t) {
		l.actToken = t
	}
}

// makeActuation creates the credential this machine offers the console.
func (l *Link) makeActuation() error {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	t := "authsec_act_" + base64.RawURLEncoding.EncodeToString(b[:])
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(l.actuationPath(), []byte(t+"\n"), 0o600); err != nil {
		return err
	}
	l.actToken = t
	return nil
}

// Register announces the machine once (connect uses it to check a
// configuration).
func (l *Link) Register(ctx context.Context) (*Registered, error) {
	_, rt, _ := l.snapshot()
	r := Registration{WorkspaceID: l.cfg.WorkspaceID, Kind: SourceKind, InstanceID: "host:" + l.mid,
		DisplayName: l.host, ClusterName: l.host, AgentVersion: l.opt.Version, Status: "healthy",
		Runtime: map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH}, ReportedSightings: l.sightings}
	for k, v := range rt {
		r.Runtime[k] = v
	}
	if l.actuation == "pending" && l.actToken != "" {
		r.ActuationToken = l.actToken
	}
	reg, err := l.client.Register(ctx, l.bearer(), r)
	if err != nil && l.bearer() != l.cfg.IngestToken && StatusOf(err) == http.StatusUnauthorized {
		// The console turned actuation off (or replaced the credential):
		// speak with the ingest token again.
		l.actuation = "off"
		reg, err = l.client.Register(ctx, l.bearer(), r)
	}
	if err != nil {
		return nil, err
	}
	l.source = reg.SourceID
	prev := l.actuation
	if reg.Actuation != "" {
		l.actuation = reg.Actuation
	}
	if reg.ActuationError != "" {
		l.note("control plane did not take the actuation credential: " + reg.ActuationError)
	}
	// Pending: the console asked this machine to enforce. Make a credential
	// and offer it on the next heartbeat (now).
	if l.actuation == "pending" && r.ActuationToken == "" {
		if l.actToken == "" {
			if err := l.makeActuation(); err != nil {
				return reg, fmt.Errorf("actuation credential: %w", err)
			}
		}
		return l.Register(ctx)
	}
	if l.actuation == "on" && prev != "on" {
		l.note("console enforcement is on: quarantine and release from the console are carried out here")
	}
	if l.actuation == "on" && l.actToken == "" {
		l.note("console enforcement is on but this machine has no credential (" + l.actuationPath() + "): turn enforcement off and on again in the console")
	}
	return reg, nil
}

func (l *Link) note(msg string) {
	l.opt.Status(msg)
	if l.log != nil {
		l.log(events.Record{Type: events.Sensor, Note: "control plane: " + msg})
	}
}

// Run keeps the machine connected until ctx is done. log writes a record to
// the daemon's log.
func (l *Link) Run(ctx context.Context, log func(events.Record)) {
	l.log = log
	l.loadActuation()
	if l.actToken != "" {
		l.actuation = "on" // until the control plane says otherwise
	}
	backoff := 5 * time.Second
	for {
		if _, err := l.Register(ctx); err == nil {
			break
		} else {
			l.opt.Status(fmt.Sprintf("control plane %s: %v (retrying in %s)", l.cfg.Base(), err, backoff))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
	l.note(fmt.Sprintf("connected to %s as machine %s (source %s)", l.cfg.Base(), l.host, l.source))

	heartbeat := time.NewTicker(l.opt.Every)
	defer heartbeat.Stop()
	push := time.NewTicker(5 * time.Second)
	defer push.Stop()
	pull := time.NewTicker(30 * time.Second)
	defer pull.Stop()
	lease := time.NewTicker(10 * time.Second)
	defer lease.Stop()
	summary := time.NewTicker(10 * time.Minute)
	defer summary.Stop()

	l.sightAll(ctx)
	l.pullPolicies(ctx)
	l.pushAccess(ctx)
	for {
		select {
		case <-ctx.Done():
			// Last records, best effort.
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			l.pushEvents(fctx)
			cancel()
			return
		case <-heartbeat.C:
			if _, err := l.Register(ctx); err != nil {
				l.opt.Status("control plane heartbeat: " + err.Error())
				continue
			}
			l.sightAll(ctx)
		case <-push.C:
			l.pushEvents(ctx)
		case <-pull.C:
			l.pullPolicies(ctx)
		case <-lease.C:
			l.runInstructions(ctx)
		case <-summary.C:
			l.pushAccess(ctx)
		}
	}
}

/* ------------------------------- sightings ------------------------------- */

func (l *Link) fingerprint(agentID string) string { return "machine:" + l.mid + ":" + agentID }

// sightAll reports every agent running now, and those that stopped since.
func (l *Link) sightAll(ctx context.Context) {
	agents, _, _ := l.snapshot()
	type group struct {
		name  string
		pids  []int
		users map[string]bool
	}
	byID := map[string]*group{}
	for _, a := range agents {
		g := byID[a.ID]
		if g == nil {
			g = &group{name: a.Name, users: map[string]bool{}}
			byID[a.ID] = g
		}
		g.pids = append(g.pids, a.PID)
		if a.User != "" {
			g.users[a.User] = true
		}
	}
	now := time.Now().UTC()
	send := func(id, name, status string, pids []int, users []string) {
		meta := map[string]any{"machine": map[string]any{"agent_id": id, "host": l.host, "machine_id": l.mid,
			"pids": pids, "users": users, "instances": len(pids)}}
		err := l.client.Sight(ctx, l.bearer(), Sighting{WorkspaceID: l.cfg.WorkspaceID, Source: SourceKind,
			DiscoverySourceID: l.source, Fingerprint: l.fingerprint(id), DisplayName: name + " on " + l.host,
			Metadata: meta, DeploymentOrigin: "manual", ObservedAt: now, RuntimeStatus: status})
		if err != nil {
			l.opt.Status("control plane sighting " + id + ": " + err.Error())
			return
		}
		l.sightings++
		l.reported[id] = status == "running"
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		g := byID[id]
		sort.Ints(g.pids)
		users := make([]string, 0, len(g.users))
		for u := range g.users {
			users = append(users, u)
		}
		sort.Strings(users)
		name := g.name
		if name == "" {
			name = id
		}
		send(id, name, "running", g.pids, users)
	}
	for id, running := range l.reported {
		if running && byID[id] == nil {
			send(id, id, "stopped", []int{}, []string{})
		}
	}
}

/* -------------------------------- events -------------------------------- */

// wire is a record as the console receives it: the log record, its
// compliance tags and the machine.
func (l *Link) wire(r events.Record) json.RawMessage {
	b, _ := json.Marshal(r)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["tags"] = siem.Tags(r)
	m["host"] = l.host
	out, _ := json.Marshal(m)
	return out
}

func (l *Link) pushEvents(ctx context.Context) {
	if l.source == "" {
		return
	}
	_, _, dropped := l.snapshot()
	var batch []json.RawMessage
	if dropped > 0 {
		batch = append(batch, l.wire(events.Record{Time: time.Now(), Type: events.Sensor,
			Note: fmt.Sprintf("control plane: %d records were not sent (queue full)", dropped)}))
	}
	for len(batch) < 500 {
		select {
		case r := <-l.recs:
			if r.Time.IsZero() {
				r.Time = time.Now()
			}
			w := l.wire(r)
			if len(w) > 15000 {
				r.Args, r.Evidence, r.Note = nil, nil, "record too large for the console; see the machine's log"
				w = l.wire(r)
			}
			batch = append(batch, w)
			continue
		default:
		}
		break
	}
	if len(batch) == 0 {
		return
	}
	res, err := l.client.Push(ctx, l.bearer(), l.source, batch)
	if err != nil {
		// Kept for the next push only when the control plane could not be
		// reached; a refused batch is dropped (the machine's log keeps it).
		if StatusOf(err) == 0 {
			for _, raw := range batch {
				var r events.Record
				if json.Unmarshal(raw, &r) == nil {
					l.Tee(r)
				}
			}
		}
		l.opt.Status("control plane events: " + err.Error())
		return
	}
	if res.Rejected > 0 && len(res.Errors) > 0 {
		l.opt.Status(fmt.Sprintf("control plane refused %d records (first: %s)", res.Rejected, res.Errors[0].Error))
	}
}

// pushAccess sends what each agent reached in the last hour.
func (l *Link) pushAccess(ctx context.Context) {
	if l.source == "" || l.opt.LogPath == "" {
		return
	}
	recs, err := events.Read(l.opt.LogPath, time.Now().Add(-time.Hour))
	if err != nil {
		return
	}
	sums := access.Summarize(recs, nil)
	var batch []json.RawMessage
	for _, s := range sums {
		for limit := 40; limit >= 5; limit /= 2 {
			t := trimSummary(s, limit)
			b, _ := json.Marshal(map[string]any{"ts": time.Now().UTC(), "type": "access", "host": l.host,
				"agent": map[string]any{"id": s.ID, "name": s.Name}, "summary": t})
			if len(b) <= 15000 {
				batch = append(batch, b)
				break
			}
		}
	}
	if len(batch) == 0 {
		return
	}
	if _, err := l.client.Push(ctx, l.bearer(), l.source, batch); err != nil {
		l.opt.Status("control plane access summary: " + err.Error())
	}
}

func trimSummary(s access.Summary, n int) access.Summary {
	if len(s.Files) > n {
		s.Files = s.Files[:n]
	}
	if len(s.Destinations) > n {
		s.Destinations = s.Destinations[:n]
	}
	if len(s.Commands) > n {
		s.Commands = s.Commands[:n]
	}
	if len(s.Services) > n {
		s.Services = s.Services[:n]
	}
	if len(s.PIDs) > n {
		s.PIDs = s.PIDs[:n]
	}
	return s
}

/* ------------------------------- policies ------------------------------- */

var consoleFileRe = regexp.MustCompile(`^(_all|[a-z0-9][a-z0-9._-]{0,99})\.yaml$`)

func consoleFile(agentID string) string {
	if agentID == policy.AnyAgent {
		return "_all.yaml"
	}
	return agentID + ".yaml"
}

func (l *Link) pullPolicies(ctx context.Context) {
	if l.source == "" || l.opt.ConsoleDir == "" {
		return
	}
	pols, tag, changed, err := l.client.Policies(ctx, l.bearer(), l.source, l.etag)
	if err != nil {
		l.opt.Status("control plane policies: " + err.Error())
		return
	}
	if !changed {
		return
	}
	n, err := WritePolicies(l.opt.ConsoleDir, pols, l.note)
	if err != nil {
		l.note("could not write console policies: " + err.Error())
		return
	}
	l.etag = tag
	l.note(fmt.Sprintf("%d console policies applied", n))
	l.do(ctx, Command{Op: "reload"})
}

// WritePolicies replaces the console policies in dir with pols. A policy that
// does not pass `policy check` is not written (the previous one stays); it
// returns how many were written.
func WritePolicies(dir string, pols []ConsolePolicy, note func(string)) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	keep := map[string]bool{}
	n := 0
	for _, p := range pols {
		if p.AgentID != policy.AnyAgent && !consoleFileRe.MatchString(p.AgentID+".yaml") {
			note(fmt.Sprintf("console policy for %q skipped: not an agent id", p.AgentID))
			continue
		}
		name := consoleFile(p.AgentID)
		keep[name] = true
		parsed, issues := policy.Parse([]byte(p.Document))
		bad := parsed == nil
		for _, i := range issues {
			if !i.Warning {
				bad = true
			}
		}
		if parsed != nil && parsed.Agent.ID != p.AgentID {
			bad = true
		}
		if bad {
			note(fmt.Sprintf("console policy %s v%d has errors and is not applied (the previous one stays): %v", p.AgentID, p.Version, issues))
			continue
		}
		path := filepath.Join(dir, name)
		if old, err := os.ReadFile(path); err == nil && string(old) == p.Document {
			n++
			continue
		}
		head := fmt.Sprintf("# Saved in the AuthSec console: %s version %d. Edit it there; this file is replaced.\n", p.AgentID, p.Version)
		doc := p.Document
		if !strings.HasPrefix(doc, "# Saved in the AuthSec console") {
			doc = head + doc
		}
		if err := writeFileAtomic(path, []byte(doc), 0o644); err != nil {
			return n, err
		}
		n++
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return n, err
	}
	for _, e := range ents {
		if consoleFileRe.MatchString(e.Name()) && !keep[e.Name()] {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	return n, nil
}

/* ----------------------------- instructions ----------------------------- */

// do hands a command to the daemon's loop and waits for it.
func (l *Link) do(ctx context.Context, c Command) Result {
	c.Reply = make(chan Result, 1)
	select {
	case l.cmds <- c:
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	case <-time.After(30 * time.Second):
		return Result{Err: errors.New("daemon busy")}
	}
	select {
	case r := <-c.Reply:
		return r
	case <-ctx.Done():
		return Result{Err: ctx.Err()}
	case <-time.After(60 * time.Second):
		return Result{Err: errors.New("daemon did not answer")}
	}
}

func (l *Link) runInstructions(ctx context.Context) {
	if l.actuation != "on" || l.actToken == "" {
		return
	}
	items, err := l.client.Lease(ctx, l.actToken, l.host)
	if err != nil {
		if StatusOf(err) == http.StatusUnauthorized {
			l.actuation = "off"
		}
		l.opt.Status("control plane instructions: " + err.Error())
		return
	}
	for _, in := range items {
		var p struct {
			Target  string `json:"target"`
			AgentID string `json:"agent_id"`
			Reason  string `json:"reason"`
		}
		_ = json.Unmarshal(in.Payload, &p)
		op := ""
		switch in.Kind {
		case "quarantine":
			op = "quarantine"
		case "unquarantine":
			op = "release"
		}
		if op == "" || p.Target != "machine" || p.AgentID == "" {
			_ = l.client.Report(ctx, l.actToken, in.ID, false,
				fmt.Sprintf("instruction %s is not something a machine carries out", in.Kind), nil)
			continue
		}
		res := l.do(ctx, Command{Op: op, Agent: p.AgentID})
		msg := ""
		if res.Err != nil {
			msg = res.Err.Error()
		}
		l.note(fmt.Sprintf("console %s of %s: %d instance(s)%s", op, p.AgentID, res.Instances, map[bool]string{true: "", false: ": " + msg}[res.Err == nil]))
		if err := l.client.Report(ctx, l.actToken, in.ID, res.Err == nil, msg,
			map[string]any{"instances": res.Instances, "host": l.host}); err != nil {
			l.opt.Status("control plane report: " + err.Error())
		}
	}
}
