package collector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/link"
	"github.com/authsec-ai/authsec-cli/internal/proc"
)

// Options configures a running collector.
type Options struct {
	Version   string
	StateDir  string
	PolicyDir string        // where delivered policies are written (the daemon loads them first)
	Status    func(string)  // progress for people
	MinEvery  time.Duration // shortest sync interval (default 5s)
}

// Collector is the daemon's uplink to the v2 collector API.
type Collector struct {
	opt    Options
	st     *State
	client *Client

	cmds chan link.Command
	recs chan events.Record

	mu      sync.Mutex
	agents  []events.Agent
	dropped int64

	insts   map[int]*instance // by top pid, kept a while after the agent stops
	pending []AppliedReceipt
	log     func(events.Record)
	every   time.Duration
	stopped bool // a refusal no retry fixes (schema upgrade, credential gone)
}

// New loads an enrolled collector.
func New(opt Options) (*Collector, error) {
	st, err := LoadState(opt.StateDir)
	if err != nil {
		return nil, err
	}
	c, err := NewClient(st.URL, opt.Version)
	if err != nil {
		return nil, err
	}
	if opt.Status == nil {
		opt.Status = func(string) {}
	}
	if opt.MinEvery == 0 {
		opt.MinEvery = 5 * time.Second
	}
	if st.Applied == nil {
		st.Applied = map[string]AppliedState{}
	}
	return &Collector{opt: opt, st: st, client: c, cmds: make(chan link.Command),
		recs: make(chan events.Record, 10000), insts: map[int]*instance{}, every: 30 * time.Second}, nil
}

// State is the collector's identity (no secrets are printed from it).
func (c *Collector) State() *State { return c.st }

// Commands is the work the daemon's loop carries out.
func (c *Collector) Commands() <-chan link.Command { return c.cmds }

// Tee queues a record. It never blocks.
func (c *Collector) Tee(r events.Record) {
	select {
	case c.recs <- r:
	default:
		c.mu.Lock()
		c.dropped++
		c.mu.Unlock()
	}
}

// SetAgents is the daemon's view of what runs.
func (c *Collector) SetAgents(agents []events.Agent, _ map[string]any) {
	cp := append([]events.Agent(nil), agents...)
	c.mu.Lock()
	c.agents = cp
	c.mu.Unlock()
}

func (c *Collector) note(msg string) {
	c.opt.Status("collector: " + msg)
	if c.log != nil {
		c.log(events.Record{Type: events.Sensor, Note: "collector: " + msg})
	}
}

// Run syncs until ctx is done.
func (c *Collector) Run(ctx context.Context, log func(events.Record)) {
	c.log = log
	c.note(fmt.Sprintf("collector %s syncing to %s", c.st.CollectorID, c.st.URL))
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c.syncOnce(fctx)
			cancel()
			return
		case <-timer.C:
		}
		wait := c.every
		if err := c.syncOnce(ctx); err != nil {
			var he *HTTPError
			if errors.As(err, &he) && he.RetryAfter > 0 {
				wait = he.RetryAfter
			} else {
				wait = 30 * time.Second
			}
			c.opt.Status("collector: " + err.Error())
		}
		if c.stopped {
			wait = 10 * time.Minute
		}
		if len(c.recs) > 2000 && wait > c.opt.MinEvery {
			wait = c.opt.MinEvery
		}
		timer.Reset(wait)
	}
}

// refreshInstances updates the objects of running agents and drops agents
// gone for more than ten minutes.
func (c *Collector) refreshInstances(now time.Time) {
	c.mu.Lock()
	agents := c.agents
	c.mu.Unlock()
	for _, a := range agents {
		inst := c.insts[a.PID]
		if inst == nil || inst.agent.ID != a.ID {
			p, _ := proc.Get(a.PID)
			inst = &instance{agent: a, object: objectFor(a, p)}
			c.insts[a.PID] = inst
		}
		inst.seen = now
	}
	for pid, inst := range c.insts {
		if now.Sub(inst.seen) > 10*time.Minute {
			delete(c.insts, pid)
		}
	}
}

// syncOnce sends one batch and applies what comes back.
func (c *Collector) syncOnce(ctx context.Context) error {
	now := time.Now()
	if c.st.needsRotation(now) {
		if err := c.st.rotate(ctx, c.client); err != nil {
			if !c.st.CredentialExpires.IsZero() && now.After(c.st.CredentialExpires) {
				c.stopped = true
				return errCredentialExpired
			}
			c.opt.Status("collector: credential rotation failed (will retry): " + err.Error())
		} else {
			_ = c.st.Save(c.opt.StateDir)
			c.note("credential rotated; valid until " + c.st.CredentialExpires.Format(time.RFC3339))
		}
	}
	c.refreshInstances(now)

	// Observations, with the objects they name.
	var obs []Observation
	used := map[string]bool{}
	var held []events.Record
	for len(obs) < maxObservations {
		var r events.Record
		select {
		case r = <-c.recs:
		default:
		}
		if r.Type == "" {
			break
		}
		if r.Time.IsZero() {
			r.Time = now
		}
		ref := ""
		if r.Agent != nil {
			if inst := c.insts[r.Agent.PID]; inst != nil {
				ref = inst.object.Ref
			}
		}
		ob, ok := observationFor(r, ref)
		if !ok {
			continue
		}
		if ref != "" {
			used[ref] = true
		}
		obs = append(obs, ob)
		held = append(held, r)
	}
	objs := []Object{}
	for _, inst := range c.insts {
		if now.Sub(inst.seen) < time.Minute || used[inst.object.Ref] {
			objs = append(objs, inst.object)
		}
	}
	c.mu.Lock()
	lost := c.dropped
	c.mu.Unlock()
	if obs == nil {
		obs = []Observation{}
	}
	applied := c.pending
	if applied == nil {
		applied = []AppliedReceipt{}
	}
	caps, digest := capabilities(c.opt.Version)
	req := SyncRequest{
		SchemaVersion: SchemaVersion, BatchID: newUUID(), CollectorEpoch: c.st.Epoch, Sequence: c.st.Sequence + 1,
		SentAt: now.UTC().Format(time.RFC3339), Capabilities: caps, CapabilityDigest: digest,
		Objects: objs, Observations: obs, Applied: applied,
		Health: Health{EventsLost: lost, QueueDepth: int64(len(c.recs))},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if len(body) > maxBatchBytes { // too big: keep half for the next batch
		for _, r := range held[len(held)/2:] {
			c.Tee(r)
		}
		req.Observations = obs[:len(obs)/2]
		body, _ = json.Marshal(req)
	}
	resp, err := c.client.Sync(ctx, c.st.Credential, body)
	if err != nil {
		switch StatusOf(err) {
		case 0, 401, 409, 429, 500, 502, 503, 504:
			for _, r := range held { // keep the records for the next try
				c.Tee(r)
			}
		}
		switch StatusOf(err) {
		case 401:
			c.stopped = now.After(c.st.CredentialExpires)
			return fmt.Errorf("credential rejected: %w (if it expired, enroll again)", err)
		case 409:
			return fmt.Errorf("the server holds another collector_epoch or sequence for this collector: an administrator must authorize epoch %s (POST /api/iga/v2/collectors/%s/epoch): %w", c.st.Epoch, c.st.CollectorID, err)
		case 426:
			c.stopped = true
			return fmt.Errorf("the server no longer accepts schema %s: upgrade authsec-cli: %w", SchemaVersion, err)
		case 422:
			// A batch the server cannot accept is dropped, not retried forever.
			c.note("batch refused: " + err.Error())
		}
		return err
	}
	c.mu.Lock()
	c.dropped -= lost
	c.mu.Unlock()
	c.stopped = false
	c.st.Sequence = req.Sequence
	c.pending = nil
	if resp.NextSyncSeconds > 0 {
		c.every = time.Duration(resp.NextSyncSeconds) * time.Second
		if c.every < c.opt.MinEvery {
			c.every = c.opt.MinEvery
		}
		if c.every > 5*time.Minute {
			c.every = 5 * time.Minute
		}
	}
	desired, err := ParseDesired(resp.Desired)
	if err != nil {
		c.note("desired state could not be read: " + err.Error())
	}
	for _, d := range desired {
		c.apply(ctx, d)
	}
	return c.st.Save(c.opt.StateDir)
}

// capabilities is what this collector can do, sent with every batch; the
// server keys publication on the digest of these bytes.
func capabilities(version string) (json.RawMessage, string) {
	caps := map[string]any{
		"observation_fields": []string{"source"},
		"collector":          "authsec-cli",
		"version":            version,
		"policy_format":      PolicyFormat,
		"controls":           []string{"egress", "exec", "filesystem"},
		"modes":              []string{"observe", "enforce"},
		"quarantine":         true,
	}
	raw, _ := json.Marshal(caps)
	return raw, sha256Hex(raw)
}

var agentIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// apply verifies one delivery and puts it in force on the local agent it
// names, queuing a receipt either way.
func (c *Collector) apply(ctx context.Context, d Desired) {
	fail := func(msg string) {
		c.note(fmt.Sprintf("delivery %d for workload %s not applied: %s", d.Revision, d.WorkloadID, msg))
		c.pending = append(c.pending, c.receipt(d, "failed", "", []ControlReceipt{{Kind: "policy", State: "failed",
			ArtifactSHA256: hexOr(d.Controls.SHA256), Test: msg}}))
	}
	if d.PolicyFormat != "" && d.PolicyFormat != PolicyFormat {
		fail("policy format " + d.PolicyFormat + " is not supported")
		return
	}
	manHash := sha256Hex([]byte(d.SignedManifest))
	prev, had := c.st.Applied[d.WorkloadID]

	// The manifest, against the pinned keys (fetched again once for a new key).
	keys, err := ParseKeys(c.st.PolicyKeys)
	if err != nil {
		fail(err.Error())
		return
	}
	m, kid, err := VerifyManifest(d.SignedManifest, keys)
	if errors.Is(err, errUnknownKey) {
		if fresh, ferr := c.client.PolicyKeys(ctx, c.st.Credential); ferr == nil && len(fresh) > 0 {
			c.st.PolicyKeys = fresh
			keys, _ = ParseKeys(fresh)
			m, kid, err = VerifyManifest(d.SignedManifest, keys)
		}
	}
	if err != nil {
		fail(fmt.Sprintf("manifest signature (key %s): %v", kid, err))
		return
	}
	switch {
	case c.st.WorkspaceID != "" && m.WorkspaceID != c.st.WorkspaceID:
		fail("the manifest names another workspace")
		return
	case m.DeliveryRevision != d.Revision:
		fail("the manifest's delivery revision does not match")
		return
	case d.OPABundle.SHA256 != "" && d.OPABundle.SHA256 != m.OPABundleSHA256,
		d.Controls.SHA256 != "" && d.Controls.SHA256 != m.ControlsSHA256:
		fail("the artifact hashes do not match the signed manifest")
		return
	}
	if c.st.WorkspaceID == "" {
		c.st.WorkspaceID = m.WorkspaceID
	}
	mode := m.Mode
	if mode == "" {
		mode = d.Mode
	}
	quarantine := d.Quarantine
	for _, t := range m.Targets {
		if t.WorkloadID == d.WorkloadID && (t.Effect == "quarantine" || t.Effect == "deny") {
			quarantine = true
		}
	}
	agentID, why := c.match(d)
	if agentID == "" {
		fail(why)
		return
	}
	if had && prev.ManifestHash == manHash && prev.Quarantine == quarantine && prev.AgentID == agentID {
		return // already in force
	}

	if d.Revoked || mode == "revoked" || m.Revoked {
		_ = os.Remove(filepath.Join(c.opt.PolicyDir, agentID+".yaml"))
		c.do(ctx, link.Command{Op: "reload"})
		if prev.Quarantine {
			c.do(ctx, link.Command{Op: "release", Agent: agentID})
		}
		c.st.Applied[d.WorkloadID] = AppliedState{Revision: d.Revision, ManifestHash: manHash, AgentID: agentID}
		c.pending = append(c.pending, c.receipt(d, "revoked", agentID, []ControlReceipt{{Kind: "policy", State: "revoked",
			ArtifactSHA256: m.ControlsSHA256, Test: "policy removed from " + agentID}}))
		c.note(fmt.Sprintf("delivery %d revoked the policy of %s", d.Revision, agentID))
		return
	}

	bundle, err := c.fetch(ctx, d.OPABundle, m.OPABundleSHA256)
	if err != nil {
		fail("opa bundle: " + err.Error())
		return
	}
	controlsRaw, err := c.fetch(ctx, d.Controls, m.ControlsSHA256)
	if err != nil {
		fail("controls: " + err.Error())
		return
	}
	data, err := OpenBundle(bundle)
	if err != nil {
		fail(err.Error())
		return
	}
	inScope := false
	for _, w := range data.Targets.WorkloadIDs {
		if w == d.WorkloadID {
			inScope = true
		}
	}
	if !inScope {
		fail("the bundle's targets do not include this workload")
		return
	}
	ctl, err := ParseControls(controlsRaw)
	if err != nil {
		fail(err.Error())
		return
	}
	tr, err := Translate(agentID, mode, data, ctl, m.ControlsSHA256)
	if err != nil {
		fail(err.Error())
		return
	}
	head := fmt.Sprintf("# Delivered by the AuthSec control plane: workload %s, delivery %d, %s mode.\n# Signed manifest %s. This file is replaced on the next delivery.\n",
		d.WorkloadID, d.Revision, mode, manHash[:16])
	if err := os.MkdirAll(c.opt.PolicyDir, 0o755); err != nil {
		fail(err.Error())
		return
	}
	if err := writeAtomic(filepath.Join(c.opt.PolicyDir, agentID+".yaml"), append([]byte(head), tr.Document...)); err != nil {
		fail(err.Error())
		return
	}
	if res := c.do(ctx, link.Command{Op: "reload"}); res.Err != nil {
		fail("reload: " + res.Err.Error())
		return
	}
	state := "observing"
	if mode == "enforce" {
		state = "applied"
	}
	if quarantine && !prev.Quarantine {
		res := c.do(ctx, link.Command{Op: "quarantine", Agent: agentID})
		qs, test := "applied", fmt.Sprintf("%d instance(s) frozen, network cut", res.Instances)
		if res.Err != nil {
			qs, test = "failed", res.Err.Error()
		}
		tr.Controls = append(tr.Controls, ControlReceipt{Kind: "quarantine", State: qs, ArtifactSHA256: m.ControlsSHA256, Test: test})
	} else if !quarantine && prev.Quarantine {
		c.do(ctx, link.Command{Op: "release", Agent: agentID})
	}
	for _, n := range tr.Notes {
		c.note(n)
	}
	c.st.Applied[d.WorkloadID] = AppliedState{Revision: d.Revision, ManifestHash: manHash, AgentID: agentID, Quarantine: quarantine}
	c.pending = append(c.pending, c.receipt(d, state, agentID, tr.Controls))
	c.note(fmt.Sprintf("delivery %d (%s) in force on %s", d.Revision, mode, agentID))
}

// match finds the local agent a delivery is for: by the workload's native
// identity when the server sends it, else the only agent on this machine.
func (c *Collector) match(d Desired) (string, string) {
	ids := map[string]bool{}
	for _, inst := range c.insts {
		if agentIDRe.MatchString(inst.agent.ID) {
			ids[inst.agent.ID] = true
		}
	}
	if len(d.Workload) > 0 {
		want := func(k string) string { s, _ := d.Workload[k].(string); return s }
		for _, inst := range c.insts {
			n := inst.object.Native
			got := func(k string) string { s, _ := n[k].(string); return s }
			switch {
			case want("systemd_unit") != "" && want("systemd_unit") == got("systemd_unit"),
				want("unit") != "" && want("unit") == got("systemd_unit"),
				want("exe") != "" && want("exe") == got("exe") && sameArgv(d.Workload["argv"], n["argv"]):
				if agentIDRe.MatchString(inst.agent.ID) {
					return inst.agent.ID, ""
				}
			}
		}
		if prev, ok := c.st.Applied[d.WorkloadID]; ok && prev.AgentID != "" {
			return prev.AgentID, "" // the agent is not running now; keep its policy current
		}
		return "", "no local process matches the workload (" + want("exe") + ")"
	}
	if len(ids) == 1 {
		for id := range ids {
			return id, ""
		}
	}
	if prev, ok := c.st.Applied[d.WorkloadID]; ok && prev.AgentID != "" {
		return prev.AgentID, ""
	}
	return "", fmt.Sprintf("the delivery does not say which process it is for and %d agents run here", len(ids))
}

func sameArgv(want, got any) bool {
	w, _ := json.Marshal(want)
	g, _ := json.Marshal(got)
	return string(w) == "null" || string(w) == string(g)
}

func (c *Collector) fetch(ctx context.Context, a Artifact, wantSHA string) ([]byte, error) {
	var body []byte
	if a.Body != "" {
		b, err := base64.StdEncoding.DecodeString(a.Body)
		if err != nil {
			return nil, errors.New("inline body is not base64")
		}
		body = b
	} else {
		b, err := c.client.Artifact(ctx, c.st.Credential, a.URL)
		if err != nil {
			return nil, err
		}
		body = b
	}
	if got := sha256Hex(body); got != wantSHA {
		return nil, fmt.Errorf("sha256 %s does not match the signed manifest", got[:16])
	}
	return body, nil
}

// do hands a command to the daemon's loop.
func (c *Collector) do(ctx context.Context, cmd link.Command) link.Result {
	cmd.Reply = make(chan link.Result, 1)
	select {
	case c.cmds <- cmd:
	case <-ctx.Done():
		return link.Result{Err: ctx.Err()}
	case <-time.After(30 * time.Second):
		return link.Result{Err: errors.New("daemon busy")}
	}
	select {
	case r := <-cmd.Reply:
		return r
	case <-ctx.Done():
		return link.Result{Err: ctx.Err()}
	case <-time.After(60 * time.Second):
		return link.Result{Err: errors.New("daemon did not answer")}
	}
}

func (c *Collector) receipt(d Desired, state, agentID string, ctl []ControlReceipt) AppliedReceipt {
	if ctl == nil {
		ctl = []ControlReceipt{}
	}
	return AppliedReceipt{
		WorkloadID: d.WorkloadID, DeliveryRevision: d.Revision,
		RuntimeGeneration: runtimeGeneration(agentID), State: state, Controls: ctl,
		ObservedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// runtimeGeneration names the running incarnation a receipt is about: this
// boot of this machine, and the agent.
func runtimeGeneration(agentID string) string {
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	g := strings.TrimSpace(string(boot))
	if g == "" {
		g = "boot-unknown"
	}
	if agentID != "" {
		g += ":" + agentID
	}
	return g
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func hexOr(s string) string {
	if hex64.MatchString(s) {
		return s
	}
	return sha256Hex(nil)
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
