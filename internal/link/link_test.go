package link

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

const testWS = "11111111-2222-3333-4444-555555555555"

func TestConfigValidate(t *testing.T) {
	ok := Config{URL: "https://api.example.com", WorkspaceID: testWS, IngestToken: "aid_x"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"http remote":    func(c *Config) { c.URL = "http://api.example.com" },
		"creds in url":   func(c *Config) { c.URL = "https://u:p@api.example.com" },
		"bad workspace":  func(c *Config) { c.WorkspaceID = "acme" },
		"no token":       func(c *Config) { c.IngestToken = "" },
		"token w/ space": func(c *Config) { c.IngestToken = "a b" },
	} {
		c := ok
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	local := ok
	local.URL = "http://127.0.0.1:7468"
	if err := local.Validate(); err != nil {
		t.Errorf("http on loopback: %v", err)
	}
}

func TestSaveLoadRefusesOpenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "connect.json")
	c := &Config{URL: "https://api.example.com/", WorkspaceID: testWS, IngestToken: "aid_secret"}
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got.IngestToken != "aid_secret" || got.Base() != "https://api.example.com" {
		t.Fatalf("load: %+v %v", got, err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Errorf("0644 file: %v", err)
	}
}

const goodPolicy = `apiVersion: authsec.ai/v1
kind: AgentPolicy
agent:
  id: claude-code
mode: enforce
network:
  default: allow
`

func TestWritePolicies(t *testing.T) {
	dir := t.TempDir()
	var notes []string
	note := func(s string) { notes = append(notes, s) }
	stale := filepath.Join(dir, "old-agent.yaml")
	_ = os.WriteFile(stale, []byte("x"), 0o644)
	mine := filepath.Join(dir, "notes.txt") // not a console file: kept
	_ = os.WriteFile(mine, []byte("x"), 0o644)

	n, err := WritePolicies(dir, []ConsolePolicy{
		{AgentID: "claude-code", Version: 3, Document: goodPolicy},
		{AgentID: "*", Version: 1, Document: strings.Replace(goodPolicy, "id: claude-code", `id: "*"`, 1)},
		{AgentID: "codex", Version: 2, Document: strings.Replace(goodPolicy, "id: claude-code", "id: codex", 1) + "network:\n  default: maybe\n"},
		{AgentID: "aider", Version: 1, Document: goodPolicy}, // names another agent
		{AgentID: "../etc", Version: 1, Document: goodPolicy},
	}, note)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("%d written, want 2 (notes %v)", n, notes)
	}
	b, err := os.ReadFile(filepath.Join(dir, "claude-code.yaml"))
	if err != nil || !strings.Contains(string(b), "version 3") || !strings.Contains(string(b), "default: allow") {
		t.Errorf("claude-code.yaml: %s %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "_all.yaml")); err != nil {
		t.Error("the * policy was not written as _all.yaml")
	}
	for _, p := range []string{"codex.yaml", "aider.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			t.Errorf("%s written", p)
		}
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("a console policy no longer in the console was kept")
	}
	if _, err := os.Stat(mine); err != nil {
		t.Error("a file the console did not write was removed")
	}
	if len(notes) != 3 {
		t.Errorf("notes: %v", notes)
	}
}

// fakePlane is a control plane that records what the machine sends.
type fakePlane struct {
	mu          sync.Mutex
	actuation   string // what registration answers
	offered     string
	sightings   []Sighting
	events      []map[string]any
	reports     []map[string]any
	instruction []Instruction
	bearers     map[string]string // path -> last bearer
}

func (f *fakePlane) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.bearers[r.URL.Path] = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch {
		case r.URL.Path == "/authsec/discovery/agent-registration":
			if tok, _ := body["actuation_token"].(string); tok != "" && f.actuation == "pending" {
				f.offered, f.actuation = tok, "on"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"discovery_source_id": "src-1", "actuation": f.actuation})
		case r.URL.Path == "/authsec/discovery/sightings":
			b, _ := json.Marshal(body)
			var s Sighting
			_ = json.Unmarshal(b, &s)
			f.sightings = append(f.sightings, s)
		case r.URL.Path == "/authsec/discovery/agentkit/machine/events":
			for _, e := range body["events"].([]any) {
				f.events = append(f.events, e.(map[string]any))
			}
			_, _ = w.Write([]byte(`{"accepted":1}`))
		case r.URL.Path == "/authsec/discovery/agentkit/machine/policies":
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"etag": `"v1"`, "policies": []ConsolePolicy{{AgentID: "claude-code", Version: 1, Document: goodPolicy}}})
		case r.URL.Path == "/authsec/provisioning/instructions":
			_ = json.NewEncoder(w).Encode(map[string]any{"instructions": f.instruction})
			f.instruction = nil
		case strings.HasPrefix(r.URL.Path, "/authsec/provisioning/instructions/"):
			body["id"] = strings.Split(r.URL.Path, "/")[4]
			f.reports = append(f.reports, body)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestLinkEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	if os.Geteuid() == 0 {
		t.Skip("Dir() is /etc/authsec as root")
	}
	f := &fakePlane{actuation: "pending", bearers: map[string]string{},
		instruction: []Instruction{
			{ID: "i1", Kind: "quarantine", Payload: json.RawMessage(`{"target":"machine","agent_id":"claude-code"}`)},
			{ID: "i2", Kind: "network_policy", Payload: json.RawMessage(`{"namespace":"x"}`)},
		}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	cfg := &Config{URL: srv.URL, WorkspaceID: testWS, IngestToken: "aid_ingest"}
	consoleDir := filepath.Join(home, "console")
	l := New(cfg, Options{Version: "test", ConsoleDir: consoleDir, Every: time.Hour})
	l.SetAgents([]events.Agent{{ID: "claude-code", Name: "Claude Code", PID: 10, User: "dev"}, {ID: "claude-code", Name: "Claude Code", PID: 11}}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logged []events.Record
	var logMu sync.Mutex
	go l.Run(ctx, func(r events.Record) { logMu.Lock(); logged = append(logged, r); logMu.Unlock() })

	// The daemon's loop: carry out commands.
	var got []Command
	deadline := time.After(20 * time.Second)
	for len(got) < 2 { // reload (policies) + quarantine
		select {
		case c := <-l.Commands():
			got = append(got, c)
			c.Reply <- Result{Instances: 2}
		case <-deadline:
			t.Fatalf("commands: %+v", got)
		}
	}
	if got[0].Op != "reload" || got[1].Op != "quarantine" || got[1].Agent != "claude-code" {
		t.Errorf("commands %+v", got)
	}
	l.Tee(events.Record{Type: events.Decision, Kind: "network", Action: "deny", Enforced: true, Agent: &events.Agent{ID: "claude-code"}})
	l.Tee(events.Record{Type: events.File, Path: "/x"}) // not forwarded
	time.Sleep(6 * time.Second)                         // one push tick
	cancel()

	f.mu.Lock()
	defer f.mu.Unlock()
	if !actTokenRe.MatchString(f.offered) {
		t.Errorf("offered actuation credential %q", f.offered)
	}
	if st, err := os.Stat(filepath.Join(home, "authsec", "actuation.token")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("actuation.token: %v %v", st, err)
	}
	if f.bearers["/authsec/provisioning/instructions"] != f.offered || f.bearers["/authsec/discovery/agentkit/machine/events"] != f.offered {
		t.Errorf("after handover the machine must speak with its credential: %v", f.bearers)
	}
	if len(f.sightings) != 1 || f.sightings[0].Fingerprint != "machine:"+MachineID()+":claude-code" ||
		f.sightings[0].Source != "vm_sensor" || f.sightings[0].RuntimeStatus != "running" {
		t.Errorf("sightings %+v", f.sightings)
	}
	m := f.sightings[0].Metadata["machine"].(map[string]any)
	if m["agent_id"] != "claude-code" || m["instances"] != float64(2) {
		t.Errorf("sighting metadata %v", m)
	}
	var deny map[string]any
	for _, e := range f.events {
		if e["type"] == "file" {
			t.Error("a file record was sent")
		}
		if e["action"] == "deny" {
			deny = e
		}
	}
	if deny == nil || !strings.Contains(strings.Join(toStrings(deny["tags"]), ","), "LLM06") {
		t.Errorf("deny record with tags not sent: %v", f.events)
	}
	if len(f.reports) != 2 || f.reports[0]["success"] != true || f.reports[1]["success"] != false {
		t.Errorf("reports %v", f.reports)
	}
	if _, err := os.Stat(filepath.Join(consoleDir, "claude-code.yaml")); err != nil {
		t.Error("console policy not written")
	}
}

func toStrings(v any) []string {
	var out []string
	if xs, ok := v.([]any); ok {
		for _, x := range xs {
			s, _ := x.(string)
			out = append(out, s)
		}
	}
	return out
}
