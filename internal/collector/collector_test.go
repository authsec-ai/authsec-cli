package collector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/policy"
)

// signManifest signs like the server's sign.SignManifest: a JSON array of
// compact ES256 JWS with raw R||S signatures over json.Marshal(manifest).
func signManifest(t *testing.T, m Manifest, key *ecdsa.PrivateKey, kid string) string {
	t.Helper()
	payload, _ := json.Marshal(m)
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": kid})
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	out, _ := json.Marshal([]string{in + "." + base64.RawURLEncoding.EncodeToString(sig)})
	return string(out)
}

func testKey(t *testing.T, kid string) (*ecdsa.PrivateKey, PolicyKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return k, PolicyKey{KeyID: kid, PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Current: true}
}

func TestVerifyManifest(t *testing.T) {
	k1, pk1 := testKey(t, "k1")
	k2, _ := testKey(t, "k2")
	keys, err := ParseKeys([]PolicyKey{pk1})
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{WorkspaceID: "ws", PublicationID: "pub", DeliveryRevision: 3, OPABundleSHA256: "aa", ControlsSHA256: "bb",
		KeyID: "k1", Mode: "observe", Targets: []TargetEffect{{WorkloadID: "w1", Effect: "quarantine", Source: "fact"}}}
	got, _, err := VerifyManifest(signManifest(t, m, k1, "k1"), keys)
	if err != nil || got.DeliveryRevision != 3 || got.ControlsSHA256 != "bb" || len(got.Targets) != 1 {
		t.Fatalf("valid manifest: %+v %v", got, err)
	}
	if _, kid, err := VerifyManifest(signManifest(t, m, k2, "k2"), keys); err == nil || kid != "k2" {
		t.Errorf("unknown key accepted: %v", err)
	}
	// Signed by k2 but claiming k1: the signature does not verify.
	if _, _, err := VerifyManifest(signManifest(t, m, k2, "k1"), keys); err == nil {
		t.Error("a forged signature verified")
	}
	// A payload changed after signing.
	signed := signManifest(t, m, k1, "k1")
	var parts []string
	_ = json.Unmarshal([]byte(signed), &parts)
	seg := strings.Split(parts[0], ".")
	m.ControlsSHA256 = "cc"
	p2, _ := json.Marshal(m)
	seg[1] = base64.RawURLEncoding.EncodeToString(p2)
	tampered, _ := json.Marshal([]string{strings.Join(seg, ".")})
	if _, _, err := VerifyManifest(string(tampered), keys); err == nil {
		t.Error("a tampered manifest verified")
	}
	if _, _, err := VerifyManifest(`not json`, keys); err == nil {
		t.Error("garbage verified")
	}
}

func bundle(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

const dataJSON = `{"policy_revision":"r1","targets":{"workload_ids":["w1"]},"rules":[
 {"id":"exec-allow","action":"exec","effect":"allow"},
 {"id":"ssh","action":"file.read","path":"/home/a/.ssh/**","effect":"deny"},
 {"id":"tmp","action":"file.write","path":"/tmp/**","effect":"allow"},
 {"id":"sec","action":"secret.read","resource_id":"r9","effect":"allow"}]}`

func TestOpenBundleRefusesOtherRego(t *testing.T) {
	ok := bundle(t, map[string]string{"policy.rego": string(decisionRego), "data.json": dataJSON, ".signatures.json": "{}"})
	d, err := OpenBundle(ok)
	if err != nil || len(d.Rules) != 4 || d.Targets.WorkloadIDs[0] != "w1" {
		t.Fatalf("pinned template: %+v %v", d, err)
	}
	evil := strings.Replace(string(decisionRego), `rule.effect == "deny"`, `false`, 1)
	if _, err := OpenBundle(bundle(t, map[string]string{"policy.rego": evil, "data.json": dataJSON})); err == nil {
		t.Error("a changed policy.rego was accepted")
	}
	if _, err := OpenBundle(bundle(t, map[string]string{"policy.rego": string(decisionRego), "data.json": dataJSON, "extra.rego": "package x"})); err == nil {
		t.Error("an extra module was accepted")
	}
	if _, err := OpenBundle(bundle(t, map[string]string{"policy.rego": string(decisionRego),
		"data.json": `{"rules":[{"id":"x","action":"exec","effect":"maybe"}]}`})); err == nil {
		t.Error("an unknown effect was accepted")
	}
}

const controlsJSON = `{"schema":"authsec.controls.v1","profile":"linux-managed-v1",
 "filesystem":{"baseline":{"loaders":{"amd64":"/lib64/ld.so"},"libraries":["/lib/libc.so.6"],"certificates":[],"readonly_config":[]},"paths":[]},
 "egress":[{"rule_id":"e1","resource_id":"r1","address":"api.anthropic.com","port":443,"protocol":"tcp","effect":"allow"},
           {"rule_id":"e2","resource_id":"r2","address":"10.0.0.0/8","port":0,"protocol":"tcp","effect":"deny"},
           {"rule_id":"e3","resource_id":"r3","address":"1.2.3.4","port":22,"protocol":"tcp","effect":"require_approval"}],
 "exec":[{"rule_id":"exec-allow","effect":"allow"}],"admission":[],"broker":[]}`

func TestTranslateFollowsTheTemplate(t *testing.T) {
	var d Data
	_ = json.Unmarshal([]byte(dataJSON), &d)
	c, err := ParseControls([]byte(controlsJSON))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Translate("claude-code", "enforce", &d, c, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	p := tr.Policy
	if p.Mode != policy.Enforce || p.Network.Default != policy.Deny || p.Commands.Default != policy.Allow {
		t.Errorf("mode/defaults: %+v", p)
	}
	if len(p.Network.Allow) != 1 || p.Network.Allow[0].Host != "api.anthropic.com" || p.Network.Allow[0].Port != 443 {
		t.Errorf("allow: %+v", p.Network.Allow)
	}
	if len(p.Network.Deny) != 2 || p.Network.Deny[0].CIDR != "10.0.0.0/8" || p.Network.Deny[1].CIDR != "1.2.3.4/32" {
		t.Errorf("deny (require_approval is denied without a human): %+v", p.Network.Deny)
	}
	if strings.Join(p.Filesystem.Deny, ",") != "/home/a/.ssh" || strings.Join(p.Filesystem.ReadWrite, ",") != "/tmp" ||
		!strings.Contains(strings.Join(p.Filesystem.ReadOnly, ","), "/lib/libc.so.6") {
		t.Errorf("filesystem: %+v", p.Filesystem)
	}
	var secret bool
	for _, r := range tr.Controls {
		if r.Kind == "secret" && r.State == stateUnsupported {
			secret = true
		}
		if r.ArtifactSHA256 != strings.Repeat("a", 64) {
			t.Errorf("receipt without the controls hash: %+v", r)
		}
	}
	if !secret {
		t.Errorf("secret.read not reported unsupported: %+v", tr.Controls)
	}
	if parsed, issues := policy.Parse(tr.Document); parsed == nil || len(issues) > 0 && !issues[0].Warning {
		t.Errorf("document does not pass policy check: %v\n%s", issues, tr.Document)
	}

	// No exec rule: default deny, as the template's default_deny.
	d.Rules = d.Rules[1:]
	tr, _ = Translate("claude-code", "observe", &d, c, strings.Repeat("a", 64))
	if tr.Policy.Commands.Default != policy.Deny || tr.Policy.Mode != policy.Monitor {
		t.Errorf("no exec rule: %+v", tr.Policy.Commands)
	}
	if _, err := Translate("x", "sideways", &d, c, ""); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestParseDesiredBothShapes(t *testing.T) {
	if d, err := ParseDesired([]byte(`null`)); err != nil || d != nil {
		t.Errorf("null: %v %v", d, err)
	}
	one, err := ParseDesired([]byte(`{"revision":2,"manifest_id":"m","policy_format":"authsec.runtime.v1","opa_bundle":{"url":"/u","sha256":"s"},"controls":{"url":"/c","sha256":"t"},"signed_manifest":"[]","mode":"observe"}`))
	if err != nil || len(one) != 1 || one[0].Revision != 2 {
		t.Errorf("object: %+v %v", one, err)
	}
	many, err := ParseDesired([]byte(`{"bindings":[{"workload_id":"a","revision":1},{"workload_id":"b","revision":4,"quarantine":true,"workload":{"exe":"/x"}}]}`))
	if err != nil || len(many) != 2 || !many[1].Quarantine || many[1].Workload["exe"] != "/x" {
		t.Errorf("bindings: %+v %v", many, err)
	}
}

// The server refuses a whole batch that has a secret-like key name anywhere.
var bannedKeys = []string{"password", "passwd", "secret", "secret_value", "token", "api_key", "apikey", "private_key",
	"access_key", "client_secret", "connection_string", "shadow", "credential", "credentials", "kubeconfig",
	"authorization", "bearer", "canonical_id", "iga_id", "graph_id"}

func walkKeys(t *testing.T, v any, path string) {
	switch n := v.(type) {
	case map[string]any:
		for k, c := range n {
			for _, b := range bannedKeys {
				if strings.ToLower(k) == b {
					t.Errorf("banned key %s at %s", k, path)
				}
			}
			walkKeys(t, c, path+"."+k)
		}
	case []any:
		for _, c := range n {
			walkKeys(t, c, path+"[]")
		}
	}
}

func TestBatchUsesOnlyAcceptedNames(t *testing.T) {
	now := time.Now()
	recs := []events.Record{
		{Time: now, Type: events.Process, Agent: &events.Agent{ID: "a", PID: 1}, PID: 2, Comm: "git", Exe: "/usr/bin/git", Args: []string{"git", "push"}},
		{Time: now, Type: events.Network, Agent: &events.Agent{ID: "a", PID: 1}, Dst: &events.Dst{IP: "1.2.3.4", Port: 443, Host: "api.x.com", LLM: true}},
		{Time: now, Type: events.File, Agent: &events.Agent{ID: "a", PID: 1}, Path: "/home/a/.aws/credentials", Access: "read", Sensitive: true},
		{Time: now, Type: events.Decision, Kind: "network", Action: "deny", Enforced: true, Agent: &events.Agent{ID: "a", PID: 1}, Dst: &events.Dst{IP: "5.6.7.8", Port: 80}},
		{Time: now, Type: events.Decision, Kind: "command", Action: "deny", Agent: &events.Agent{ID: "a", PID: 1}, Comm: "rm"},
		{Time: now, Type: events.AgentStopped, Agent: &events.Agent{ID: "a", PID: 1}},
	}
	want := []struct{ kind, outcome string }{
		{"runtime.process_exec", "success"}, {"runtime.network_connect", "success"}, {"runtime.file_open", "success"},
		{"runtime.network_connect", "denied"}, {"runtime.process_exec", "attempted"}, {"runtime.process_exit", "success"},
	}
	req := SyncRequest{SchemaVersion: SchemaVersion, Objects: []Object{objectFor(events.Agent{ID: "a", Name: "A", PID: 1}, nil)}}
	ids := map[string]bool{}
	for i, r := range recs {
		ob, ok := observationFor(r, "o_p1")
		if !ok {
			t.Fatalf("record %d not mapped", i)
		}
		if ob.Kind != want[i].kind || ob.Outcome != want[i].outcome {
			t.Errorf("record %d: %s/%s, want %s/%s", i, ob.Kind, ob.Outcome, want[i].kind, want[i].outcome)
		}
		if ids[ob.EventID] {
			t.Errorf("duplicate event id %s", ob.EventID)
		}
		ids[ob.EventID] = true
		req.Observations = append(req.Observations, ob)
	}
	for _, r := range []events.Record{{Type: events.Sensor}, {Type: events.Detection}, {Type: events.Decision, Action: "allow", Kind: "network"}} {
		if _, ok := observationFor(r, ""); ok {
			t.Errorf("%s/%s should not be sent", r.Type, r.Action)
		}
	}
	raw, _ := json.Marshal(req)
	var generic any
	_ = json.Unmarshal(raw, &generic)
	walkKeys(t, generic, "$")
	if !strings.HasPrefix(req.Objects[0].Ref, "o_") {
		t.Errorf("ref %s", req.Objects[0].Ref)
	}
}

func TestRotationMessageIsTheServers(t *testing.T) {
	// services.RotateSignedMessage("c", "n", "t", "", "") on the server.
	want := "authsec.collector.rotate.v1\nc\nn\nt\n\n"
	got := strings.Join([]string{"authsec.collector.rotate.v1", "c", "n", "t", "", ""}, "\n")
	if got != want {
		t.Fatalf("%q", got)
	}
}

func TestNeedsRotation(t *testing.T) {
	now := time.Now()
	s := &State{CredentialExpires: now.Add(20 * time.Hour)}
	if s.needsRotation(now) {
		t.Error("rotated with 20 hours left")
	}
	s.CredentialExpires = now.Add(5 * time.Hour)
	if !s.needsRotation(now) {
		t.Error("not rotated with 5 hours left")
	}
}

func TestStateFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	s := &State{CollectorID: "c", Credential: "authsec_col_x", InstallationKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatal(err)
	}
	if err := chmod(statePath(dir), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil {
		t.Error("a readable state file was accepted")
	}
}

func chmod(p string, m uint32) error { return osChmod(p, m) }
