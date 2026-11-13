package collector

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
)

// decisionRego is the server's pinned typed template (authsec.runtime.v1).
// The compiler emits it unchanged and puts every rule in data.json, so a
// bundle whose policy.rego differs is refused: this collector evaluates the
// template's logic natively (see translate.go), never other Rego.
//
//go:embed decision.rego
var decisionRego []byte

// Manifest is the detached, signed claim over a delivery (the server's
// sign.Manifest; same fields, same order, so it re-encodes byte for byte).
type Manifest struct {
	WorkspaceID        string         `json:"workspace_id"`
	PublicationID      string         `json:"publication_id"`
	TargetScope        string         `json:"target_scope,omitempty"`
	DeliveryRevision   int64          `json:"delivery_revision"`
	PolicyRevisionHash string         `json:"policy_revision_hash"`
	GraphRevision      int64          `json:"graph_revision"`
	TargetDigest       string         `json:"target_digest"`
	CapabilityDigest   string         `json:"capability_digest,omitempty"`
	CompilerBuild      string         `json:"compiler_build"`
	OPABundleSHA256    string         `json:"opa_bundle_sha256"`
	ControlsSHA256     string         `json:"controls_sha256"`
	RevocationEpoch    int64          `json:"revocation_epoch"`
	KeyID              string         `json:"key_id"`
	CreatedAt          string         `json:"created_at"`
	Mode               string         `json:"mode"`
	Revoked            bool           `json:"revoked,omitempty"`
	Targets            []TargetEffect `json:"targets,omitempty"`
}

// TargetEffect is a workload-level override baked in at publish time.
type TargetEffect struct {
	WorkloadID string `json:"workload_id"`
	Effect     string `json:"effect"`
	Source     string `json:"source"`
}

// ParseKeys reads PEM public keys (P-256) by key id.
func ParseKeys(keys []PolicyKey) (map[string]*ecdsa.PublicKey, error) {
	out := map[string]*ecdsa.PublicKey{}
	for _, k := range keys {
		block, _ := pem.Decode([]byte(k.PublicKeyPEM))
		if block == nil || k.KeyID == "" {
			return nil, fmt.Errorf("policy key %q is not a PEM public key", k.KeyID)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("policy key %q: %v", k.KeyID, err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("policy key %q is not P-256", k.KeyID)
		}
		out[k.KeyID] = ec
	}
	return out, nil
}

// VerifyManifest checks the signed manifest (a JSON array of compact ES256
// JWS, one per signing key during rotation) against the pinned keys and
// returns the claim. The payload must be the canonical encoding.
func VerifyManifest(signed string, keys map[string]*ecdsa.PublicKey) (*Manifest, string, error) {
	var parts []string
	if err := json.Unmarshal([]byte(signed), &parts); err != nil || len(parts) == 0 {
		return nil, "", errors.New("manifest is not signed")
	}
	var unknown string
	for _, part := range parts {
		kid, payload, err := verifyJWS(part, keys)
		if err != nil {
			if errors.Is(err, errUnknownKey) {
				unknown = kid
				continue
			}
			return nil, kid, err
		}
		var m Manifest
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&m); err != nil {
			return nil, kid, fmt.Errorf("manifest: %v", err)
		}
		if m.Targets != nil {
			sort.Slice(m.Targets, func(i, j int) bool { return m.Targets[i].WorkloadID < m.Targets[j].WorkloadID })
		}
		again, _ := json.Marshal(m)
		if !bytes.Equal(again, payload) {
			return nil, kid, errors.New("manifest is not canonical")
		}
		return &m, kid, nil
	}
	return nil, unknown, fmt.Errorf("%w %q", errUnknownKey, unknown)
}

var errUnknownKey = errors.New("manifest is signed by an unknown key")

func verifyJWS(compact string, keys map[string]*ecdsa.PublicKey) (string, []byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", nil, errors.New("signature is not a compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, errors.New("signature header is not base64url")
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "ES256" || h.Kid == "" {
		return "", nil, errors.New("signature is not ES256 with a key id")
	}
	pub := keys[h.Kid]
	if pub == nil {
		return h.Kid, nil, errUnknownKey
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return h.Kid, nil, errors.New("signature encoding is invalid")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return h.Kid, nil, errors.New("manifest signature did not verify")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return h.Kid, nil, errors.New("signature payload is not base64url")
	}
	return h.Kid, payload, nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Data is the bundle's data.json: the resolved rules of the template.
type Data struct {
	PolicyRevision any `json:"policy_revision"`
	Targets        struct {
		WorkloadIDs []string `json:"workload_ids"`
	} `json:"targets"`
	Rules []DataRule `json:"rules"`
}

// DataRule is one typed rule.
type DataRule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	ResourceID string `json:"resource_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Effect     string `json:"effect"`
	Adapter    string `json:"adapter,omitempty"`
}

// OpenBundle reads the gzip tar, refuses any policy.rego but the pinned
// template, and returns data.json. The bundle's bytes were already matched
// to the signed manifest's hash, which is what authenticates them.
func OpenBundle(tarGz []byte) (*Data, error) {
	zr, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return nil, fmt.Errorf("bundle is not gzip: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(io.LimitReader(zr, 8<<20))
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("bundle member %q is not a regular file", hdr.Name)
		}
		name := strings.TrimPrefix(hdr.Name, "/")
		if _, dup := files[name]; dup {
			return nil, errors.New("bundle file name is duplicated")
		}
		b, err := io.ReadAll(io.LimitReader(tr, 4<<20))
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	for name := range files {
		switch name {
		case "policy.rego", "data.json", ".signatures.json", ".manifest":
		default:
			return nil, fmt.Errorf("bundle carries an unexpected file %q", name)
		}
	}
	rego, ok := files["policy.rego"]
	if !ok {
		return nil, errors.New("bundle has no policy.rego")
	}
	if !bytes.Equal(bytes.TrimSpace(rego), bytes.TrimSpace(decisionRego)) {
		return nil, errors.New("bundle's policy.rego is not the pinned authsec.runtime.v1 template: refused")
	}
	raw, ok := files["data.json"]
	if !ok {
		return nil, errors.New("bundle has no data.json")
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("data.json: %v", err)
	}
	for _, r := range d.Rules {
		switch r.Effect {
		case "allow", "deny", "require_approval":
		default:
			return nil, fmt.Errorf("rule %s has effect %q", r.ID, r.Effect)
		}
	}
	return &d, nil
}

// Controls is the authsec.controls.v1 artifact.
type Controls struct {
	Schema     string `json:"schema"`
	Profile    string `json:"profile"`
	Filesystem struct {
		Baseline struct {
			Loaders        map[string]string `json:"loaders"`
			Libraries      []string          `json:"libraries"`
			Certificates   []string          `json:"certificates"`
			ReadonlyConfig []string          `json:"readonly_config"`
		} `json:"baseline"`
		Paths []struct {
			RuleID string `json:"rule_id"`
			Path   string `json:"path"`
			Effect string `json:"effect"`
		} `json:"paths"`
	} `json:"filesystem"`
	Egress []struct {
		RuleID     string `json:"rule_id"`
		ResourceID string `json:"resource_id"`
		Address    string `json:"address"`
		Port       int    `json:"port"`
		Protocol   string `json:"protocol"`
		Effect     string `json:"effect"`
	} `json:"egress"`
	Exec []struct {
		RuleID string `json:"rule_id"`
		Effect string `json:"effect"`
	} `json:"exec"`
	Admission []struct {
		RuleID string `json:"rule_id"`
		Effect string `json:"effect"`
	} `json:"admission"`
	Broker []struct {
		RuleID     string `json:"rule_id"`
		ResourceID string `json:"resource_id"`
		Adapter    string `json:"adapter"`
		Effect     string `json:"effect"`
	} `json:"broker"`
}

// ParseControls reads the controls artifact.
func ParseControls(raw []byte) (*Controls, error) {
	var c Controls
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("controls: %v", err)
	}
	if c.Schema != ControlsSchema {
		return nil, fmt.Errorf("controls schema %q is not %s", c.Schema, ControlsSchema)
	}
	return &c, nil
}
