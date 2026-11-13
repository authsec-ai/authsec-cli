// Package collector makes authsec-cli a TRD 2 Linux host collector
// (authsec-local): it enrolls with a one-time token, sends what runs on the
// machine through /api/iga/v2/agent-sync, and applies the signed runtime
// policy the control plane publishes for it, reporting what it applied.
//
// The wire types mirror the server's pkg/collectorcontract (package 2.2.0,
// schema 2.0). The server rejects unknown fields, secret-like key names
// anywhere in a batch, and client-chosen canonical ids, so only the fields
// below are ever sent.
package collector

import "encoding/json"

// Contract versions this collector speaks.
const (
	SchemaVersion   = "2.0"
	PackageVersion  = "2.2.0"
	PolicyFormat    = "authsec.runtime.v1"
	ControlsSchema  = "authsec.controls.v1"
	Kind            = "linux_collector"
	maxBatchBytes   = 2 << 20 // the server's decompressed cap
	maxObservations = 1000
)

// SyncRequest is one agent-sync batch.
type SyncRequest struct {
	SchemaVersion    string           `json:"schema_version"`
	BatchID          string           `json:"batch_id"`
	CollectorEpoch   string           `json:"collector_epoch"`
	Sequence         int64            `json:"sequence"`
	SentAt           string           `json:"sent_at"`
	Capabilities     json.RawMessage  `json:"capabilities,omitempty"`
	CapabilityDigest string           `json:"capability_digest,omitempty"`
	Objects          []Object         `json:"objects"`
	Observations     []Observation    `json:"observations"`
	Applied          []AppliedReceipt `json:"applied"`
	Health           Health           `json:"health"`
}

// Object is a native object with a batch-local ref (o_<token>).
type Object struct {
	Ref        string         `json:"ref"`
	Kind       string         `json:"kind"`
	Native     map[string]any `json:"native"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Observation is one fact about an object.
type Observation struct {
	EventID     string         `json:"event_id"`
	Kind        string         `json:"kind"`
	SubjectRef  string         `json:"subject_ref,omitempty"`
	ResourceRef string         `json:"resource_ref,omitempty"`
	Runtime     map[string]any `json:"runtime,omitempty"`
	ObservedAt  string         `json:"observed_at"`
	Outcome     string         `json:"outcome"`
	Source      string         `json:"source,omitempty"`
}

// AppliedReceipt says what the collector did with one delivery.
type AppliedReceipt struct {
	WorkloadID        string           `json:"workload_id"`
	DeliveryRevision  int64            `json:"delivery_revision"`
	RuntimeGeneration string           `json:"runtime_generation"`
	State             string           `json:"state"`
	Controls          []ControlReceipt `json:"controls"`
	ObservedAt        string           `json:"observed_at"`
}

// ControlReceipt is one control inside a receipt.
type ControlReceipt struct {
	Kind           string `json:"kind"`
	State          string `json:"state"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Test           string `json:"test"`
}

// Health is liveness, not authorization.
type Health struct {
	EventsLost     int64 `json:"events_lost"`
	QueueDepth     int64 `json:"queue_depth"`
	SourceFailures int64 `json:"source_failures,omitempty"`
}

// SyncResponse is the server's receipt for a batch.
type SyncResponse struct {
	ReceiptID        string          `json:"receipt_id"`
	AcceptedSequence int64           `json:"accepted_sequence"`
	ReceiptState     string          `json:"receipt_state"`
	ProjectionState  string          `json:"projection_state"`
	Desired          json.RawMessage `json:"desired"`
	NextSyncSeconds  int             `json:"next_sync_seconds"`
}

// Desired is one delivery for one workload. The server sends either one
// object (the schema) or {"bindings":[...]}, one per target workload.
type Desired struct {
	WorkloadID     string   `json:"workload_id"`
	Revision       int64    `json:"revision"`
	GraphRevision  int64    `json:"graph_revision"`
	ManifestID     string   `json:"manifest_id"`
	PolicyFormat   string   `json:"policy_format"`
	OPABundle      Artifact `json:"opa_bundle"`
	Controls       Artifact `json:"controls"`
	SignedManifest string   `json:"signed_manifest"`
	Mode           string   `json:"mode"`
	Revoked        bool     `json:"revoked"`
	Quarantine     bool     `json:"quarantine"`
	// Workload is the target's native identity (exe, argv, unit, path,
	// container_id), when the server sends it; it says which local process
	// the delivery is for.
	Workload map[string]any `json:"workload,omitempty"`
}

// Artifact is a policy file to fetch (or its inline body).
type Artifact struct {
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	RegoVersion string `json:"rego_version,omitempty"`
	Body        string `json:"body,omitempty"`
}

// ParseDesired reads either desired shape. null gives none.
func ParseDesired(raw json.RawMessage) ([]Desired, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var multi struct {
		Bindings []Desired `json:"bindings"`
	}
	if err := json.Unmarshal(raw, &multi); err == nil && multi.Bindings != nil {
		return multi.Bindings, nil
	}
	var one Desired
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, err
	}
	return []Desired{one}, nil
}

// PolicyKey is a policy-signing public key the server publishes.
type PolicyKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	Current      bool   `json:"current"`
}
