package collector

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is what a collector keeps between runs. The file is 0600: it holds
// the credential and the installation key.
type State struct {
	URL               string    `json:"url"`
	CollectorID       string    `json:"collector_id"`
	WorkspaceID       string    `json:"workspace_id,omitempty"`
	DiscoverySourceID string    `json:"discovery_source_id,omitempty"`
	EstateID          string    `json:"estate_id,omitempty"`
	Credential        string    `json:"credential"`
	CredentialExpires time.Time `json:"credential_expires_at"`
	Scopes            []string  `json:"scopes"`
	// InstallationKey is the Ed25519 seed (base64). The public half was
	// given at enrollment; rotation is signed with it.
	InstallationKey string `json:"installation_key"`
	// Epoch binds this installation's batch stream; Sequence is the last
	// sequence the server accepted. A new epoch needs an administrator.
	Epoch      string      `json:"collector_epoch"`
	Sequence   int64       `json:"sequence"`
	PolicyKeys []PolicyKey `json:"policy_keys,omitempty"`
	// Applied is the manifest hash applied per workload, so a delivery is
	// applied once.
	Applied map[string]AppliedState `json:"applied,omitempty"`
}

// AppliedState is the last delivery applied for one workload.
type AppliedState struct {
	Revision     int64  `json:"revision"`
	ManifestHash string `json:"manifest_hash"`
	AgentID      string `json:"agent_id"`
	Quarantine   bool   `json:"quarantine"`
}

// DefaultStateDir is /var/lib/authsec-local as root, else the user's state
// directory.
func DefaultStateDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/authsec-local"
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "authsec-local")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".local", "state", "authsec-local")
}

func statePath(dir string) string { return filepath.Join(dir, "collector.json") }

// LoadState reads the state, or os.ErrNotExist before enrollment. A file
// others can read is refused.
func LoadState(dir string) (*State, error) {
	p := statePath(dir)
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be a regular file readable by its owner only", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if s.CollectorID == "" || s.Credential == "" || s.InstallationKey == "" {
		return nil, fmt.Errorf("%s is incomplete: enroll again", p)
	}
	return &s, nil
}

// Save writes the state atomically.
func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".collector.json.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, statePath(dir))
}

// Key is the installation key.
func (s *State) Key() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(s.InstallationKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("installation key is damaged: enroll again")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func newKey() (seedB64, pubB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), base64.StdEncoding.EncodeToString(pub), nil
}

// newUUID is a random (version 4) UUID.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func randomToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
