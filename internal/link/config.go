// Package link connects the daemon to the AuthSec control plane. The machine
// registers as a discovery source (kind vm_sensor), reports its agents as
// sightings, pushes decisions and detections for the console's logs, pulls
// the agent policies saved in the console, and carries out the console's
// quarantine and release. Records carry names, paths and scrubbed command
// lines, never secret values.
package link

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Config is what `authsec-cli connect` saves.
type Config struct {
	// URL is the control plane's API base, e.g. https://api.authsec.ai.
	URL         string `json:"url"`
	WorkspaceID string `json:"workspace_id"`
	// IngestToken is the workspace's discovery ingest token (a secret; the
	// file is 0600).
	IngestToken string `json:"ingest_token"`
	// Name is how the machine is shown in the console (default: host name).
	Name string `json:"name,omitempty"`
}

// Dir is where the connection is kept: /etc/authsec as root, else the
// user's config directory.
func Dir() string {
	if os.Geteuid() == 0 {
		return "/etc/authsec"
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "authsec")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("authsec-%d", os.Getuid()))
}

// Path is the connection file.
func Path() string { return filepath.Join(Dir(), "connect.json") }

// Validate checks a configuration.
func (c *Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("url must be https://host[:port]")
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return errors.New("url must be https (http only for localhost)")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("url must not carry credentials, a query or a fragment")
	}
	if !uuidRe.MatchString(c.WorkspaceID) {
		return errors.New("workspace must be the workspace id (a uuid)")
	}
	if c.IngestToken == "" || strings.ContainsAny(c.IngestToken, " \t\r\n") || len(c.IngestToken) > 512 {
		return errors.New("token must be the ingest token minted in the console (Add > Machine)")
	}
	if len(c.Name) > 200 {
		return errors.New("name must be at most 200 characters")
	}
	return nil
}

func loopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }

// Base is the URL without a trailing slash.
func (c *Config) Base() string { return strings.TrimRight(c.URL, "/") }

// Load reads the connection file. A file others can read or write is
// refused: it holds a credential.
func Load(path string) (*Config, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %o): chmod 600 it", path, st.Mode().Perm())
	}
	if err := ownedByMe(st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// Save writes the connection file (0600) atomically.
func Save(path string, c *Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	mode := os.FileMode(0o700)
	if dir == "/etc/authsec" {
		mode = 0o755
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(path, append(b, '\n'), 0o600)
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
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
	return os.Rename(name, path)
}

// MachineID is a stable id of this machine: /etc/machine-id, else the host
// name.
func MachineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(b)); len(id) >= 16 && !strings.ContainsAny(id, " /") {
				return id
			}
		}
	}
	h, _ := os.Hostname()
	return "host-" + h
}
