package collector

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// EnrollmentTokenPrefix starts a one-time enrollment token.
const EnrollmentTokenPrefix = "authsec_enr_"

// ReadToken reads a token file (first line, trimmed).
func ReadToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	if !strings.HasPrefix(t, EnrollmentTokenPrefix) {
		return "", fmt.Errorf("%s does not hold an enrollment token (%s...)", path, EnrollmentTokenPrefix)
	}
	return t, nil
}

// Enroll exchanges a one-time token for a collector identity and saves the
// state. A lost answer is fetched again with the same key and nonce (the
// server keeps it for an hour), so a retry never mints a second collector.
func Enroll(ctx context.Context, apiURL, token, stateDir, version string) (*State, error) {
	c, err := NewClient(apiURL, version)
	if err != nil {
		return nil, err
	}
	seed, pub, err := newKey()
	if err != nil {
		return nil, err
	}
	nonce := randomToken()
	host, _ := os.Hostname()
	hints := map[string]any{"hostname": host, "os": runtime.GOOS, "arch": runtime.GOARCH, "agent": "authsec-cli " + version}
	if k := kernelRelease(); k != "" {
		hints["kernel"] = k
	}
	var res *EnrollResult
	for attempt := 0; ; attempt++ {
		res, err = c.Enroll(ctx, token, pub, nonce, version, hints)
		if err == nil || StatusOf(err) != 0 || attempt == 3 {
			break
		}
		select { // network error: the same key and nonce again
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 2 * time.Second):
		}
	}
	if err != nil {
		switch StatusOf(err) {
		case 401, 403, 404:
			return nil, fmt.Errorf("the enrollment token was refused (used, expired after 15 minutes, or for another kind): %w", err)
		case 409:
			return nil, fmt.Errorf("the enrollment token was already used by another installation: %w", err)
		}
		return nil, err
	}
	st := &State{
		URL: c.base, CollectorID: res.CollectorID, DiscoverySourceID: res.DiscoverySourceID, EstateID: res.EstateID,
		Credential: res.Credential, CredentialExpires: res.CredentialExpiresAt, Scopes: res.Scopes,
		InstallationKey: seed, Epoch: newUUID(), PolicyKeys: res.PolicyKeys,
	}
	if err := st.Save(stateDir); err != nil {
		return nil, err
	}
	return st, nil
}

// rotate replaces the credential before it expires (24 hours), signed with
// the installation key, so a long-running collector is never locked out.
func (s *State) rotate(ctx context.Context, c *Client) error {
	key, err := s.Key()
	if err != nil {
		return err
	}
	nonce := randomToken()
	at := time.Now().UTC().Format(time.RFC3339)
	// The scopes are not changed: the signed scope field is empty.
	msg := strings.Join([]string{"authsec.collector.rotate.v1", s.CollectorID, nonce, at, "", ""}, "\n")
	sig := ed25519.Sign(key, []byte(msg))
	res, err := c.Rotate(ctx, s.Credential, map[string]any{
		"nonce":        nonce,
		"requested_at": at,
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return err
	}
	s.Credential, s.CredentialExpires = res.Credential, res.ExpiresAt
	if len(res.Scopes) > 0 {
		s.Scopes = res.Scopes
	}
	if len(res.PolicyKeys) > 0 {
		s.PolicyKeys = res.PolicyKeys
	}
	return nil
}

// needsRotation is true within the last quarter of the credential's life
// (six hours of 24), or when the expiry is unknown.
func (s *State) needsRotation(now time.Time) bool {
	if s.CredentialExpires.IsZero() {
		return true
	}
	return now.After(s.CredentialExpires.Add(-6 * time.Hour))
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

var errCredentialExpired = errors.New("the collector credential expired: enroll again with a new token")
