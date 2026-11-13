package collector

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client calls the control plane's /api/iga/v2 collector routes.
type Client struct {
	base string
	ua   string
	http *http.Client
}

// NewClient builds a client. No redirects: a credential never goes to
// another host.
func NewClient(base, version string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return nil, fmt.Errorf("control plane URL %q must be http(s)://host[:port]", base)
	}
	if u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1", "host.docker.internal":
		default:
			// The credential is a bearer token: plain HTTP only to this machine.
			return nil, fmt.Errorf("control plane URL %q must be https (http only for localhost or host.docker.internal)", base)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{base: u.String(), ua: "authsec-local/" + version + " (authsec-cli)", http: &http.Client{
		Transport:     tr,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// HTTPError is a refusal.
type HTTPError struct {
	Status     int
	Msg        string
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Msg)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// StatusOf is err's HTTP status, or 0.
func StatusOf(err error) int {
	var h *HTTPError
	if errors.As(err, &h) {
		return h.Status
	}
	return 0
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body []byte, gz bool, out any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		if gz {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(body)
			_ = zw.Close()
			body = buf.Bytes()
		}
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		if gz {
			req.Header.Set("Content-Encoding", "gzip")
		}
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error  string `json:"error"`
			Fields []struct {
				Path    string `json:"path"`
				Message string `json:"message"`
			} `json:"fields"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		for i, f := range e.Fields {
			if i == 3 {
				msg += "; …"
				break
			}
			msg += fmt.Sprintf("; %s: %s", f.Path, f.Message)
		}
		he := &HTTPError{Status: resp.StatusCode, Msg: msg}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
		return nil, he
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fmt.Errorf("unexpected answer from %s: %v", path, err)
		}
	}
	return raw, nil
}

// EnrollResult is the server's answer to an enrollment.
type EnrollResult struct {
	CollectorID         string      `json:"collector_id"`
	DiscoverySourceID   string      `json:"discovery_source_id"`
	EstateID            string      `json:"estate_id"`
	Credential          string      `json:"credential"`
	CredentialExpiresAt time.Time   `json:"credential_expires_at"`
	Scopes              []string    `json:"scopes"`
	PolicyKeys          []PolicyKey `json:"policy_keys"`
}

// Enroll exchanges a one-time token for a collector credential.
func (c *Client) Enroll(ctx context.Context, token, pubB64, nonce, version string, hints map[string]any) (*EnrollResult, error) {
	body, _ := json.Marshal(map[string]any{
		"installation_public_key": pubB64,
		"installation_nonce":      nonce,
		"kind":                    Kind,
		"version":                 version,
		"native_hints":            hints,
	})
	var out EnrollResult
	if _, err := c.do(ctx, http.MethodPost, "/api/iga/v2/collectors/enroll", token, body, false, &out); err != nil {
		return nil, err
	}
	if out.CollectorID == "" || out.Credential == "" {
		return nil, errors.New("enrollment answered without a collector credential")
	}
	return &out, nil
}

// RotateResult is a replacement credential.
type RotateResult struct {
	Credential string      `json:"credential"`
	ExpiresAt  time.Time   `json:"expires_at"`
	Scopes     []string    `json:"scopes"`
	PolicyKeys []PolicyKey `json:"policy_keys"`
}

// Rotate replaces the credential; the request is signed with the
// installation key (authsec.collector.rotate.v1).
func (c *Client) Rotate(ctx context.Context, credential string, body map[string]any) (*RotateResult, error) {
	raw, _ := json.Marshal(body)
	var out RotateResult
	if _, err := c.do(ctx, http.MethodPost, "/api/iga/v2/collectors/self/credentials/rotate", credential, raw, false, &out); err != nil {
		return nil, err
	}
	if out.Credential == "" {
		return nil, errors.New("rotation answered without a credential")
	}
	return &out, nil
}

// Sync sends one batch (gzip) and returns the receipt.
func (c *Client) Sync(ctx context.Context, credential string, body []byte) (*SyncResponse, error) {
	var out SyncResponse
	if _, err := c.do(ctx, http.MethodPost, "/api/iga/v2/agent-sync?include_policy=inline", credential, body, true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PolicyKeys lists the policy-signing keys.
func (c *Client) PolicyKeys(ctx context.Context, credential string) ([]PolicyKey, error) {
	var out struct {
		Keys []PolicyKey `json:"keys"`
	}
	_, err := c.do(ctx, http.MethodGet, "/api/iga/v2/policy-keys", credential, nil, false, &out)
	return out.Keys, err
}

// Artifact downloads a policy artifact. Only paths under the API are
// followed: the URL comes from the server's answer.
func (c *Client) Artifact(ctx context.Context, credential, path string) ([]byte, error) {
	if !strings.HasPrefix(path, "/api/iga/v2/policy-artifacts/") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("artifact URL %q is not a policy artifact path", path)
	}
	return c.do(ctx, http.MethodGet, path, credential, nil, false, nil)
}
