package link

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls the control plane.
type Client struct {
	cfg     *Config
	http    *http.Client
	agentUA string
}

// NewClient builds a client: TLS 1.2+, no redirects (a credential is never
// sent to another host), short timeouts.
func NewClient(cfg *Config, version string) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.Proxy = http.ProxyFromEnvironment
	return &Client{cfg: cfg, agentUA: "authsec-cli/" + version, http: &http.Client{
		Transport:     tr,
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// HTTPError is a non-2xx answer.
type HTTPError struct {
	Status int
	Msg    string
}

func (e *HTTPError) Error() string {
	if e.Msg != "" {
		return fmt.Sprintf("%d: %s", e.Status, e.Msg)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// StatusOf is the HTTP status of err, or 0.
func StatusOf(err error) int {
	var h *HTTPError
	if errors.As(err, &h) {
		return h.Status
	}
	return 0
}

// call sends body (JSON) and decodes the answer into out. header, when
// given, is set on the request; the answer's headers are returned.
func (c *Client) call(ctx context.Context, method, path string, query url.Values, bearer string,
	body, out any, header http.Header) (int, http.Header, error) {

	u := c.cfg.Base() + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.agentUA)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, resp.Header, err
	}
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, resp.Header, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error
		if len(msg) > 300 {
			msg = msg[:300]
		}
		if msg == "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			msg = "redirected to " + resp.Header.Get("Location") + " (use the API URL itself)"
		}
		return resp.StatusCode, resp.Header, &HTTPError{Status: resp.StatusCode, Msg: strings.ToValidUTF8(msg, "")}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, resp.Header, fmt.Errorf("unexpected answer from %s: %v", path, err)
		}
	}
	return resp.StatusCode, resp.Header, nil
}

// Registration is what the machine announces.
type Registration struct {
	WorkspaceID       string         `json:"workspace_id"`
	Kind              string         `json:"kind"`
	InstanceID        string         `json:"instance_id"`
	DisplayName       string         `json:"display_name,omitempty"`
	ClusterName       string         `json:"cluster_name"`
	AgentVersion      string         `json:"agent_version,omitempty"`
	Status            string         `json:"status,omitempty"`
	Error             string         `json:"error,omitempty"`
	Runtime           map[string]any `json:"runtime,omitempty"`
	ReportedSightings int64          `json:"reported_sightings,omitempty"`
	ActuationToken    string         `json:"actuation_token,omitempty"`
}

// Registered is the answer.
type Registered struct {
	SourceID       string `json:"discovery_source_id"`
	Created        bool   `json:"created"`
	Actuation      string `json:"actuation"` // off | pending | on (only to a verified caller)
	ActuationError string `json:"actuation_error"`
}

// Register announces the machine (and heartbeats).
func (c *Client) Register(ctx context.Context, bearer string, r Registration) (*Registered, error) {
	var out Registered
	_, _, err := c.call(ctx, http.MethodPost, "/authsec/discovery/agent-registration", nil, bearer, r, &out, nil)
	if err != nil {
		return nil, err
	}
	if out.SourceID == "" {
		return nil, errors.New("registration answered without a discovery_source_id")
	}
	return &out, nil
}

// Sighting reports one agent.
type Sighting struct {
	WorkspaceID       string         `json:"workspace_id"`
	Source            string         `json:"source"`
	DiscoverySourceID string         `json:"discovery_source_id"`
	Fingerprint       string         `json:"fingerprint"`
	DisplayName       string         `json:"display_name,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	DeploymentOrigin  string         `json:"deployment_origin,omitempty"`
	ObservedAt        time.Time      `json:"observed_at"`
	RuntimeStatus     string         `json:"runtime_status,omitempty"`
}

// Sight reports one agent.
func (c *Client) Sight(ctx context.Context, bearer string, s Sighting) error {
	_, _, err := c.call(ctx, http.MethodPost, "/authsec/discovery/sightings", nil, bearer, s, nil, nil)
	return err
}

// PushResult is what the control plane did with a batch.
type PushResult struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
	Errors   []struct {
		Index int    `json:"index"`
		Error string `json:"error"`
	} `json:"errors"`
}

// Push sends a batch of records (at most 500).
func (c *Client) Push(ctx context.Context, bearer, sourceID string, recs []json.RawMessage) (*PushResult, error) {
	var out PushResult
	_, _, err := c.call(ctx, http.MethodPost, "/authsec/discovery/agentkit/machine/events", nil, bearer,
		map[string]any{"workspace_id": c.cfg.WorkspaceID, "discovery_source_id": sourceID, "events": recs}, &out, nil)
	return &out, err
}

// ConsolePolicy is one policy saved in the console.
type ConsolePolicy struct {
	AgentID  string `json:"agent_id"`
	Version  int    `json:"version"`
	SHA256   string `json:"sha256"`
	Document string `json:"document"`
}

// Policies pulls the workspace's policies. etag is the previous answer's;
// changed is false when nothing changed since.
func (c *Client) Policies(ctx context.Context, bearer, sourceID, etag string) (pols []ConsolePolicy, newTag string, changed bool, err error) {
	q := url.Values{"workspace_id": {c.cfg.WorkspaceID}, "discovery_source_id": {sourceID}}
	h := http.Header{}
	if etag != "" {
		h.Set("If-None-Match", etag)
	}
	var out struct {
		Policies []ConsolePolicy `json:"policies"`
		ETag     string          `json:"etag"`
	}
	code, hdr, err := c.call(ctx, http.MethodGet, "/authsec/discovery/agentkit/machine/policies", q, bearer, nil, &out, h)
	if err != nil {
		return nil, "", false, err
	}
	if code == http.StatusNotModified {
		return nil, etag, false, nil
	}
	tag := out.ETag
	if tag == "" && hdr != nil {
		tag = hdr.Get("ETag")
	}
	return out.Policies, tag, true, nil
}

// Instruction is one piece of work the console queued for this machine.
type Instruction struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Payload     json.RawMessage `json:"payload"`
	Fingerprint string          `json:"fingerprint"`
}

// Lease takes queued instructions (actuation credential only).
func (c *Client) Lease(ctx context.Context, actuation, holder string) ([]Instruction, error) {
	var out struct {
		Instructions []Instruction `json:"instructions"`
	}
	q := url.Values{"max": {"10"}, "pod": {holder}}
	_, _, err := c.call(ctx, http.MethodGet, "/authsec/provisioning/instructions", q, actuation, nil, &out, nil)
	return out.Instructions, err
}

// Report says how an instruction went.
func (c *Client) Report(ctx context.Context, actuation, id string, ok bool, msg string, result map[string]any) error {
	body := map[string]any{"success": ok, "result": result}
	if msg != "" {
		body["error"] = msg
	}
	_, _, err := c.call(ctx, http.MethodPost, "/authsec/provisioning/instructions/"+url.PathEscape(id)+"/result", nil, actuation, body, nil, nil)
	return err
}
