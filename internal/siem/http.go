package siem

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// sourcetype is the Splunk sourcetype of every event.
const sourcetype = "authsec:agentkit"

// hecPath is Splunk's HTTP Event Collector endpoint for JSON events.
const hecPath = "/services/collector/event"

// wire is a record as the webhook and Splunk receive it.
type wire struct {
	events.Record
	Host     string   `json:"host,omitempty"`
	AgentKit string   `json:"agentkit_version,omitempty"`
	Tags     []string `json:"tags"`
}

// hecEvent is one Splunk HEC event.
type hecEvent struct {
	Time       float64 `json:"time"`
	Host       string  `json:"host,omitempty"`
	Source     string  `json:"source"`
	Sourcetype string  `json:"sourcetype"`
	Event      wire    `json:"event"`
}

// httpT posts batches over HTTPS, retrying network errors, 408, 429 and
// 5xx with backoff.
type httpT struct {
	name   string // webhook | splunk
	url    string // no credentials: Open refuses URLs with them
	where  string // host only, for errors
	auth   string // Authorization header value, "" for none
	ctype  string
	encode func([]events.Record) ([]byte, error)
	client *http.Client
}

func newWebhook(u *url.URL, opt Options, token string) *httpT {
	t := newHTTP("webhook", u, opt, token, "Bearer ")
	t.ctype = "application/json"
	t.encode = func(b []events.Record) ([]byte, error) {
		out := make([]wire, len(b))
		for i, r := range b {
			out[i] = toWire(r, opt)
		}
		return json.Marshal(out)
	}
	return t
}

func newSplunk(u *url.URL, opt Options, token string) *httpT {
	if u.Path == "" || u.Path == "/" {
		u.Path = hecPath
	}
	t := newHTTP("splunk", u, opt, token, "Splunk ")
	t.ctype = "application/json"
	t.encode = func(b []events.Record) ([]byte, error) {
		var buf bytes.Buffer
		for _, r := range b {
			w := toWire(r, opt)
			line, err := json.Marshal(hecEvent{Time: float64(w.Time.UnixMilli()) / 1000, Host: opt.Hostname,
				Source: appName, Sourcetype: sourcetype, Event: w})
			if err != nil {
				return nil, err
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		return buf.Bytes(), nil
	}
	return t
}

func newHTTP(name string, u *url.URL, opt Options, token, authScheme string) *httpT {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: opt.InsecureSkipVerify} // #nosec G402 -- only when the operator asks
	// Redirects are not followed: Go keeps the Authorization header on a
	// redirect to the same host, even to plain http, and the records would
	// go somewhere the operator did not name. A 3xx is a failure.
	// Errors name the host only: webhook URLs often hold a secret in the
	// path.
	t := &httpT{name: name, where: u.Host,
		client: &http.Client{Transport: tr, Timeout: reqTimeout, CheckRedirect: noRedirect}}
	nu := *u
	nu.Scheme = "https"
	t.url = nu.String()
	if token != "" {
		t.auth = authScheme + token
	}
	return t
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func toWire(r events.Record, opt Options) wire {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	r.Time = r.Time.UTC().Truncate(time.Millisecond)
	return wire{Record: r, Host: opt.Hostname, AgentKit: opt.Version, Tags: Tags(r)}
}

func (t *httpT) send(ctx context.Context, batch []events.Record) (int, error) {
	body, err := t.encode(batch)
	if err != nil {
		return 0, fmt.Errorf("%s: encode: %v", t.name, err)
	}
	for attempt := 0; ; attempt++ {
		retry, err := t.post(ctx, body)
		if err == nil {
			return len(batch), nil
		}
		if !retry || attempt >= retries {
			return 0, err
		}
		select {
		case <-ctx.Done():
			return 0, err
		case <-time.After(retryWait << attempt):
		}
	}
}

// post sends one request. retry says whether a failure may succeed later.
func (t *httpT) post(ctx context.Context, body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("%s %s: bad request", t.name, t.where)
	}
	req.Header.Set("Content-Type", t.ctype)
	req.Header.Set("User-Agent", appName)
	if t.auth != "" {
		req.Header.Set("Authorization", t.auth)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		// The url.Error repeats the URL; keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return ctx.Err() == nil && !permanent(err), fmt.Errorf("%s %s: %v", t.name, t.where, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	c := resp.StatusCode
	if c >= 200 && c < 300 {
		return false, nil
	}
	retry = c == http.StatusRequestTimeout || c == http.StatusTooManyRequests || c >= 500
	return retry, fmt.Errorf("%s %s: HTTP %d %s", t.name, t.where, c, strings.TrimSpace(http.StatusText(c)))
}

// permanent reports a TLS failure that a retry cannot fix.
func permanent(err error) bool {
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci)
}

func (t *httpT) close() error {
	t.client.CloseIdleConnections()
	return nil
}
