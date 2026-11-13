package siem

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// fakeToken is planted in the environment; it must never show up anywhere
// but the Authorization header.
const fakeToken = "tok-PLANTED-s3cr3t-9f8e7d"

const tokenEnv = "AUTHSEC_SIEM_TEST_TOKEN"

// request is what a fake server saw.
type request struct {
	path, auth, ctype string
	body              []byte
}

// recorder is an httptest TLS server that keeps every request and answers
// with the codes in plan, then 200.
type recorder struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []request
	plan []int
}

func newRecorder(t *testing.T, plan ...int) *recorder {
	rec := &recorder{plan: plan}
	rec.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.reqs = append(rec.reqs, request{r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b})
		code := 200
		if len(rec.plan) > 0 {
			code, rec.plan = rec.plan[0], rec.plan[1:]
		}
		rec.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(rec.Close)
	return rec
}

func (r *recorder) requests() []request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]request(nil), r.reqs...)
}

func host(u string) string { return strings.TrimPrefix(u, "https://") }

func noToken(t *testing.T, where string, s string) {
	t.Helper()
	if strings.Contains(s, fakeToken) {
		t.Fatalf("token leaked into %s: %q", where, s)
	}
}

func TestWebhookBatchesAndAuth(t *testing.T) {
	t.Setenv(tokenEnv, fakeToken)
	set(t, &batchWait, time.Hour) // only size and Close flush
	srv := newRecorder(t)
	s, err := Open("webhook+https://"+host(srv.URL)+"/hook/in?x=1", Options{Version: "1.0", Hostname: "box-1",
		TokenEnv: tokenEnv, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sample(250) {
		s.Send(r)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reqs := srv.requests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want 3 (100, 100, 50)", len(reqs))
	}
	total := 0
	for i, rq := range reqs {
		if rq.path != "/hook/in" || rq.auth != "Bearer "+fakeToken || rq.ctype != "application/json" {
			t.Errorf("request %d: path %q auth ok %v type %q", i, rq.path, rq.auth == "Bearer "+fakeToken, rq.ctype)
		}
		noToken(t, "webhook body", string(rq.body))
		var batch []map[string]any
		if err := json.Unmarshal(rq.body, &batch); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if want := []int{100, 100, 50}[i]; len(batch) != want {
			t.Errorf("batch %d has %d records, want %d", i, len(batch), want)
		}
		first := batch[0]
		if first["type"] != "decision" || first["host"] != "box-1" || first["agentkit_version"] != "1.0" {
			t.Errorf("record fields: %v", first)
		}
		if tags, _ := first["tags"].([]any); len(tags) == 0 {
			t.Errorf("no tags: %v", first)
		}
		total += len(batch)
	}
	if st := s.Stats(); st.Sent != 250 || total != 250 || st.Failed != 0 || st.Dropped != 0 {
		t.Fatalf("stats %+v total %d", st, total)
	}
}

func TestWebhookWithoutToken(t *testing.T) {
	srv := newRecorder(t)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(sample(1)[0])
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reqs := srv.requests(); len(reqs) != 1 || reqs[0].auth != "" {
		t.Fatalf("requests %+v", reqs)
	}
}

func TestWebhookBatchTimer(t *testing.T) {
	set(t, &batchWait, 30*time.Millisecond)
	srv := newRecorder(t)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Send(sample(1)[0])
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(srv.requests()) != 1 || s.Stats().Sent != 1 {
		t.Fatalf("the batch was not sent when its time ran out: %+v", s.Stats())
	}
}

func TestSplunkHEC(t *testing.T) {
	t.Setenv(tokenEnv, fakeToken)
	srv := newRecorder(t)
	s, err := Open("splunk+https://"+host(srv.URL), Options{Version: "2.0", Hostname: "box-2",
		TokenEnv: tokenEnv, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sample(3) {
		s.Send(r)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want one batch", len(reqs))
	}
	rq := reqs[0]
	if rq.path != "/services/collector/event" || rq.auth != "Splunk "+fakeToken {
		t.Fatalf("path %q, auth ok %v", rq.path, rq.auth == "Splunk "+fakeToken)
	}
	noToken(t, "splunk body", string(rq.body))
	sc := bufio.NewScanner(bytes.NewReader(rq.body))
	n := 0
	for sc.Scan() {
		var ev struct {
			Time       float64        `json:"time"`
			Host       string         `json:"host"`
			Sourcetype string         `json:"sourcetype"`
			Event      map[string]any `json:"event"`
		}
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d: %v", n, err)
		}
		if ev.Sourcetype != "authsec:agentkit" || ev.Host != "box-2" || ev.Event["type"] != "decision" ||
			ev.Time != float64(t0.UnixMilli())/1000 {
			t.Errorf("line %d: %+v", n, ev)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("%d events, want one per line", n)
	}
}

func TestRetryOn500(t *testing.T) {
	set(t, &retryWait, time.Millisecond)
	srv := newRecorder(t, 500, 503)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(sample(1)[0])
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.requests()); n != 3 {
		t.Fatalf("%d requests, want 3", n)
	}
	if st := s.Stats(); st.Sent != 1 || st.Failed != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestRetryGivesUp(t *testing.T) {
	t.Setenv(tokenEnv, fakeToken)
	set(t, &retryWait, time.Millisecond)
	srv := newRecorder(t, 500, 500, 500, 500, 500, 500)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{TokenEnv: tokenEnv, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sample(2) {
		s.Send(r)
	}
	cerr := s.Close()
	if cerr == nil {
		t.Fatal("Close reported no failure")
	}
	noToken(t, "Close error", cerr.Error())
	if n := len(srv.requests()); n != 4 {
		t.Fatalf("%d requests, want 1 + 3 retries", n)
	}
	st := s.Stats()
	if st.Failed != 2 || st.Sent != 0 || !strings.Contains(st.LastError, "HTTP 500") {
		t.Fatalf("stats %+v", st)
	}
	noToken(t, "Stats", st.LastError)
}

func TestNoRetryOnClientError(t *testing.T) {
	set(t, &retryWait, time.Millisecond)
	srv := newRecorder(t, 401)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(sample(1)[0])
	_ = s.Close()
	if n := len(srv.requests()); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
	if st := s.Stats(); st.Failed != 1 || !strings.Contains(st.LastError, "HTTP 401") {
		t.Fatalf("stats %+v", st)
	}
}

func TestHTTPSVerifiesByDefault(t *testing.T) {
	srv := newRecorder(t)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(sample(1)[0])
	if s.Close() == nil || len(srv.requests()) != 0 {
		t.Fatal("an unknown certificate was accepted")
	}
}

func TestTypesFilter(t *testing.T) {
	srv := newRecorder(t)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(events.Record{Type: events.Process, Comm: "ls"})
	s.Send(events.Record{Type: events.Network})
	s.Send(events.Record{Type: events.Detection, Rule: "artex_present"})
	_ = s.Close()
	if st := s.Stats(); st.Sent != 1 || st.Dropped != 0 {
		t.Fatalf("default types: %+v", st)
	}

	s, err = Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true, Types: []string{events.Process}})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(events.Record{Type: events.Process, Comm: "ls"})
	s.Send(events.Record{Type: events.Detection})
	_ = s.Close()
	if st := s.Stats(); st.Sent != 1 {
		t.Fatalf("custom types: %+v", st)
	}
}
