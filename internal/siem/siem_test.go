package siem

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendNeverBlocks(t *testing.T) {
	t.Setenv(tokenEnv, fakeToken)
	set(t, &batchWait, 5*time.Millisecond)
	set(t, &closeWait, 300*time.Millisecond)
	arrived := make(chan struct{}, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body) // the server notices a client hang-up only after the body
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-r.Context().Done() // hang until the client gives up
	}))
	defer srv.Close()
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{QueueSize: 10, TokenEnv: tokenEnv, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	recs := sample(1001)
	s.Send(recs[0])
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the first batch never reached the server")
	}
	var slowest time.Duration
	for _, r := range recs[1:] {
		start := time.Now()
		s.Send(r)
		if d := time.Since(start); d > slowest {
			slowest = d
		}
	}
	if slowest > 5*time.Millisecond {
		t.Fatalf("Send blocked for %s", slowest)
	}
	if st := s.Stats(); st.Dropped != 990 {
		t.Fatalf("dropped %d, want 990 (queue of 10 full)", st.Dropped)
	}

	start := time.Now()
	cerr := s.Close()
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Close took %s with a hung server", took)
	}
	if cerr == nil {
		t.Fatal("Close reported success with nothing delivered")
	}
	noToken(t, "Close error", cerr.Error())
	st := s.Stats()
	if st.Sent != 0 || st.Failed != 11 || st.Dropped != 990 {
		t.Fatalf("stats %+v", st)
	}
	noToken(t, "Stats", st.LastError)

	s.Send(recs[0]) // after Close: counted, not queued, no panic
	if s.Stats().Dropped != 991 {
		t.Fatalf("send after close: %+v", s.Stats())
	}
	if err := s.Close(); err != cerr {
		t.Fatalf("second Close: %v", err)
	}
}

func TestCloseFlushes(t *testing.T) {
	set(t, &batchWait, time.Hour)
	srv := newRecorder(t)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sample(5) {
		s.Send(r)
	}
	if len(srv.requests()) != 0 {
		t.Fatal("sent before the batch was due")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reqs := srv.requests(); len(reqs) != 1 || s.Stats().Sent != 5 {
		t.Fatalf("Close did not flush: %d requests, %+v", len(reqs), s.Stats())
	}
}

func TestOpenErrors(t *testing.T) {
	t.Setenv(tokenEnv, fakeToken)
	t.Setenv("AUTHSEC_SIEM_EMPTY", "")
	cases := []struct {
		spec string
		opt  Options
		want string
	}{
		{"ftp://siem.example/x", Options{}, `unknown destination scheme "ftp"`},
		{"webhook+http://siem.example/x", Options{}, `unknown destination scheme "webhook+http"`},
		{"siem.example:514", Options{}, "not a URL"},
		{"", Options{}, "not a URL"},
		{"syslog+udp://", Options{}, "no host"},
		{"syslog+tcp://siem.example:601/path", Options{}, "host:port only"},
		{"splunk+https://siem.example:8088", Options{}, "needs a HEC token"},
		{"webhook+https://siem.example/x", Options{TokenEnv: "AUTHSEC_SIEM_EMPTY"}, "AUTHSEC_SIEM_EMPTY is empty"},
		{"webhook+https://user:" + fakeToken + "@siem.example/x", Options{}, "credentials in the destination URL"},
		{"ftp://user:" + fakeToken + "@siem.example/x", Options{}, `unknown destination scheme "ftp"`},
		{"syslog+udp:" + fakeToken, Options{}, "not a URL"},
		{"%%" + fakeToken, Options{}, "not a URL"},
	}
	for _, c := range cases {
		s, err := Open(c.spec, c.opt)
		if err == nil {
			s.Close()
			t.Errorf("%q: no error", c.spec)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.spec, err, c.want)
		}
		noToken(t, "Open error", err.Error())
	}
}

func TestOpenDefaults(t *testing.T) {
	cases := map[string]string{
		"syslog+udp://127.0.0.1":     "127.0.0.1:514",
		"syslog+tcp://127.0.0.1":     "127.0.0.1:601",
		"syslog+tls://[::1]":         "[::1]:6514",
		"syslog+tls://127.0.0.1:999": "127.0.0.1:999",
	}
	for spec, want := range cases {
		s, err := Open(spec, Options{})
		if err != nil {
			t.Fatal(err)
		}
		sk := s.(*sink)
		if got := sk.t.(*syslogT).addr; got != want {
			t.Errorf("%s: addr %s, want %s", spec, got, want)
		}
		if cap(sk.q) != 1000 {
			t.Errorf("queue %d, want 1000", cap(sk.q))
		}
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}
}

func TestRedact(t *testing.T) {
	if got := redact("bad header Bearer "+fakeToken, fakeToken); strings.Contains(got, fakeToken) {
		t.Fatalf("got %q", got)
	}
	if got := redact("plain", ""); got != "plain" {
		t.Fatalf("got %q", got)
	}
}
