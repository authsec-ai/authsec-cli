package siem

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// A webhook that redirects must not lead the sink to send the token (or
// the records) anywhere else, least of all over plain HTTP.
func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	t.Setenv(tokenEnv, fakeToken)
	set(t, &retryWait, time.Millisecond)
	var mu sync.Mutex
	var leaked []string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = append(leaked, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer plain.Close()
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	for _, spec := range []string{"webhook+https://" + host(redir.URL) + "/hook", "splunk+https://" + host(redir.URL)} {
		s, err := Open(spec, Options{TokenEnv: tokenEnv, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		s.Send(sample(1)[0])
		err = s.Close()
		mu.Lock()
		n := len(leaked)
		mu.Unlock()
		if n != 0 {
			mu.Lock()
			withToken := leaked[0] != ""
			mu.Unlock()
			t.Fatalf("%s: followed a redirect to plain HTTP (%d requests, Authorization sent: %v)", spec, n, withToken)
		}
		st := s.Stats()
		if err == nil || st.Failed != 1 || !strings.Contains(st.LastError, "HTTP 307") {
			t.Fatalf("%s: err %v stats %+v", spec, err, st)
		}
		noToken(t, "Close", err.Error())
	}
}

// Webhook URLs often carry their secret in the path (Slack, Teams,
// Discord): errors name the host only.
func TestErrorsOmitURLPath(t *testing.T) {
	set(t, &retryWait, time.Millisecond)
	srv := newRecorder(t, 403)
	s, err := Open("webhook+https://"+host(srv.URL)+"/services/T0/B0/"+fakeToken, Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(sample(1)[0])
	err = s.Close()
	if err == nil {
		t.Fatal("no error for 403")
	}
	noToken(t, "Close", err.Error())
	noToken(t, "Stats", s.Stats().LastError)
}

// Cancelling while a message is written must not touch the connection
// after write has closed and cleared it (run with -race).
func TestSyslogCancelDuringWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	u, _ := url.Parse("syslog+tcp://" + ln.Addr().String())
	st := newSyslog("tcp", u, Options{Hostname: "h", Version: "1"})
	for i := 0; i < 300; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		if err := st.connect(ctx); err != nil {
			t.Fatal(err)
		}
		go cancel()
		_ = st.writeConn(ctx, []byte("5 hello"))
		st.close()
		cancel()
	}
}

// Send may race Close from many goroutines without a panic or a data race,
// and no record is counted twice.
func TestSendDuringClose(t *testing.T) {
	srv := newRecorder(t)
	s, err := Open("webhook+https://"+host(srv.URL)+"/", Options{InsecureSkipVerify: true, QueueSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	const each, workers = 200, 8
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, r := range sample(each) {
				s.Send(r)
			}
		}()
	}
	_ = s.Close()
	wg.Wait()
	st := s.Stats()
	if got := st.Sent + st.Dropped + st.Failed; got > each*workers || st.Dropped == 0 && st.Sent == 0 {
		t.Fatalf("stats %+v", st)
	}
}
