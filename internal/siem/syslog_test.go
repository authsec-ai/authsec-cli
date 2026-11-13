package siem

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// set changes a package variable for one test.
func set[T any](t *testing.T, p *T, v T) {
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

func sample(n int) []events.Record {
	out := make([]events.Record, n)
	for i := range out {
		out[i] = events.Record{Time: t0, Type: events.Decision, Kind: "network", Action: "deny", Enforced: true,
			Rule: "r" + strconv.Itoa(i), Agent: &events.Agent{ID: "goose", Name: "goose", PID: 10 + i},
			Dst: &events.Dst{IP: "10.0.0.1", Port: 443}}
	}
	return out
}

var syslogLine = regexp.MustCompile(`^<(\d+)>1 \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z (\S+) authsec-agentkit - (\S+) - (CEF:0\|.*)$`)

// readFrames reads n octet-counted frames (RFC 6587) from c.
func readFrames(t *testing.T, c net.Conn, n int) []string {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	var out []string
	for len(out) < n {
		lenStr, err := br.ReadString(' ')
		if err != nil {
			t.Fatalf("frame %d: %v", len(out), err)
		}
		size, err := strconv.Atoi(strings.TrimSuffix(lenStr, " "))
		if err != nil {
			t.Fatalf("frame length %q", lenStr)
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatal(err)
		}
		out = append(out, string(buf))
	}
	return out
}

func checkSyslog(t *testing.T, msgs []string, host string) {
	t.Helper()
	for i, m := range msgs {
		g := syslogLine.FindStringSubmatch(m)
		if g == nil {
			t.Fatalf("message %d not RFC 5424 + CEF: %q", i, m)
		}
		// facility 4, CEF 7 -> syslog error (3)
		if g[1] != "35" || g[2] != host || g[3] != "decision" {
			t.Errorf("message %d header: pri %s host %s msgid %s", i, g[1], g[2], g[3])
		}
		if !strings.Contains(g[4], "cs1=r"+strconv.Itoa(i)+" ") {
			t.Errorf("message %d out of order or missing rule: %q", i, g[4])
		}
	}
}

func TestSyslogTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got <- readFrames(t, c, 3)
	}()
	s, err := Open("syslog+tcp://"+ln.Addr().String(), Options{Version: "1.0", Hostname: "box-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sample(3) {
		s.Send(r)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	checkSyslog(t, <-got, "box-1")
	if st := s.Stats(); st.Sent != 3 || st.Failed != 0 || st.Dropped != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s, err := Open("syslog+udp://"+pc.LocalAddr().String(), Options{Version: "1.0", Hostname: "box-1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sample(3) {
		s.Send(r)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var msgs []string
	buf := make([]byte, 65536)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(msgs) < 3 {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, string(buf[:n])) // one message per datagram, no length prefix
	}
	checkSyslog(t, msgs, "box-1")
}

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "siem.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{testCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestSyslogTLS(t *testing.T) {
	ln := tlsListener(t)
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		got <- readFrames(t, c, 2)
	}()
	s, err := Open("syslog+tls://"+ln.Addr().String(), Options{Version: "1.0", Hostname: "box-1", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range sample(2) {
		s.Send(r)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	checkSyslog(t, <-got, "box-1")
}

func TestSyslogTLSVerifiesByDefault(t *testing.T) {
	ln := tlsListener(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	s, err := Open("syslog+tls://"+ln.Addr().String(), Options{Hostname: "box-1"})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(sample(1)[0])
	if err := s.Close(); err == nil {
		t.Fatal("an unknown certificate was accepted")
	}
	st := s.Stats()
	if st.Failed != 1 || st.Sent != 0 || !strings.Contains(st.LastError, "certificate") {
		t.Fatalf("stats %+v", st)
	}
}

func TestSyslogReconnects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	set(t, &batchWait, 20*time.Millisecond)
	got := make(chan []string, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			got <- readFrames(t, c, 1)
			c.Close() // the server drops every connection after one message
		}
	}()
	s, err := Open("syslog+tcp://"+ln.Addr().String(), Options{Hostname: "box-1"})
	if err != nil {
		t.Fatal(err)
	}
	s.Send(sample(1)[0])
	<-got
	time.Sleep(100 * time.Millisecond) // let the close reach the client
	s.Send(sample(1)[0])
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("second message not delivered after the server closed the connection")
	}
}

func TestFormatSyslog(t *testing.T) {
	r := events.Record{Time: t0, Type: events.Detection, Rule: "artex_present", Severity: "high"}
	m := formatSyslog(r, "1.0", "bad host\nname")
	want := "<34>1 2026-11-13T10:00:00.123Z badhostname authsec-agentkit - detection - CEF:0|AuthSec|Agent Kit|1.0|detection:artex_present|"
	if !strings.HasPrefix(m, want) {
		t.Fatalf("got %q", m)
	}
	if m2 := formatSyslog(events.Record{Time: t0, Type: events.Sensor}, "1", ""); !strings.HasPrefix(m2, "<38>1 2026-11-13T10:00:00.123Z - ") {
		t.Fatalf("got %q", m2)
	}
}
