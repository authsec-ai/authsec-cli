package siem

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// Syslog facility 4 (security/authorization messages, RFC 5424 6.2.1).
const facility = 4

const appName = "authsec-agentkit"

// syslogT sends RFC 5424 messages with a CEF payload. UDP sends one
// message per datagram; TCP and TLS use octet-counting framing (RFC 6587
// 3.4.1).
type syslogT struct {
	network string // udp | tcp | tls
	addr    string
	server  string
	opt     Options
	conn    net.Conn
	gone    *atomic.Bool // the peer closed conn (TCP and TLS)
}

func newSyslog(network string, u *url.URL, opt Options) *syslogT {
	port := map[string]string{"udp": "514", "tcp": "601", "tls": "6514"}[network]
	return &syslogT{network: network, addr: hostPort(u, port), server: u.Hostname(), opt: opt}
}

func (t *syslogT) send(ctx context.Context, batch []events.Record) (int, error) {
	for i, r := range batch {
		msg := formatSyslog(r, t.opt.Version, t.opt.Hostname)
		if t.network != "udp" {
			msg = strconv.Itoa(len(msg)) + " " + msg
		}
		if err := t.write(ctx, []byte(msg)); err != nil {
			return i, fmt.Errorf("syslog %s %s: %v", t.network, t.addr, err)
		}
	}
	return len(batch), nil
}

// write sends one message, reconnecting once if the connection broke.
func (t *syslogT) write(ctx context.Context, b []byte) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if t.conn != nil && t.gone.Load() {
			t.close()
		}
		if t.conn == nil {
			if err = t.connect(ctx); err != nil {
				return err
			}
		}
		if err = t.writeConn(ctx, b); err == nil {
			return nil
		}
		t.close()
		if ctx.Err() != nil {
			return err
		}
	}
	return err
}

func (t *syslogT) writeConn(ctx context.Context, b []byte) error {
	// The callback may run after this returns and t.conn is cleared, so it
	// holds its own copy.
	c := t.conn
	stop := context.AfterFunc(ctx, func() { _ = c.SetWriteDeadline(time.Unix(1, 0)) })
	defer stop()
	_ = c.SetWriteDeadline(time.Now().Add(reqTimeout))
	_, err := c.Write(b)
	return err
}

// connect dials and, for a stream, watches for the peer closing it: a
// receiver sends nothing, so any read result means the connection is gone.
// Without this the first message after a close would be lost.
func (t *syslogT) connect(ctx context.Context) error {
	c, err := t.dial(ctx)
	if err != nil {
		return err
	}
	gone := new(atomic.Bool)
	if t.network != "udp" {
		go func() {
			_, _ = io.Copy(io.Discard, c)
			gone.Store(true)
		}()
	}
	t.conn, t.gone = c, gone
	return nil
}

func (t *syslogT) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialWait)
	defer cancel()
	if t.network == "tls" {
		d := tls.Dialer{Config: &tls.Config{ServerName: t.server, MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: t.opt.InsecureSkipVerify}} // #nosec G402 -- only when the operator asks
		return d.DialContext(ctx, "tcp", t.addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, t.network, t.addr)
}

func (t *syslogT) close() error {
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}

// formatSyslog renders r as an RFC 5424 message whose MSG is FormatCEF:
// <PRI>1 TIMESTAMP HOSTNAME authsec-agentkit - TYPE - CEF:0|...
func formatSyslog(r events.Record, version, host string) string {
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	pri := facility*8 + syslogSeverity(severity(r))
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s", pri, t.UTC().Format("2006-01-02T15:04:05.000Z"),
		headerField(host, 255), appName, headerField(r.Type, 32), FormatCEF(r, version, host))
}

// syslogSeverity maps a CEF severity to an RFC 5424 one.
func syslogSeverity(cef int) int {
	switch {
	case cef >= 9:
		return 2 // critical
	case cef >= 7:
		return 3 // error
	case cef >= 4:
		return 4 // warning
	case cef >= 2:
		return 5 // notice
	}
	return 6 // informational
}

// headerField keeps printable ASCII without spaces (RFC 5424 PRINTUSASCII),
// cut to n; an empty field is "-".
func headerField(s string, n int) string {
	s = strings.Map(func(c rune) rune {
		if c < 33 || c > 126 {
			return -1
		}
		return c
	}, s)
	if len(s) > n {
		s = s[:n]
	}
	if s == "" {
		return "-"
	}
	return s
}
