// Package siem forwards event records to a SIEM: syslog (RFC 5424 with a
// CEF payload) over UDP, TCP or TLS, a JSON webhook, or Splunk HEC.
//
// Send never blocks: records go to a bounded queue that one goroutine
// empties in batches, and a full queue drops the record and counts it. The
// token is read from the environment variable Options.TokenEnv names, and
// it never appears in errors, Stats or logs.
package siem

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// Options configure a sink.
type Options struct {
	Version, Hostname  string
	TokenEnv           string   // name of the env var holding a token; never logged
	Types              []string // record types to send; default decision, detection, agent_started, agent_stopped, sensor
	QueueSize          int      // default 1000
	InsecureSkipVerify bool
	CloseTimeout       time.Duration // how long Close waits for delivery; default 5s
}

// Sink forwards records to one SIEM destination.
type Sink interface {
	Send(events.Record) // non-blocking; drops when the queue is full
	Close() error       // flush with a 5s deadline
	Stats() Stats
}

// Stats count records. LastError never holds the token.
type Stats struct {
	Sent, Dropped, Failed uint64
	LastError             string
}

// defaultTypes are the record types sent when Options.Types is empty.
var defaultTypes = []string{events.Decision, events.Detection, events.AgentStarted, events.AgentStopped, events.Sensor}

// Batching and timing. Variables so tests can shorten them.
var (
	batchMax   = 100
	batchWait  = 2 * time.Second
	closeWait  = 5 * time.Second
	retryWait  = 500 * time.Millisecond
	retries    = 3
	dialWait   = 5 * time.Second
	reqTimeout = 10 * time.Second
)

const defaultQueue = 1000

// transport delivers one batch. It returns how many records were delivered
// (in order) and the error that stopped it.
type transport interface {
	send(ctx context.Context, batch []events.Record) (int, error)
	close() error
}

// Open parses spec and returns a sink for it. Forms:
//
//	syslog+udp://host:514   syslog+tcp://host:601   syslog+tls://host:6514
//	webhook+https://host/path   splunk+https://host:8088
//
// Nothing is sent or dialled until the first batch.
func Open(spec string, opt Options) (Sink, error) {
	spec = strings.TrimSpace(spec)
	u, err := url.Parse(spec)
	if err != nil || u.Scheme == "" || !strings.Contains(spec, "://") {
		// The spec may hold a secret, so it is not echoed.
		return nil, errors.New("siem: destination is not a URL (want syslog+udp://, syslog+tcp://, syslog+tls://, webhook+https:// or splunk+https://)")
	}
	if !knownSchemes[u.Scheme] {
		return nil, fmt.Errorf("siem: unknown destination scheme %q (want syslog+udp, syslog+tcp, syslog+tls, webhook+https or splunk+https)", u.Scheme)
	}
	if u.User != nil {
		return nil, errors.New("siem: credentials in the destination URL are not allowed; name an environment variable with the token instead")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("siem: %s destination has no host", u.Scheme)
	}
	opt = withDefaults(opt)
	token := ""
	if opt.TokenEnv != "" {
		token = os.Getenv(opt.TokenEnv)
		if token == "" {
			return nil, fmt.Errorf("siem: environment variable %s is empty or not set", opt.TokenEnv)
		}
	}
	t, err := newTransport(u, opt, token)
	if err != nil {
		return nil, err
	}
	return start(t, opt, token), nil
}

var knownSchemes = map[string]bool{"syslog+udp": true, "syslog+tcp": true, "syslog+tls": true,
	"webhook+https": true, "splunk+https": true}

func withDefaults(opt Options) Options {
	if len(opt.Types) == 0 {
		opt.Types = defaultTypes
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = defaultQueue
	}
	if opt.Hostname == "" {
		opt.Hostname, _ = os.Hostname()
	}
	if opt.Version == "" {
		opt.Version = "dev"
	}
	return opt
}

func newTransport(u *url.URL, opt Options, token string) (transport, error) {
	switch u.Scheme {
	case "syslog+udp", "syslog+tcp", "syslog+tls":
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return nil, fmt.Errorf("siem: %s destination takes host:port only", u.Scheme)
		}
		return newSyslog(strings.TrimPrefix(u.Scheme, "syslog+"), u, opt), nil
	case "webhook+https":
		return newWebhook(u, opt, token), nil
	case "splunk+https":
		if token == "" {
			return nil, errors.New("siem: splunk needs a HEC token: name its environment variable")
		}
		return newSplunk(u, opt, token), nil
	}
	return nil, fmt.Errorf("siem: unknown destination scheme %q (want syslog+udp, syslog+tcp, syslog+tls, webhook+https or splunk+https)", u.Scheme)
}

// sink is the queue and the goroutine that empties it.
type sink struct {
	closeTimeout time.Duration
	t            transport
	types        map[string]bool
	token        string
	q            chan events.Record
	stop         chan struct{}
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	closed       atomic.Bool

	sent, dropped, failed atomic.Uint64
	mu                    sync.Mutex
	lastErr               string

	closeOnce sync.Once
	closeErr  error
}

func start(t transport, opt Options, token string) *sink {
	s := &sink{closeTimeout: opt.CloseTimeout, t: t, token: token, types: map[string]bool{},
		q: make(chan events.Record, opt.QueueSize), stop: make(chan struct{}), done: make(chan struct{})}
	for _, ty := range opt.Types {
		s.types[ty] = true
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	go s.run()
	return s
}

// Send queues r if its type is sent. It never blocks.
func (s *sink) Send(r events.Record) {
	if !s.types[r.Type] {
		return
	}
	if s.closed.Load() {
		s.dropped.Add(1)
		return
	}
	select {
	case s.q <- r:
	default:
		s.dropped.Add(1)
	}
}

// Stats returns the counters.
func (s *sink) Stats() Stats {
	s.mu.Lock()
	le := s.lastErr
	s.mu.Unlock()
	return Stats{Sent: s.sent.Load(), Dropped: s.dropped.Load(), Failed: s.failed.Load(), LastError: le}
}

// Close sends what is queued, waiting at most 5s, then closes the
// connection. Later calls return the first call's result.
func (s *sink) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		before := s.failed.Load()
		close(s.stop)
		wait := closeWait
		if s.closeTimeout > 0 {
			wait = s.closeTimeout
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-s.done:
		case <-timer.C:
			s.cancel()
			<-s.done
			s.closeErr = fmt.Errorf("siem: records not delivered within %s", wait)
		}
		s.cancel()
		_ = s.t.close()
		if s.closeErr == nil && s.failed.Load() > before {
			s.closeErr = fmt.Errorf("siem: %d records failed: %s", s.failed.Load()-before, s.Stats().LastError)
		}
	})
	return s.closeErr
}

func (s *sink) run() {
	defer close(s.done)
	var batch []events.Record
	var due <-chan time.Time
	for {
		select {
		case r := <-s.q:
			if len(batch) == 0 {
				due = time.After(batchWait)
			}
			batch = append(batch, r)
			if len(batch) >= batchMax {
				s.flush(batch)
				batch, due = nil, nil
			}
		case <-due:
			s.flush(batch)
			batch, due = nil, nil
		case <-s.stop:
			s.drain(batch)
			return
		}
	}
}

// drain sends the batch and everything still queued.
func (s *sink) drain(batch []events.Record) {
	for {
		select {
		case r := <-s.q:
			batch = append(batch, r)
			if len(batch) >= batchMax {
				s.flush(batch)
				batch = nil
			}
		default:
			s.flush(batch)
			return
		}
	}
}

func (s *sink) flush(batch []events.Record) {
	if len(batch) == 0 {
		return
	}
	if err := s.ctx.Err(); err != nil {
		s.fail(len(batch), errors.New("siem: closed before the records were sent"))
		return
	}
	n, err := s.t.send(s.ctx, batch)
	s.sent.Add(uint64(n))
	if err != nil {
		s.fail(len(batch)-n, err)
	}
}

func (s *sink) fail(n int, err error) {
	s.failed.Add(uint64(n))
	s.mu.Lock()
	s.lastErr = redact(err.Error(), s.token)
	s.mu.Unlock()
}

// redact removes the token from s, in case a library echoed it.
func redact(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "[redacted]")
}

// hostPort adds the default port when the URL has none.
func hostPort(u *url.URL, port string) string {
	if p := u.Port(); p != "" {
		port = p
	}
	return net.JoinHostPort(u.Hostname(), port)
}
