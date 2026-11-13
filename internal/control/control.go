// Package control is the daemon's local control socket: one JSON request
// per connection, one JSON response. The daemon checks the caller with
// SO_PEERCRED: quarantine, release and reload need uid 0; a process may ask
// to have itself enforced; anyone may report a decision (the Claude Code
// hook runs as the user).
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// Ops.
const (
	OpStatus     = "status"
	OpReload     = "reload"
	OpQuarantine = "quarantine"
	OpRelease    = "release"
	OpEnforcePID = "enforce_pid" // a process asks to be enforced (run --enforce)
	OpReport     = "report"      // a decision made elsewhere (the Claude Code hook)
)

// Request is one call.
type Request struct {
	Op     string         `json:"op"`
	Agent  string         `json:"agent,omitempty"`
	PID    int            `json:"pid,omitempty"`
	Record *events.Record `json:"record,omitempty"`
}

// Response is the answer.
type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Peer is who is calling.
type Peer struct {
	UID, PID int
	Known    bool // false where SO_PEERCRED is unavailable
}

// Privileged reports whether the peer is root.
func (p Peer) Privileged() bool { return p.Known && p.UID == 0 }

// SocketPath is where the daemon listens: /run/authsec when running as root
// (or when that socket exists), else the user's runtime directory.
func SocketPath() string {
	sys := "/run/authsec/control.sock"
	if os.Geteuid() == 0 {
		return sys
	}
	if _, err := os.Stat(sys); err == nil {
		return sys
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "authsec", "control.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("authsec-%d", os.Getuid()), "control.sock")
}

// privateDir checks (creating it if needed) that a user socket directory is
// a real directory owned by this user and closed to others: in /tmp anyone
// could otherwise plant it first.
func privateDir(dir string) error {
	if dir == "/run/authsec" {
		return os.MkdirAll(dir, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is open to other users (mode %v)", dir, st.Mode().Perm())
	}
	if !ownedBySelf(st) {
		return fmt.Errorf("%s belongs to another user", dir)
	}
	return nil
}

// Limits on clients.
const (
	maxConns    = 32
	maxRequest  = 64 << 10
	readTimeout = 2 * time.Second
)

// Serve accepts calls until ctx is done. handle runs for each call; it must
// be quick (the daemon passes it to its own loop).
func Serve(ctx context.Context, path string, handle func(Request, Peer) Response) error {
	if err := privateDir(filepath.Dir(path)); err != nil {
		return err
	}
	// Remove a socket only if nothing answers on it (a crash left it); a
	// live one belongs to another daemon.
	if c, err := net.DialTimeout("unix", path, 500*time.Millisecond); err == nil {
		c.Close()
		return fmt.Errorf("another daemon is listening on %s", path)
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	var self os.FileInfo
	self, _ = os.Stat(path)
	// Anyone may connect; what they may do is decided per op from SO_PEERCRED.
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
		// Unlink only our own socket (another daemon may have replaced it).
		if st, err := os.Stat(path); err == nil && self != nil && os.SameFile(st, self) {
			os.Remove(path)
		}
	}()
	slots := make(chan struct{}, maxConns)
	backoff := 10 * time.Millisecond
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 10 * time.Millisecond
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				serveConn(c.(*net.UnixConn), handle)
			}()
		default:
			c.Close() // too many clients at once
		}
	}
}

func serveConn(c *net.UnixConn, handle func(Request, Peer) Response) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(readTimeout))
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	peer := peerOf(c)
	var req Request
	r := bufio.NewReader(&limited{c, maxRequest})
	line, err := r.ReadBytes('\n')
	var resp Response
	if err != nil && len(line) == 0 {
		return
	}
	if err := json.Unmarshal(line, &req); err != nil {
		resp = Response{Error: "bad request"}
	} else {
		resp = handle(req, peer)
	}
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

type limited struct {
	c *net.UnixConn
	n int
}

func (l *limited) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("request too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.c.Read(p)
	l.n -= n
	return n, err
}

// Call sends one request to the daemon.
func Call(path string, req Request, timeout time.Duration) (Response, error) {
	if dir := filepath.Dir(path); dir != "/run/authsec" {
		if err := privateDir(dir); err != nil {
			return Response{}, fmt.Errorf("the daemon is not running (%s): %w", path, err)
		}
	}
	c, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return Response{}, fmt.Errorf("the daemon is not running (%s): %w", path, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return Response{}, err
	}
	if !resp.OK && resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// OK builds a success response carrying data.
func OK(data any) Response {
	if data == nil {
		return Response{OK: true}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, Data: b}
}

// Fail builds an error response.
func Fail(format string, a ...any) Response { return Response{Error: fmt.Sprintf(format, a...)} }
