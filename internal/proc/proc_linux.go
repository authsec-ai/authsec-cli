//go:build linux

package proc

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func take() (*Snapshot, error) { return readProc("/proc") }

// readProc reads a /proc tree. root is a parameter so tests can use a fake one.
func readProc(root string) (*Snapshot, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Taken: time.Now(), Procs: map[int]*Process{}}
	boot := bootTime(root)
	users := map[int]string{}
	sockets := map[string]int{} // socket inode -> pid

	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		p, partial, ok := readProcess(filepath.Join(root, e.Name()), pid, boot, users, sockets)
		if !ok {
			continue // exited while we read
		}
		if partial {
			s.Partial = true
		}
		s.Procs[pid] = p
	}
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		s.Conns = append(s.Conns, readNetTCP(filepath.Join(root, f), sockets)...)
	}
	return s, nil
}

// readProcess reads one /proc/<pid> directory. sockets, if not nil, collects
// the process's socket inodes. partial is true when the process belongs to
// another user and its exe, environment and fds are hidden.
func readProcess(dir string, pid int, boot time.Time, users map[int]string, sockets map[string]int) (p *Process, partial, ok bool) {
	p, ok = readStat(dir, pid, boot)
	if !ok {
		return nil, false, false
	}
	p.UID = readUID(dir)
	if name, ok := users[p.UID]; ok {
		p.User = name
	} else if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
		p.User, users[p.UID] = u.Username, u.Username
	} else {
		users[p.UID] = ""
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		p.Args = splitNUL(b)
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	} else if !os.IsNotExist(err) && len(p.Args) > 0 {
		partial = true
	}
	if b, err := os.ReadFile(filepath.Join(dir, "environ")); err == nil {
		p.EnvNames = envNames(b)
		clear(b)
	}
	if sockets != nil {
		if fds, err := os.ReadDir(filepath.Join(dir, "fd")); err == nil {
			for _, fd := range fds {
				l, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
				if err == nil && strings.HasPrefix(l, "socket:[") {
					sockets[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = pid
				}
			}
		}
	}
	return p, partial, true
}

var (
	getMu    sync.Mutex
	getUsers = map[int]string{}
	getBoot  time.Time
)

// get reads one process from /proc.
func get(pid int) (*Process, bool) {
	getMu.Lock()
	defer getMu.Unlock()
	if getBoot.IsZero() {
		getBoot = bootTime("/proc")
	}
	p, _, ok := readProcess(filepath.Join("/proc", strconv.Itoa(pid)), pid, getBoot, getUsers, nil)
	return p, ok
}

// readStat parses /proc/<pid>/stat: comm is in parentheses and may contain
// spaces, so fields are counted after the last ')'.
func readStat(dir string, pid int, boot time.Time) (*Process, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return nil, false
	}
	open, close := bytes.IndexByte(b, '('), bytes.LastIndexByte(b, ')')
	if open < 0 || close < open {
		return nil, false
	}
	p := &Process{PID: pid, Comm: string(b[open+1 : close])}
	f := strings.Fields(string(b[close+1:]))
	// f[0] is state (field 3); ppid is field 4, starttime field 22.
	if len(f) > 1 {
		p.PPID, _ = strconv.Atoi(f[1])
	}
	if len(f) > 19 && !boot.IsZero() {
		if ticks, err := strconv.ParseInt(f[19], 10, 64); err == nil {
			p.Started = boot.Add(time.Duration(ticks) * time.Second / 100).UTC().Truncate(time.Second)
		}
	}
	return p, true
}

func readUID(dir string) int {
	f, err := os.Open(filepath.Join(dir, "status"))
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
			if fs := strings.Fields(rest); len(fs) > 0 {
				uid, _ := strconv.Atoi(fs[0])
				return uid
			}
		}
	}
	return -1
}

func bootTime(root string) time.Time {
	b, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
				return time.Unix(sec, 0)
			}
		}
	}
	return time.Time{}
}

func splitNUL(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = string(p)
	}
	return out
}

// TCP states in /proc/net/tcp.
const (
	tcpEstablished = "01"
	tcpListen      = "0A"
)

// readNetTCP parses /proc/net/tcp{,6}, keeping sockets owned by a known
// process that are established or listening.
func readNetTCP(path string, sockets map[string]int) []Conn {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Conn
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		state := fs[3]
		if state != tcpEstablished && state != tcpListen {
			continue
		}
		pid, ok := sockets[fs[9]]
		if !ok {
			continue
		}
		lip, lport, ok1 := hexAddr(fs[1])
		rip, rport, ok2 := hexAddr(fs[2])
		if !ok1 || !ok2 {
			continue
		}
		c := Conn{PID: pid, LocalIP: lip, LocalPort: lport}
		if state == tcpListen {
			c.Listen = true
		} else {
			c.RemoteIP, c.RemotePort = rip, rport
		}
		out = append(out, c)
	}
	return out
}

// hexAddr decodes "0100007F:1F90": the address is stored as 32-bit words in
// host (little-endian) order.
func hexAddr(s string) (net.IP, int, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, false
	}
	ip := make(net.IP, len(raw))
	for w := 0; w < len(raw); w += 4 {
		ip[w], ip[w+1], ip[w+2], ip[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return nil, 0, false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip, int(port), true
}
