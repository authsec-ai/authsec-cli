//go:build darwin

package proc

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// macOS: no /proc. ps gives the table, lsof the TCP sockets. Both run with a
// timeout; a missing lsof leaves the connections empty.
func take() (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-axww", "-o", "pid=,ppid=,uid=,user=,lstart=,comm=").Output()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Taken: time.Now(), Procs: map[int]*Process{}}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 { // pid ppid uid user + 5 lstart words + comm
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		ppid, _ := strconv.Atoi(f[1])
		uid, _ := strconv.Atoi(f[2])
		started, _ := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(f[4:9], " "), time.Local)
		exe := strings.Join(f[9:], " ")
		s.Procs[pid] = &Process{PID: pid, PPID: ppid, UID: uid, User: f[3], Exe: exe,
			Comm: lastElem(exe), Started: started.UTC()}
	}
	// argv separately: ps cannot split arguments that contain spaces, so
	// args are split on whitespace (good enough for matching).
	if out, err := exec.CommandContext(ctx, "ps", "-axww", "-o", "pid=,args=").Output(); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(out))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			pidStr, args, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
			pid, _ := strconv.Atoi(pidStr)
			if p := s.Procs[pid]; ok && p != nil {
				p.Args = strings.Fields(args)
			}
		}
	}
	if out, err := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED,LISTEN", "-F", "pnT").Output(); err == nil {
		s.Conns = parseLsof(out)
	}
	return s, nil
}

// parseLsof reads lsof -F pnT output: p<pid>, n<local>-><remote>, TST=<state>.
func parseLsof(out []byte) []Conn {
	var conns []Conn
	pid := 0
	var name string
	flush := func(state string) {
		if name == "" {
			return
		}
		local, remote, _ := strings.Cut(name, "->")
		lip, lport := splitHostPort(local)
		c := Conn{PID: pid, LocalIP: lip, LocalPort: lport}
		if state == "LISTEN" {
			c.Listen = true
		} else if remote != "" {
			c.RemoteIP, c.RemotePort = splitHostPort(remote)
		}
		conns = append(conns, c)
		name = ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			name = line[1:]
		case 'T':
			if st, ok := strings.CutPrefix(line[1:], "ST="); ok {
				flush(st)
			}
		}
	}
	return conns
}

func splitHostPort(s string) (net.IP, int) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0
	}
	port, _ := strconv.Atoi(p)
	return net.ParseIP(strings.Trim(h, "[]")), port
}

func lastElem(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func get(pid int) (*Process, bool) {
	s, err := take()
	if err != nil {
		return nil, false
	}
	p, ok := s.Procs[pid]
	return p, ok
}

func startTime(pid int) (uint64, bool) {
	p, ok := get(pid)
	if !ok {
		return 0, false
	}
	return uint64(p.Started.Unix()), true
}
