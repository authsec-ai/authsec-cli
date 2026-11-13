//go:build windows

package proc

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Windows: the process table from CIM (PowerShell), TCP sockets from netstat.
func take() (*Snapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ps := `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress`
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ProcessId       int
		ParentProcessId int
		Name            string
		ExecutablePath  string
		CommandLine     string
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, err
	}
	s := &Snapshot{Taken: time.Now(), Procs: map[int]*Process{}}
	for _, r := range rows {
		p := &Process{PID: r.ProcessId, PPID: r.ParentProcessId, UID: -1,
			Comm: strings.TrimSuffix(r.Name, ".exe"), Exe: r.ExecutablePath, Args: strings.Fields(r.CommandLine)}
		if p.Exe == "" && r.CommandLine != "" {
			s.Partial = true
		}
		s.Procs[p.PID] = p
	}
	if out, err := exec.CommandContext(ctx, "netstat", "-ano", "-p", "TCP").Output(); err == nil {
		s.Conns = parseNetstat(string(out))
	}
	if out, err := exec.CommandContext(ctx, "netstat", "-ano", "-p", "TCPv6").Output(); err == nil {
		s.Conns = append(s.Conns, parseNetstat(string(out))...)
	}
	return s, nil
}

// parseNetstat reads "TCP  local  remote  STATE  PID" rows.
func parseNetstat(out string) []Conn {
	var conns []Conn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 5 || f[0] != "TCP" || (f[3] != "ESTABLISHED" && f[3] != "LISTENING") {
			continue
		}
		pid, _ := strconv.Atoi(f[4])
		lip, lport := hostPort(f[1])
		c := Conn{PID: pid, LocalIP: lip, LocalPort: lport}
		if f[3] == "LISTENING" {
			c.Listen = true
		} else {
			c.RemoteIP, c.RemotePort = hostPort(f[2])
		}
		conns = append(conns, c)
	}
	return conns
}

func hostPort(s string) (net.IP, int) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0
	}
	port, _ := strconv.Atoi(p)
	return net.ParseIP(strings.Trim(h, "[]")), port
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
