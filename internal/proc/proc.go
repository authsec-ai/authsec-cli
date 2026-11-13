// Package proc lists the processes on the machine and their TCP connections.
//
// Args holds the raw command line: callers must scrub it (parse.Args) before
// keeping or printing it. Environment variables are read by NAME only; values
// are dropped as soon as the name is split off.
package proc

import (
	"net"
	"sort"
	"time"
)

// Process is one running process.
type Process struct {
	PID      int       `json:"pid"`
	PPID     int       `json:"ppid"`
	UID      int       `json:"uid"`
	User     string    `json:"user,omitempty"`
	Comm     string    `json:"comm"`          // short name (kernel comm or image name)
	Exe      string    `json:"exe,omitempty"` // binary path; "" when not readable
	Args     []string  `json:"-"`             // raw argv: scrub before use
	EnvNames []string  `json:"-"`             // names only, never values
	Started  time.Time `json:"started,omitempty"`
}

// Conn is one TCP socket owned by a process.
type Conn struct {
	PID        int    `json:"pid"`
	LocalIP    net.IP `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   net.IP `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Listen     bool   `json:"listen,omitempty"`
}

// Snapshot is the process table at one moment.
type Snapshot struct {
	Taken time.Time
	Procs map[int]*Process
	Conns []Conn
	// Partial is true when some processes could not be read fully (other
	// users' processes without root). Agents of other users may be missed.
	Partial bool
}

// Take reads the process table of this machine.
func Take() (*Snapshot, error) { return take() }

// Get reads one process; ok is false when it has exited. On macOS and
// Windows it takes a whole snapshot.
func Get(pid int) (*Process, bool) { return get(pid) }

// StartTime is a process's start time in boot clock ticks (Linux) or
// seconds (elsewhere); ok is false when it has exited. A pid with a new
// start time is a different process.
func StartTime(pid int) (uint64, bool) { return startTime(pid) }

// Children returns the direct children of pid, sorted by pid.
func (s *Snapshot) Children(pid int) []*Process {
	var out []*Process
	for _, p := range s.Procs {
		if p.PPID == pid && p.PID != pid {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// Descendants returns every process below pid, parents before children.
func (s *Snapshot) Descendants(pid int) []*Process {
	var out []*Process
	seen := map[int]bool{pid: true}
	queue := []int{pid}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range s.Children(cur) {
			if seen[c.PID] {
				continue
			}
			seen[c.PID] = true
			out = append(out, c)
			queue = append(queue, c.PID)
		}
	}
	return out
}

// Ancestors returns the parents of pid, nearest first.
func (s *Snapshot) Ancestors(pid int) []*Process {
	var out []*Process
	seen := map[int]bool{pid: true}
	p := s.Procs[pid]
	for p != nil {
		parent := s.Procs[p.PPID]
		if parent == nil || seen[parent.PID] {
			break
		}
		seen[parent.PID] = true
		out = append(out, parent)
		p = parent
	}
	return out
}

// ConnsOf returns the connections of the given processes.
func (s *Snapshot) ConnsOf(pids map[int]bool) []Conn {
	var out []Conn
	for _, c := range s.Conns {
		if pids[c.PID] {
			out = append(out, c)
		}
	}
	return out
}

// envNames splits a NUL-separated environment block into its names. The
// values are not kept.
func envNames(block []byte) []string {
	var out []string
	start := 0
	for i := 0; i <= len(block); i++ {
		if i == len(block) || block[i] == 0 {
			entry := block[start:i]
			start = i + 1
			for j, b := range entry {
				if b == '=' {
					if j > 0 {
						out = append(out, string(entry[:j]))
					}
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}
