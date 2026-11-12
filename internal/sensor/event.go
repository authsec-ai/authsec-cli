// Package sensor loads the eBPF programs (Linux) and delivers kernel events:
// process start and exit, outgoing TCP connections, file opens by tracked
// processes, and DNS answers. See bpf/sensor.c for what the kernel side
// filters.
package sensor

import (
	"errors"
	"net"
	"time"
)

// Type is the kind of a kernel event.
type Type uint32

const (
	Exec    Type = 1
	Exit    Type = 2
	Fork    Type = 3
	Connect Type = 4
	Open    Type = 5
)

func (t Type) String() string {
	switch t {
	case Exec:
		return "exec"
	case Exit:
		return "exit"
	case Fork:
		return "fork"
	case Connect:
		return "connect"
	case Open:
		return "open"
	}
	return "unknown"
}

// Event is one kernel event. Path is the binary (exec) or file (open).
type Event struct {
	Type    Type
	PID     int // process (tgid); the child for fork
	PPID    int // parent: exec and fork only
	UID     int
	Time    time.Time
	Comm    string
	Path    string
	Flags   int32 // open flags
	DstIP   net.IP
	DstPort int
}

// DNSAnswer is a name and the addresses a DNS response gave for it, after
// following CNAMEs (Name is the name that was asked).
type DNSAnswer struct {
	Name string
	IPs  []net.IP
	TTL  time.Duration
}

// ErrUnsupported means the sensor cannot run here: not Linux, no BTF, or not
// root. Callers fall back to polling the process table.
var ErrUnsupported = errors.New("eBPF sensor unavailable")

// Sensor is a running set of eBPF programs.
type Sensor interface {
	Events() <-chan Event
	DNS() <-chan DNSAnswer
	// Track adds a process to the tracked set: its file opens, children
	// and exit are reported from now on.
	Track(pid int) error
	Untrack(pid int)
	// Dropped is the number of events lost because user space fell behind.
	Dropped() uint64
	Close() error
}

// Open flags that mean the file is written.
const (
	oWronly = 0x1
	oRdwr   = 0x2
	oCreat  = 0x40
	oTrunc  = 0x200
	oAppend = 0x400
)

// Writes reports whether open flags allow writing.
func Writes(flags int32) bool {
	return flags&(oWronly|oRdwr|oCreat|oTrunc|oAppend) != 0
}
