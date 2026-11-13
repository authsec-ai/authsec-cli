//go:build linux

package sensor

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// sensor.o is built from bpf/sensor.c by `make bpf` (clang in Docker) and
// committed, so `go build` needs no clang.
//
//go:embed bpf/sensor.o
var object []byte

type objects struct {
	OnExec      *ebpf.Program `ebpf:"on_exec"`
	OnFork      *ebpf.Program `ebpf:"on_fork"`
	OnExit      *ebpf.Program `ebpf:"on_exit"`
	OnSockState *ebpf.Program `ebpf:"on_sock_state"`
	OnOpenat    *ebpf.Program `ebpf:"on_openat"`
	DNSAnswers  *ebpf.Program `ebpf:"dns_answers"`
	Events      *ebpf.Map     `ebpf:"events"`
	Tracked     *ebpf.Map     `ebpf:"tracked"`
	DroppedMap  *ebpf.Map     `ebpf:"dropped"`
}

func (o *objects) close() {
	for _, c := range []interface{ Close() error }{o.OnExec, o.OnFork, o.OnExit, o.OnSockState, o.OnOpenat, o.DNSAnswers, o.Events, o.Tracked, o.DroppedMap} {
		if c != nil {
			c.Close()
		}
	}
}

type linuxSensor struct {
	objs   objects
	links  []link.Link
	rd     *ringbuf.Reader
	dnsFD  int
	events chan Event
	dns    chan DNSAnswer
	boot   time.Time // wall clock at boot, for event times
	wg     sync.WaitGroup
	once   sync.Once
}

// Start loads and attaches the programs. It returns ErrUnsupported (wrapped
// with the reason) when the kernel or privileges do not allow it.
func Start() (Sensor, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: needs root (or CAP_BPF and CAP_PERFMON)", ErrUnsupported)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return nil, fmt.Errorf("%w: kernel has no BTF (/sys/kernel/btf/vmlinux)", ErrUnsupported)
	}
	_ = rlimit.RemoveMemlock() // kernels before 5.11 account BPF memory to memlock
	ensureTracefs()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("load eBPF object: %w", err)
	}
	s := &linuxSensor{events: make(chan Event, 4096), dns: make(chan DNSAnswer, 256), dnsFD: -1, boot: bootWallTime()}
	if err := spec.LoadAndAssign(&s.objs, nil); err != nil {
		return nil, fmt.Errorf("%w: load programs: %v", ErrUnsupported, err)
	}
	// The kernel's BTF (tens of MiB parsed) is only needed to load: free it.
	spec = nil
	btf.FlushKernelSpec()
	defer debug.FreeOSMemory()
	for _, tp := range []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"sched", "sched_process_exec", s.objs.OnExec},
		{"sched", "sched_process_fork", s.objs.OnFork},
		{"sched", "sched_process_exit", s.objs.OnExit},
		{"sock", "inet_sock_set_state", s.objs.OnSockState},
		{"syscalls", "sys_enter_openat", s.objs.OnOpenat},
	} {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("%w: attach %s/%s: %v", ErrUnsupported, tp.group, tp.name, err)
		}
		s.links = append(s.links, l)
	}
	if s.rd, err = ringbuf.NewReader(s.objs.Events); err != nil {
		s.Close()
		return nil, fmt.Errorf("ring buffer: %w", err)
	}
	if fd, err := dnsSocket(s.objs.DNSAnswers); err == nil {
		s.dnsFD = fd
		s.wg.Add(1)
		go s.readDNS()
	} // without it, destinations are named only by the LLM host table
	s.wg.Add(1)
	go s.readEvents()
	return s, nil
}

func (s *linuxSensor) Events() <-chan Event  { return s.events }
func (s *linuxSensor) DNS() <-chan DNSAnswer { return s.dns }
func (s *linuxSensor) Untrack(pid int)       { _ = s.objs.Tracked.Delete(uint32(pid)) }
func (s *linuxSensor) Track(pid int) error   { return s.objs.Tracked.Put(uint32(pid), uint8(1)) }
func (s *linuxSensor) Dropped() uint64 {
	var v uint64
	_ = s.objs.DroppedMap.Lookup(uint32(0), &v)
	return v
}

func (s *linuxSensor) Close() error {
	s.once.Do(func() {
		for _, l := range s.links {
			l.Close()
		}
		if s.rd != nil {
			s.rd.Close()
		}
		if s.dnsFD >= 0 {
			unix.Close(s.dnsFD)
		}
		s.wg.Wait()
		s.objs.close()
		close(s.events)
		close(s.dns)
	})
	return nil
}

// rawEvent mirrors struct event in sensor.c (320 bytes, no padding).
type rawEvent struct {
	Type   uint32
	PID    uint32
	PPID   uint32
	UID    uint32
	TsNs   uint64
	Family uint16
	DPort  uint16
	Flags  int32
	DAddr  [16]byte
	Comm   [16]byte
	Path   [256]byte
}

func (s *linuxSensor) readEvents() {
	defer s.wg.Done()
	var raw rawEvent
	for {
		rec, err := s.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		s.events <- decode(&raw, s.boot)
	}
}

func decode(r *rawEvent, boot time.Time) Event {
	e := Event{Type: Type(r.Type), PID: int(r.PID), PPID: int(r.PPID), UID: int(r.UID),
		Time: boot.Add(time.Duration(r.TsNs)), Comm: cstr(r.Comm[:]), Path: cstr(r.Path[:]), Flags: r.Flags}
	if e.Type == Connect {
		e.DstPort = int(r.DPort)
		switch r.Family {
		case unix.AF_INET:
			e.DstIP = net.IP(append([]byte(nil), r.DAddr[:4]...))
		case unix.AF_INET6:
			e.DstIP = net.IP(append([]byte(nil), r.DAddr[:16]...))
		}
	}
	return e
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// bootWallTime is the wall-clock time the machine booted (event timestamps
// are nanoseconds since boot, suspend included).
func bootWallTime() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Now()
	}
	return time.Now().Add(-time.Duration(ts.Nano()))
}

// dnsSocket opens a packet socket on every interface with the DNS filter.
func dnsSocket(prog *ebpf.Program) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return -1, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD()); err != nil {
		unix.Close(fd)
		return -1, err
	}
	// Wake up periodically so Close is noticed.
	tv := unix.Timeval{Sec: 1}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return fd, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (s *linuxSensor) readDNS() {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, _, err := unix.Recvfrom(s.dnsFD, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return // closed
		}
		if a, ok := ParseDNSPacket(buf[:n]); ok {
			select {
			case s.dns <- a:
			default: // never block the reader on DNS
			}
		}
	}
}

// ParseDNSPacket reads an IP packet carrying a UDP DNS response and returns
// the asked name with its A/AAAA answers.
func ParseDNSPacket(pkt []byte) (DNSAnswer, bool) {
	if len(pkt) < 1 {
		return DNSAnswer{}, false
	}
	var off int
	var src net.IP
	switch pkt[0] >> 4 {
	case 4:
		off = int(pkt[0]&0x0F) * 4
		if len(pkt) >= 20 {
			src = net.IP(append([]byte(nil), pkt[12:16]...))
		}
	case 6:
		off = 40
		if len(pkt) >= 40 {
			src = net.IP(append([]byte(nil), pkt[8:24]...))
		}
	default:
		return DNSAnswer{}, false
	}
	if len(pkt) < off+8 {
		return DNSAnswer{}, false
	}
	a, ok := ParseDNS(pkt[off+8:])
	a.Src = src
	return a, ok
}

// ParseDNS reads a DNS response message.
func ParseDNS(msg []byte) (DNSAnswer, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return DNSAnswer{}, false
	}
	q, err := p.Question()
	if err != nil {
		return DNSAnswer{}, false
	}
	_ = p.SkipAllQuestions()
	a := DNSAnswer{Name: trimDot(q.Name.String())}
	var minTTL uint32
	for {
		hdr, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch hdr.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return a, len(a.IPs) > 0
			}
			a.IPs = append(a.IPs, net.IP(append([]byte(nil), r.A[:]...)))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return a, len(a.IPs) > 0
			}
			a.IPs = append(a.IPs, net.IP(append([]byte(nil), r.AAAA[:]...)))
		default:
			if err := p.SkipAnswer(); err != nil {
				return a, len(a.IPs) > 0
			}
			continue
		}
		if minTTL == 0 || hdr.TTL < minTTL {
			minTTL = hdr.TTL
		}
	}
	a.TTL = time.Duration(minTTL) * time.Second
	return a, len(a.IPs) > 0
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// OpensDirectory reports whether open flags open a directory (a listing,
// not a file access).
func OpensDirectory(flags int32) bool { return flags&unix.O_DIRECTORY != 0 }

// ensureTracefs mounts tracefs when it is missing, as in a privileged
// container: tracepoints are attached through it. A failure is left to the
// attach, which reports it.
func ensureTracefs() {
	for _, d := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		if _, err := os.Stat(d + "/events"); err == nil {
			return
		}
	}
	if err := os.MkdirAll("/sys/kernel/tracing", 0o700); err == nil {
		_ = unix.Mount("tracefs", "/sys/kernel/tracing", "tracefs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
	}
}
