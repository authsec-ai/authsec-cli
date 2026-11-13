//go:build linux

package enforce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// DestroySockets closes the TCP and UDP sockets (IPv4 and IPv6) the
// processes hold, as `ss -K` does: netlink sock_diag finds them by inode,
// SOCK_DESTROY closes them (the process sees ECONNABORTED). Listening
// sockets are kept: only connections are cut. Needs root and a kernel with
// CONFIG_INET_DIAG_DESTROY.
func DestroySockets(pids []int) (int, error) {
	inodes := socketInodes("/proc", pids)
	if len(inodes) == 0 {
		return 0, nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, err
	}
	closed := 0
	var lastErr error
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, proto := range []uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			socks, err := dumpSockets(fd, fam, proto)
			if err != nil {
				lastErr = err
				continue
			}
			for _, s := range socks {
				if !inodes[s.inode] || (proto == unix.IPPROTO_TCP && s.state == tcpStateListen) {
					continue
				}
				if err := destroySocket(fd, fam, proto, s.id); err != nil {
					lastErr = err
					continue
				}
				closed++
			}
		}
	}
	if closed == 0 && lastErr != nil {
		return 0, lastErr
	}
	return closed, nil
}

// socketInodes lists the socket inodes the processes have open.
func socketInodes(procRoot string, pids []int) map[uint32]bool {
	out := map[uint32]bool{}
	for _, pid := range pids {
		dir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			l, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			if n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"), 10, 32); err == nil {
				out[uint32(n)] = true
			}
		}
	}
	return out
}

const (
	sockDiagByFamily = 20
	sockDestroy      = 21
	tcpStateListen   = 10
	nlmsgHdrLen      = 16
	inetDiagReqLen   = 56 // struct inet_diag_req_v2
	inetDiagMsgLen   = 72 // struct inet_diag_msg
	sockIDLen        = 48 // struct inet_diag_sockid
)

type diagSock struct {
	id    [sockIDLen]byte
	state uint8
	inode uint32
}

// request builds nlmsghdr + inet_diag_req_v2.
func request(typ uint16, flags uint16, fam, proto uint8, id []byte) []byte {
	b := make([]byte, nlmsgHdrLen+inetDiagReqLen)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], 1) // seq
	r := b[nlmsgHdrLen:]
	r[0], r[1] = fam, proto                          // sdiag_family, sdiag_protocol
	binary.NativeEndian.PutUint32(r[4:], 0xffffffff) // idiag_states: all
	if id != nil {
		copy(r[8:8+sockIDLen], id)
	}
	return b
}

func dumpSockets(fd int, fam, proto uint8) ([]diagSock, error) {
	if err := unix.Sendto(fd, request(sockDiagByFamily, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, fam, proto, nil), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []diagSock
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return out, err
		}
		msgs, err := syscallParseNetlink(buf[:n])
		if err != nil {
			return out, err
		}
		for _, m := range msgs {
			switch m.typ {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				return out, nlError(m.data)
			}
			if len(m.data) < inetDiagMsgLen {
				continue
			}
			var s diagSock
			s.state = m.data[1]
			copy(s.id[:], m.data[4:4+sockIDLen])
			s.inode = binary.NativeEndian.Uint32(m.data[68:72])
			out = append(out, s)
		}
	}
}

func destroySocket(fd int, fam, proto uint8, id [sockIDLen]byte) error {
	if err := unix.Sendto(fd, request(sockDestroy, unix.NLM_F_REQUEST|unix.NLM_F_ACK, fam, proto, id[:]), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscallParseNetlink(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.typ == unix.NLMSG_ERROR {
			return nlError(m.data)
		}
	}
	return nil
}

type nlMsg struct {
	typ  uint16
	data []byte
}

func syscallParseNetlink(b []byte) ([]nlMsg, error) {
	var out []nlMsg
	for len(b) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(b[0:4]))
		if l < nlmsgHdrLen || l > len(b) {
			return out, errors.New("short netlink message")
		}
		out = append(out, nlMsg{typ: binary.NativeEndian.Uint16(b[4:6]), data: b[nlmsgHdrLen:l]})
		l = (l + 3) &^ 3
		if l > len(b) {
			break
		}
		b = b[l:]
	}
	return out, nil
}

func nlError(data []byte) error {
	if len(data) < 4 {
		return errors.New("netlink error")
	}
	code := int32(binary.NativeEndian.Uint32(data[0:4]))
	if code == 0 {
		return nil // an ACK
	}
	return fmt.Errorf("sock_diag: %w", unix.Errno(-code))
}
