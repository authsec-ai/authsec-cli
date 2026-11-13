//go:build linux

package control

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerOf(c *net.UnixConn) Peer {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}
	}
	var p Peer
	_ = raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			p = Peer{UID: int(cred.Uid), PID: int(cred.Pid), Known: true}
		}
	})
	return p
}
