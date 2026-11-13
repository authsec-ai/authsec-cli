//go:build !linux

package control

import "net"

// peerOf is unknown off Linux: privileged ops are refused.
func peerOf(*net.UnixConn) Peer { return Peer{} }
