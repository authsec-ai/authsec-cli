//go:build !windows

package control

import (
	"os"
	"syscall"
)

func ownedBySelf(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == os.Getuid()
}
