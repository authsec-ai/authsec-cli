//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

// ownedBy reports whether a file belongs to uid or root.
func ownedBy(st os.FileInfo, uid int) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && (int(sys.Uid) == uid || sys.Uid == 0)
}
