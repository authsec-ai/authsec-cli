//go:build !windows

package link

import (
	"errors"
	"os"
	"syscall"
)

// ownedByMe refuses a file another user owns (root's files are accepted).
func ownedByMe(st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || (int(sys.Uid) != os.Geteuid() && sys.Uid != 0) {
		return errors.New("owned by another user")
	}
	return nil
}
