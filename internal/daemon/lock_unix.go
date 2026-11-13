//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lockInstance makes sure one daemon runs per socket directory.
func lockInstance(dir string) (func(), error) {
	perm := os.FileMode(0o700) // a user daemon's directory is private
	if dir == "/run/authsec" {
		perm = 0o755
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "daemon.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another authsec-cli daemon is running (%s is locked)", path)
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
