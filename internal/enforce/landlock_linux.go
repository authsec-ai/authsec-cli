//go:build linux

package enforce

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock rights by ABI version. Files take only file rights; directories
// take all (a rule on a directory covers what is beneath it).
const (
	llFileRO  = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE
	llDirRO   = llFileRO | unix.LANDLOCK_ACCESS_FS_READ_DIR
	llFileAll = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	llV1All   = 0x1fff // EXECUTE .. MAKE_SYM
	llRuleNet = 2      // LANDLOCK_RULE_NET_PORT

)

// landlockNetPortAttr is struct landlock_net_port_attr (ABI 4+).
type landlockNetPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

// LandlockABI returns the kernel's Landlock ABI version, 0 if unavailable.
func LandlockABI() int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return 0
	}
	return int(v)
}

func handledFS(abi int) uint64 {
	h := uint64(llV1All)
	if abi >= 2 {
		h |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		h |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		h |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return h
}

// Restrict confines the calling thread, and the program it execs next, to
// the sandbox. Call it on a locked OS thread immediately before exec.
// It returns what was applied.
func (s Sandbox) Restrict() (Applied, error) {
	abi := LandlockABI()
	if abi == 0 {
		return Applied{}, errors.New("Landlock is not available (Linux 5.13+ with landlock in the LSM list)")
	}
	fsAccess := handledFS(abi)
	var netAccess uint64
	if s.RestrictNet {
		if abi < 4 {
			return Applied{ABI: abi}, fmt.Errorf("this kernel's Landlock (ABI %d) cannot limit TCP ports (needs ABI 4, Linux 6.7+)", abi)
		}
		netAccess = unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	}
	attr := unix.LandlockRulesetAttr{Access_fs: fsAccess, Access_net: netAccess}
	size := uintptr(8)
	if abi >= 4 {
		size = 16
	}
	if abi >= 6 {
		// No abstract UNIX sockets or signals to processes outside.
		attr.Scoped = unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | unix.LANDLOCK_SCOPE_SIGNAL
		size = 24
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), size, 0)
	if errno != 0 {
		return Applied{}, fmt.Errorf("landlock_create_ruleset: %v", errno)
	}
	defer unix.Close(int(fd))
	applied := Applied{ABI: abi, Scoped: abi >= 6}
	add := func(path string, write, noExec bool) {
		pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			applied.Missing = append(applied.Missing, path)
			return
		}
		defer unix.Close(pfd)
		var st unix.Stat_t
		if unix.Fstat(pfd, &st) != nil {
			return
		}
		var access uint64
		dir := st.Mode&unix.S_IFMT == unix.S_IFDIR
		switch {
		case dir && write && noExec:
			access = fsAccess &^ unix.LANDLOCK_ACCESS_FS_EXECUTE
		case dir && write:
			access = fsAccess
		case dir:
			access = llDirRO
		case write:
			access = llFileAll & fsAccess
		default:
			access = llFileRO
		}
		pb := unix.LandlockPathBeneathAttr{Allowed_access: access & fsAccess, Parent_fd: int32(pfd)}
		if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&pb)), 0, 0, 0); errno != 0 {
			applied.Missing = append(applied.Missing, path+" ("+errno.Error()+")")
			return
		}
		if write {
			applied.ReadWrite = append(applied.ReadWrite, path)
		} else {
			applied.ReadOnly = append(applied.ReadOnly, path)
		}
	}
	for _, p := range s.ReadOnly {
		add(p, false, false)
	}
	for _, p := range s.ReadWrite {
		add(p, true, false)
	}
	for _, p := range s.ScratchRW {
		add(p, true, true)
	}
	if netAccess != 0 {
		for _, port := range s.ConnectPorts {
			na := landlockNetPortAttr{AllowedAccess: unix.LANDLOCK_ACCESS_NET_CONNECT_TCP, Port: uint64(port)}
			if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, fd, llRuleNet, uintptr(unsafe.Pointer(&na)), 0, 0, 0); errno != 0 {
				return applied, fmt.Errorf("landlock port %d: %v", port, errno)
			}
		}
		applied.Ports = s.ConnectPorts
		applied.NetRestricted = true
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return applied, fmt.Errorf("no_new_privs: %w", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); errno != 0 {
		return applied, fmt.Errorf("landlock_restrict_self: %v", errno)
	}
	return applied, nil
}

// ExecConfined confines this process and replaces it with the program. It
// only returns on error.
func (s Sandbox) ExecConfined(bin string, argv, env []string) (Applied, error) {
	runtime.LockOSThread() // Landlock applies to this thread; exec happens on it
	a, err := s.Restrict()
	if err != nil {
		return a, err
	}
	return a, unix.Exec(bin, argv, env)
}
