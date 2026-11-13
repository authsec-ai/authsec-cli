//go:build linux

package enforce

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Landlock cannot stop connect() to named UNIX sockets. The user's service
// manager (systemd-run --user), the container daemon, key agents and display
// servers listen on such sockets and would run work for a confined agent
// outside its sandbox. Isolation hides them: the agent runs in its own user
// and mount namespace with those paths covered.

// Hidden is one path covered in the agent's mount namespace.
type Hidden struct {
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
}

// HideTargets are the session sockets and directories to cover for a user:
// those that exist and do not contain the project.
func HideTargets(uid int, project string, env map[string]string) []Hidden {
	cands := []Hidden{
		{Path: fmt.Sprintf("/run/user/%d", uid), Dir: true},
		{Path: "/run/docker.sock"}, {Path: "/var/run/docker.sock"},
		{Path: "/run/podman/podman.sock"}, {Path: "/run/containerd/containerd.sock"},
		{Path: "/tmp/.X11-unix", Dir: true}, {Path: fmt.Sprintf("/tmp/tmux-%d", uid), Dir: true},
		{Path: "/run/screen", Dir: true}, {Path: "/run/dbus/system_bus_socket"},
	}
	if s := env["SSH_AUTH_SOCK"]; s != "" && filepath.IsAbs(s) {
		cands = append(cands, Hidden{Path: s})
	}
	var out []Hidden
	seen := map[string]bool{}
	for _, c := range cands {
		real, err := filepath.EvalSymlinks(c.Path)
		if err != nil {
			continue
		}
		if seen[real] || (project != "" && (within(project, real) || within(real, project))) {
			continue
		}
		seen[real] = true
		out = append(out, Hidden{Path: real, Dir: c.Dir})
	}
	return out
}

// IsolationAttr makes a child run in a new user and mount namespace as the
// same user.
func IsolationAttr() *syscall.SysProcAttr {
	uid, gid := os.Getuid(), os.Getgid()
	return &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
	}
}

// Hide covers the paths in the current mount namespace (which must be the
// process's own: see IsolationAttr). It returns the paths covered.
func Hide(paths []Hidden) ([]string, error) {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return nil, fmt.Errorf("private mount namespace: %w", err)
	}
	var done []string
	var errs []error
	for _, h := range paths {
		var err error
		if h.Dir {
			err = unix.Mount("authsec-hidden", h.Path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0700,size=16k")
		} else {
			err = unix.Mount("/dev/null", h.Path, "", unix.MS_BIND, "")
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h.Path, err))
			continue
		}
		done = append(done, h.Path)
	}
	return done, errors.Join(errs...)
}
