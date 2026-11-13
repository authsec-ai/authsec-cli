// Package enforce applies agent policies on the machine:
//
//   - each enforced agent's process tree is moved into its own cgroup v2
//     group under /sys/fs/cgroup/authsec, which new children inherit;
//   - an nftables table allows that group only the policy's destinations
//     (quarantine: nothing), matched with "socket cgroupv2";
//   - quarantine also freezes the group (cgroup.freeze);
//   - `run --enforce` confines a re-run agent with Landlock (files, TCP
//     ports) or an OpenShell sandbox;
//   - Claude Code gets a PreToolUse hook and MCP lists in managed settings.
//
// Enforcement needs root, except Landlock, which any process may apply to
// itself.
package enforce

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CgroupParent is the group all agent groups live under.
const CgroupParent = "authsec"

// Cgroups manages agent groups in a cgroup v2 hierarchy.
type Cgroups struct {
	Root string // mount point, /sys/fs/cgroup
}

// Available reports whether a writable unified (v2) hierarchy is mounted.
func (c Cgroups) Available() error {
	if _, err := os.Stat(filepath.Join(c.Root, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup v2 not mounted at %s", c.Root)
	}
	if err := os.MkdirAll(filepath.Join(c.Root, CgroupParent), 0o755); err != nil {
		return fmt.Errorf("cannot create %s/%s: %w (needs root)", c.Root, CgroupParent, err)
	}
	return nil
}

// Rel is a group's path relative to the hierarchy root, as nftables names it.
func (c Cgroups) Rel(name string) string { return CgroupParent + "/" + name }

func (c Cgroups) dir(name string) string { return filepath.Join(c.Root, CgroupParent, name) }

// Ensure creates a group.
func (c Cgroups) Ensure(name string) error {
	if !validName(name) {
		return fmt.Errorf("bad cgroup name %q", name)
	}
	return os.MkdirAll(c.dir(name), 0o755)
}

// Move puts processes into a group. Processes that exited are skipped.
func (c Cgroups) Move(name string, pids []int) (int, error) {
	f, err := os.OpenFile(filepath.Join(c.dir(name), "cgroup.procs"), os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	moved := 0
	var firstErr error
	for _, pid := range pids {
		// One write per pid: cgroup.procs takes a single id per write.
		if _, err := f.WriteString(strconv.Itoa(pid)); err != nil {
			if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such process") {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("move %d: %w", pid, err)
			}
			continue
		}
		moved++
	}
	return moved, firstErr
}

// Freeze stops (true) or resumes (false) every process in a group.
func (c Cgroups) Freeze(name string, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return writeExisting(filepath.Join(c.dir(name), "cgroup.freeze"), v)
}

// writeExisting writes a cgroup interface file, which always exists: it
// never creates one.
func writeExisting(path, v string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(v)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Procs lists the processes in a group.
func (c Cgroups) Procs(name string) []int {
	b, err := os.ReadFile(filepath.Join(c.dir(name), "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, l := range strings.Fields(string(b)) {
		if pid, err := strconv.Atoi(l); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// Remove deletes an empty group. A group that still has processes is left
// (its processes keep the policy) and reported as busy.
func (c Cgroups) Remove(name string) (busy bool, err error) {
	if len(c.Procs(name)) > 0 {
		return true, nil
	}
	_ = c.Freeze(name, false)
	if err := os.Remove(c.dir(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return true, err
	}
	return false, nil
}

// List returns the agent groups that exist.
func (c Cgroups) List() []string {
	ents, err := os.ReadDir(filepath.Join(c.Root, CgroupParent))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && validName(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// GroupName is the group of one agent instance: "<agent id>-<top pid>".
func GroupName(agentID string, pid int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(agentID) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	id := b.String()
	if id == "" || id == "_" {
		id = "agent"
	}
	return fmt.Sprintf("%s-%d", id, pid)
}

func validName(n string) bool {
	if n == "" || len(n) > 100 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
