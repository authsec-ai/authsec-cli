package enforce

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec-cli/internal/policy"
)

// Sandbox is what a re-run agent may touch: Landlock path rules and, when
// the policy denies the network by default, the TCP ports it may connect to.
// Landlock is allow-only: a deny inside an allowed directory cannot be
// expressed and is reported in Plan.Warnings.
type Sandbox struct {
	ReadOnly     []string
	ReadWrite    []string
	ScratchRW    []string // writable but not executable (/tmp, /var/tmp, /dev)
	RestrictNet  bool
	ConnectPorts []int
}

// Applied is what the kernel accepted.
type Applied struct {
	ABI           int
	Scoped        bool // abstract UNIX sockets and signals outside the sandbox are refused
	ReadOnly      []string
	ReadWrite     []string
	Missing       []string // paths that do not exist (skipped)
	NetRestricted bool
	Ports         []int
}

// Plan is a sandbox and what the policy asked for that it cannot do.
type Plan struct {
	Sandbox  Sandbox
	Warnings []string
	// Blocking are things the sandbox would fail to protect that a policy
	// must not silently lose (a credential store left readable).
	Blocking []string
}

// systemRO are what programs need to start: libraries, binaries, config,
// /proc. systemRW are scratch and devices.
var (
	// /run is not granted whole: it holds the user's service manager,
	// container and key-agent sockets. Only the resolver's files are.
	systemRO = []string{"/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin", "/etc", "/opt", "/proc", "/sys",
		"/run/systemd/resolve", "/run/resolvconf", "/run/NetworkManager", "/snap", "/nix", "/var/lib", "/var/cache",
		"{home}/.gitconfig", "{home}/.config/git"}
	systemRW = []string{"/tmp", "/var/tmp", "/dev"}
)

// OwnState are the files an agent writes to keep working (sessions, auth
// refresh). A re-run agent may write them whatever the policy says.
var OwnState = map[string][]string{
	"claude-code": {"{home}/.claude", "{home}/.claude.json", "{home}/.cache/claude", "{home}/.local/share/claude", "{home}/.local/state/claude", "{home}/.config/claude"},
	"codex":       {"{home}/.codex"},
	"gemini-cli":  {"{home}/.gemini"},
	"opencode":    {"{home}/.local/share/opencode", "{home}/.config/opencode"},
	"aider":       {"{home}/.aider"},
	"goose":       {"{home}/.config/goose", "{home}/.local/share/goose"},
}

// PlanSandbox turns an (unexpanded) policy into a Landlock sandbox for one
// run: system paths, the agent's own binary and state, the project (for
// {project}) and the policy's lists.
func PlanSandbox(p *policy.Policy, home, project, binary string) Plan {
	var plan Plan
	ep := p.Expand(home, project)
	var ro []string
	for _, x := range systemRO {
		ro = append(ro, strings.ReplaceAll(x, "{home}", home))
	}
	scratch := append([]string(nil), systemRW...)
	var rw []string
	if len(p.Filesystem.ReadWrite) == 0 && len(p.Filesystem.ReadOnly) == 0 && project != "" {
		rw = append(rw, project)
		plan.Warnings = append(plan.Warnings, "the policy lists no paths: the agent may use the project ("+project+") and nothing else of the home directory")
	}
	if binary != "" {
		if real, err := filepath.EvalSymlinks(binary); err == nil {
			binary = real
		}
		ro = append(ro, packageRoot(binary))
		if interp := interpreterOf(binary); interp != "" {
			ro = append(ro, packageRoot(interp))
		}
	}
	for _, s := range OwnState[p.Agent.ID] {
		rw = append(rw, filepath.Clean(strings.ReplaceAll(s, "{home}", home)))
	}
	rw = append(rw, ep.Filesystem.ReadWrite...)
	ro = append(ro, ep.Filesystem.ReadOnly...)

	// Denies: drop allowed paths inside them; warn when one is inside an
	// allowed path (Landlock cannot carve it out).
	keep := func(list []string, kind string) []string {
		var out []string
		for _, path := range list {
			inside := ""
			for _, d := range ep.Filesystem.Deny {
				if within(path, d) {
					inside = d
				}
			}
			if inside != "" {
				plan.Warnings = append(plan.Warnings, kind+" "+path+" left out: inside denied "+inside)
				continue
			}
			out = append(out, path)
		}
		return out
	}
	rw = keep(dedupePaths(rw), "read_write")
	ro = keep(dedupePaths(ro), "read_only")
	credential := map[string]bool{}
	for _, d := range policy.DefaultDeniedPaths {
		credential[filepath.Clean(strings.ReplaceAll(d, "{home}", home))] = true
	}
	for _, d := range ep.Filesystem.Deny {
		for _, a := range append(append(append([]string(nil), rw...), ro...), scratch...) {
			if within(d, a) && d != a {
				msg := "deny " + d + " cannot be enforced: it is inside allowed " + a + " (Landlock allows, it cannot carve out)"
				if credential[d] {
					plan.Blocking = append(plan.Blocking, msg)
				} else {
					plan.Warnings = append(plan.Warnings, msg)
				}
				break
			}
		}
	}
	for _, x := range ep.Filesystem.ReadOnly {
		for _, a := range append(append([]string(nil), rw...), scratch...) {
			if within(x, a) && x != a {
				plan.Warnings = append(plan.Warnings, "read_only "+x+" is writable: it is inside read-write "+a)
				break
			}
		}
	}
	plan.Sandbox = Sandbox{ReadOnly: ro, ReadWrite: rw, ScratchRW: scratch}

	// Network: with default deny, only the ports the allow rules name (plus
	// DNS over TCP). Host names need the daemon (nftables).
	if p.Network.Default == policy.Deny {
		ports := map[int]bool{53: true}
		anyPort := false
		for _, r := range p.Network.Allow {
			if r.Port == 0 {
				anyPort = true
			}
			ports[r.Port] = true
		}
		if anyPort {
			plan.Warnings = append(plan.Warnings, "an allow rule has no port: TCP ports are not restricted")
		} else {
			plan.Sandbox.RestrictNet = true
			for port := range ports {
				plan.Sandbox.ConnectPorts = append(plan.Sandbox.ConnectPorts, port)
			}
			sort.Ints(plan.Sandbox.ConnectPorts)
		}
	}
	return plan
}

// packageRoot is what to grant for a program: its directory, or the whole
// package it belongs to (an npm package under node_modules, a Python
// virtualenv), whose files it loads at start.
func packageRoot(bin string) string {
	dir := filepath.Dir(bin)
	for d := dir; d != "/" && d != "."; d = filepath.Dir(d) {
		if filepath.Base(filepath.Dir(d)) == "node_modules" || strings.HasPrefix(filepath.Base(filepath.Dir(d)), "@") && filepath.Base(filepath.Dir(filepath.Dir(d))) == "node_modules" {
			return d
		}
		if _, err := os.Stat(filepath.Join(d, "pyvenv.cfg")); err == nil {
			return d
		}
		if _, err := os.Stat(filepath.Join(d, "package.json")); err == nil && d != dir {
			return d
		}
	}
	return dir
}

// interpreterOf returns the interpreter of a script (#!), resolved.
func interpreterOf(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	line := string(buf[:n])
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	line = strings.TrimPrefix(strings.SplitN(line, "\n", 2)[0], "#!")
	f2 := strings.Fields(line)
	if len(f2) == 0 {
		return ""
	}
	interp := f2[0]
	if filepath.Base(interp) == "env" && len(f2) > 1 {
		if p, err := exec.LookPath(f2[1]); err == nil {
			interp = p
		}
	}
	if real, err := filepath.EvalSymlinks(interp); err == nil {
		return real
	}
	return interp
}

func within(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || dir == "/" || strings.HasPrefix(path, dir+"/")
}

func dedupePaths(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		x = filepath.Clean(x)
		if !seen[x] && x != "." {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
