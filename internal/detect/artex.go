package detect

import (
	"context"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ARTEX indicators, checked against github.com/BaaRai/ARTEX (default branch,
// read 2026-11-13). Confidence and source are given per indicator.
const (
	// High: cmd/artex/main.go is the only command; install.sh, update.sh and
	// build.sh build it as "artex" (build.sh: "artex.exe" on Windows), the
	// Dockerfile copies it to /app/artex, and `go run ./cmd/artex` (dev.sh)
	// also links a binary named artex.
	artexBinary = "artex"

	// High: every variable ARTEX reads starts with ARTEX_ (config/config.go:
	// ARTEX_CONFIG, ARTEX_PG_DSN, ARTEX_SKILL_DIR; cmd/artex/main.go:
	// ARTEX_JWT_KEY_DIR, ARTEX_TRUSTED_PROXIES; server/update_check.go:
	// ARTEX_UPDATE_CHECK; agent/provider.go: ARTEX_LLM_*; docker-compose.yml:
	// ARTEX_NOISE_PROFILE, ARTEX_TASK_BUDGET_* and others). ARTEX unsets
	// only ARTEX_PG_DSN and the API keys after startup (server/env_scrub.go),
	// so the processes it starts (shells, tools) inherit the other ARTEX_*
	// names and match too.
	artexEnvPrefix = "ARTEX_"

	// High: the -addr flag defaults to 127.0.0.1:8787 (web UI and API) and
	// -proxy to 127.0.0.1:8788 (traffic recording proxy) in
	// cmd/artex/main.go; the Docker image listens on :8787 and :8788
	// (Dockerfile CMD, docker-compose.yml ports). Both are configurable, so
	// a port only counts with another indicator.
	artexUIPort    = 8787
	artexProxyPort = 8788
)

// artexFlags are the flags of cmd/artex/main.go (high confidence). Only
// their names are read, never their values.
var artexFlags = map[string]bool{"addr": true, "proxy": true, "data": true}

// Files ARTEX keeps next to its binary (config.BaseDir is the binary's
// directory unless it runs under `go run`):
//   - jwt.key: server/auth.go writes the session signing key to
//     ARTEX_JWT_KEY_DIR, else BaseDir (high).
//   - keys/jwt.key: the Docker image sets ARTEX_JWT_KEY_DIR=/app/keys next
//     to /app/artex (Dockerfile, docker-compose.yml) (high).
//   - data/: the -data flag defaults to BaseDir/data and
//     server/manager.go NewManager creates it (high).
//   - skills/: config.SkillDir defaults to BaseDir/skills and creates it
//     (high).
//   - config.json: optional; config.Path reads it next to the binary and
//     install.sh writes it (medium: a common name, evidence only).
var artexKeyFiles = [][]string{{"jwt.key"}, {"keys", "jwt.key"}}

// ARTEX naming of containers (high confidence):
//   - docker-compose.yml has a service "artex" (and "postgres"). Compose
//     names its containers <project>-artex-<n> (v1: <project>_artex_<n>);
//     a checkout in a directory named ARTEX gives the project "artex" and
//     containers artex-artex-1 and artex-postgres-1.
//   - docker-compose.bench.yml sets container_name artex-bench.
//   - install.sh runs Postgres as a container named artex-pg.
//
// Not used here: the update check's User-Agent "artex-update-check"
// (server/update_check.go, opt-in by ARTEX_UPDATE_CHECK=1, sent to
// api.github.com/repos/BaaRai/ARTEX/releases/latest) is a network
// indicator for a TLS-inspecting proxy; the API's unauthenticated
// /api/health (server/auth.go) is an HTTP indicator.

// ARTEXProcess reports ARTEX in one process, or nil. statFile must only
// report whether a path exists; it may be nil to skip the file checks.
//
// Strong indicators (any one gives high severity): the binary name artex,
// ARTEX_* environment variable names, or jwt.key with data/ and skills/
// next to the binary. Medium indicators (two give medium severity): a
// listening port 8787 or 8788, ARTEX's flag names, or part of its file
// layout next to the binary.
func ARTEXProcess(p Process, statFile func(path string) bool) *Detection {
	var ev []string
	strong, medium := 0, 0
	if isARTEXBinary(p) {
		strong++
		ev = append(ev, "binary name artex")
	}
	if env := artexEnvNames(p.EnvNames); len(env) > 0 {
		strong++
		ev = append(ev, "ARTEX environment variables: "+joinCapped(env, 5))
	}
	if ports := artexPorts(p.Listen); ports != "" {
		medium++
		ev = append(ev, ports)
	}
	if flags := artexFlagNames(p.Args); len(flags) >= 2 {
		medium++
		ev = append(ev, "ARTEX flags: "+strings.Join(flags, ", "))
	}
	s, m, fev := artexFiles(p.Exe, statFile, strong+medium > 0)
	strong += s
	medium += m
	ev = append(ev, fev...)
	sev := ""
	switch {
	case strong > 0:
		sev = High
	case medium >= 2:
		sev = Medium
	default:
		return nil
	}
	return &Detection{Rule: RuleARTEX, Severity: sev, Title: "ARTEX AI pentest agent running",
		PID: p.PID, AgentID: artexBinary, Evidence: ev}
}

// isARTEXBinary reports whether the process's binary or short name is artex.
func isARTEXBinary(p Process) bool {
	if p.Exe != "" && baseName(p.Exe) == artexBinary {
		return true
	}
	return baseName(p.Comm) == artexBinary
}

// artexEnvNames returns the ARTEX_* names, sorted and without repeats. A
// NAME=VALUE entry given by mistake is cut to its name.
func artexEnvNames(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if i := strings.IndexByte(n, '='); i >= 0 {
			n = n[:i]
		}
		if len(n) > len(artexEnvPrefix) && strings.EqualFold(n[:len(artexEnvPrefix)], artexEnvPrefix) && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// artexPorts describes the ARTEX ports among listen, or "".
func artexPorts(listen []int) string {
	ui, proxy := false, false
	for _, p := range listen {
		ui = ui || p == artexUIPort
		proxy = proxy || p == artexProxyPort
	}
	switch {
	case ui && proxy:
		return "listening on 8787 (ARTEX web UI) and 8788 (ARTEX traffic proxy)"
	case ui:
		return "listening on 8787 (ARTEX web UI)"
	case proxy:
		return "listening on 8788 (ARTEX traffic proxy)"
	}
	return ""
}

// artexFlagNames returns ARTEX's flag names found in args (argv[0] skipped),
// sorted. Values are never kept.
func artexFlagNames(args []string) []string {
	seen := map[string]bool{}
	for i, a := range args {
		if i == 0 || !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if j := strings.IndexByte(name, '='); j >= 0 {
			name = name[:j]
		}
		if artexFlags[name] {
			seen[name] = true
		}
	}
	var out []string
	for n := range seen {
		out = append(out, "-"+n)
	}
	sort.Strings(out)
	return out
}

// artexFiles checks ARTEX's files next to exe. The key file is always
// checked; the rest only when it exists or another indicator matched
// (others), to keep a scan of every process cheap.
func artexFiles(exe string, statFile func(string) bool, others bool) (strong, medium int, ev []string) {
	if statFile == nil || exe == "" {
		return 0, 0, nil
	}
	dir := filepath.Dir(exe)
	if dir == "." || dir == "" {
		return 0, 0, nil
	}
	key := ""
	for _, parts := range artexKeyFiles {
		if statFile(filepath.Join(append([]string{dir}, parts...)...)) {
			key = strings.Join(parts, "/")
			break
		}
	}
	if key == "" && !others {
		return 0, 0, nil
	}
	data := statFile(filepath.Join(dir, "data"))
	skills := statFile(filepath.Join(dir, "skills"))
	var found []string
	if key != "" {
		found = append(found, key)
	}
	if data {
		found = append(found, "data/")
	}
	if skills {
		found = append(found, "skills/")
	}
	if statFile(filepath.Join(dir, "config.json")) {
		found = append(found, "config.json")
	}
	switch {
	case key != "" && data && skills:
		strong = 1
	case key != "" && (data || skills), data && skills:
		medium = 1
	}
	if len(found) > 0 && (strong+medium > 0 || others) {
		ev = append(ev, "next to the binary: "+strings.Join(found, ", "))
	}
	return strong, medium, ev
}

// ARTEXContainers reports the container names that follow ARTEX's compose
// or install naming, or nil.
func ARTEXContainers(names []string) *Detection {
	var hits []string
	seen := map[string]bool{}
	for _, entry := range names {
		for _, n := range strings.Split(entry, ",") {
			n = strings.TrimPrefix(strings.TrimSpace(n), "/")
			if n != "" && !seen[n] && isARTEXContainer(n) {
				seen[n] = true
				hits = append(hits, n)
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Strings(hits)
	return &Detection{Rule: RuleARTEX, Severity: High, Title: "ARTEX containers running",
		AgentID: artexBinary, Evidence: []string{"containers: " + joinCapped(hits, 5)}}
}

// isARTEXContainer matches "artex", a name starting "artex-" or "artex_"
// (compose project artex, artex-bench, artex-pg), or a compose replica of
// the service artex in any project ("<project>-artex-<n>").
func isARTEXContainer(name string) bool {
	n := strings.ToLower(name)
	if n == artexBinary || strings.HasPrefix(n, "artex-") || strings.HasPrefix(n, "artex_") {
		return true
	}
	i := strings.LastIndexAny(n, "-_")
	if i <= 0 || i == len(n)-1 || strings.Trim(n[i+1:], "0123456789") != "" {
		return false
	}
	rest := n[:i]
	return strings.HasSuffix(rest, "-artex") || strings.HasSuffix(rest, "_artex")
}

// Container runtimes Containers asks, and how. Variables so tests can fake
// them.
var (
	containerRuntimes = []string{"docker", "podman"}
	lookPath          = exec.LookPath
	runCommand        = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		// A child the runtime leaves behind can hold stdout open after
		// the deadline kills the runtime; stop waiting for it.
		cmd.WaitDelay = time.Second
		return cmd.Output()
	}
)

// Containers lists running container names from docker and podman (each
// only when installed), within 5 seconds. It returns nil on any error.
func Containers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out []string
	for _, rt := range containerRuntimes {
		path, err := lookPath(rt)
		if err != nil {
			continue
		}
		b, err := runCommand(ctx, path, "ps", "--format", "{{.Names}}")
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}
