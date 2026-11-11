package collect

import (
	"path/filepath"
	"strings"
)

// launch is how an MCP server's command fetches and runs its code.
type launch struct {
	Launcher string // npx, bunx, pnpm dlx, yarn dlx, uvx, docker
	Package  string // package or image
	Pinned   bool   // an exact version or digest was given
}

// analyzeLaunch recognises package runners that download code at start-up.
// For anything else (a local binary, node script.js) ok is false: there is no
// remote package to pin.
func analyzeLaunch(command string, args []string) (l launch, ok bool) {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(command, `\`, "/")))
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		base = strings.TrimSuffix(base, ext)
	}
	switch base {
	case "npx", "bunx":
		pkg := npmPackage(args)
		return launch{Launcher: base, Package: pkg, Pinned: npmPinned(pkg)}, pkg != ""
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			pkg := npmPackage(args[1:])
			return launch{Launcher: base + " dlx", Package: pkg, Pinned: npmPinned(pkg)}, pkg != ""
		}
	case "uvx", "pipx":
		a := args
		if base == "pipx" {
			if len(a) == 0 || a[0] != "run" {
				return l, false
			}
			a = a[1:]
		}
		pkg := firstPositional(a, map[string]bool{"--from": true, "--python": true, "--with": true, "--spec": true}, "--from", "--spec")
		return launch{Launcher: base, Package: pkg, Pinned: pyPinned(pkg)}, pkg != ""
	case "docker", "podman":
		if len(args) == 0 || args[0] != "run" {
			return l, false
		}
		img := firstPositional(args[1:], dockerValueFlags, "")
		return launch{Launcher: base, Package: img, Pinned: imagePinned(img)}, img != ""
	}
	return l, false
}

// npmPackage is the package npx runs: --package/-p if given, else the first
// argument that is not a flag.
func npmPackage(args []string) string {
	return firstPositional(args, map[string]bool{"-p": true, "--package": true, "--registry": true, "--cache": true}, "-p", "--package")
}

// firstPositional returns the first argument that is not a flag or a flag's
// value. When a flag in prefer appears, its value wins.
func firstPositional(args []string, valueFlags map[string]bool, prefer ...string) string {
	isPreferred := map[string]bool{}
	for _, p := range prefer {
		if p != "" {
			isPreferred[p] = true
		}
	}
	first := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			name, val, hasVal := strings.Cut(a, "=")
			if isPreferred[name] {
				if hasVal {
					return val
				}
				if i+1 < len(args) {
					return args[i+1]
				}
			}
			if !hasVal && valueFlags[name] {
				i++
			}
			continue
		}
		if first == "" {
			first = a
		}
	}
	return first
}

func npmPinned(pkg string) bool {
	name := strings.TrimPrefix(pkg, "@")
	at := strings.LastIndex(name, "@")
	if at <= 0 {
		return false
	}
	v := name[at+1:]
	return v != "" && v != "latest" && v != "next" && v != "*" && !strings.ContainsAny(v[:1], "^~><")
}

func pyPinned(pkg string) bool {
	if i := strings.Index(pkg, "=="); i > 0 {
		return true
	}
	if i := strings.LastIndex(pkg, "@"); i > 0 {
		v := pkg[i+1:]
		return v != "" && v != "latest"
	}
	return false
}

func imagePinned(img string) bool {
	if strings.Contains(img, "@sha256:") {
		return true
	}
	last := img[strings.LastIndex(img, "/")+1:]
	i := strings.LastIndex(last, ":")
	return i > 0 && last[i+1:] != "latest"
}

var dockerValueFlags = map[string]bool{
	"-e": true, "--env": true, "--env-file": true, "-v": true, "--volume": true, "--mount": true,
	"-p": true, "--publish": true, "--name": true, "--network": true, "--net": true, "-w": true,
	"--workdir": true, "--entrypoint": true, "-u": true, "--user": true, "-l": true, "--label": true,
	"--platform": true, "-h": true, "--hostname": true, "--add-host": true, "--cap-add": true,
	"--cap-drop": true, "--memory": true, "-m": true, "--cpus": true, "--pull": true, "--restart": true,
}
