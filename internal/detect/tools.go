package detect

import "strings"

// offensiveTools are scanners, fuzzers, crackers, exploitation frameworks
// and tunnelling tools, by base name. ARTEX's image installs nmap, nuclei,
// httpx, subfinder, katana, ffuf, dalfox, sqlmap and bbot for its workers to
// run (Dockerfile; skills/bbot-recon/SKILL.md), so those are confirmed.
var offensiveTools = map[string]bool{
	"nmap": true, "masscan": true, "naabu": true,
	"sqlmap": true, "nuclei": true, "dalfox": true, "nikto": true,
	"ffuf": true, "gobuster": true, "feroxbuster": true, "dirb": true, "dirsearch": true, "wfuzz": true,
	"hydra": true, "medusa": true, "john": true, "hashcat": true,
	"msfconsole": true, "msfvenom": true,
	"crackmapexec": true, "netexec": true, "nxc": true, "responder": true,
	"chisel": true, "ligolo": true,
	"subfinder": true, "amass": true, "katana": true, "bbot": true,
	"httpx": true, // ProjectDiscovery's httpx only: see isPDHttpx
}

// offensivePrefixes match tool families by name prefix (ligolo-ng builds,
// Debian's impacket-* commands).
var offensivePrefixes = []string{"ligolo-", "ligolo_", "impacket-"}

// maxFamilySuffix bounds the part of a family name reported after its
// prefix; a longer one is reported as the family alone, so a long word that
// is not a program name (a token, say) never reaches the output.
const maxFamilySuffix = 32

// homonyms are ordinary programs named like a tool, told apart by their
// first argument:
//   - Ory Hydra, an OAuth2 server AuthSec itself runs (command names from
//     github.com/ory/hydra cmd/). THC Hydra parses short options only
//     (hydra.c getopt), so a leading long option also means Ory.
//   - Canonical's chisel, which cuts Ubuntu package slices
//     (github.com/canonical/chisel cmd/chisel/). jpillora's chisel, the
//     tunnel, takes "server" or "client".
var homonyms = map[string]map[string]bool{
	"hydra": {"serve": true, "migrate": true, "janitor": true, "create": true, "delete": true,
		"get": true, "import": true, "introspect": true, "list": true, "perform": true,
		"revoke": true, "update": true, "version": true, "help": true, "completion": true},
	"chisel": {"cut": true, "find": true, "info": true, "debug": true, "help": true, "version": true},
}

// impacketScripts are Impacket example scripts. They match only as a .py
// script or an impacket.* module (PsExec.exe is Sysinternals' tool), and
// report as "impacket-<name>".
var impacketScripts = map[string]bool{
	"secretsdump": true, "psexec": true, "wmiexec": true, "smbexec": true, "atexec": true, "dcomexec": true,
	"ntlmrelayx": true, "getuserspns": true, "getnpusers": true, "gettgt": true, "getst": true,
}

// pdHttpxFlags are flags of ProjectDiscovery's httpx that the Python httpx
// command line does not have. Without one, "httpx" is not a match: the
// Python package installs a CLI of the same name.
var pdHttpxFlags = map[string]bool{
	"l": true, "list": true, "u": true, "target": true, "sc": true, "status-code": true,
	"title": true, "td": true, "tech-detect": true, "silent": true, "probe": true,
	"cl": true, "content-length": true, "ct": true, "content-type": true, "ip": true,
	"cname": true, "cdn": true, "asn": true, "mc": true, "fc": true, "ports": true,
	"path": true, "jsonl": true, "threads": true, "rl": true, "rate-limit": true,
	"screenshot": true, "favicon": true, "jarm": true, "tls-grab": true, "vhost": true,
	"sr": true, "store-response": true, "web-server": true,
}

// scriptExts are stripped from a script's name before the lookup.
var scriptExts = []string{".py", ".pl", ".rb", ".sh"}

// Option flags that take a separate value, per wrapper.
var (
	sudoArgFlags = map[string]bool{"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true,
		"-r": true, "-t": true, "-U": true, "-T": true, "-R": true, "--user": true, "--group": true,
		"--host": true, "--prompt": true, "--close-from": true, "--chdir": true, "--role": true,
		"--type": true, "--other-user": true, "--command-timeout": true, "--chroot": true}
	timeoutArgFlags = map[string]bool{"-s": true, "-k": true, "--signal": true, "--kill-after": true}
	wrapperArgFlags = map[string]bool{"-n": true, "--adjustment": true, "-f": true, "-i": true, "-o": true, "-e": true}
	envArgFlags     = map[string]bool{"-u": true, "--unset": true, "-C": true, "--chdir": true}
	execArgFlags    = map[string]bool{"-a": true}
	shellArgFlags   = map[string]bool{"-o": true, "+o": true, "-O": true, "+O": true, "--rcfile": true, "--init-file": true}
)

// Interpreter options, per family: those that take a separate value, and
// those that run inline code (which is not checked).
var (
	interpreterArgFlags = map[string]map[string]bool{
		"python": {"-W": true, "-X": true, "--check-hash-based-pycs": true},
		"perl":   {"-I": true},
		"ruby":   {"-I": true, "-r": true, "-C": true, "-E": true},
	}
	interpreterCodeFlags = map[string]map[string]bool{
		"python": {"-c": true},
		"perl":   {"-e": true, "-E": true},
		"ruby":   {"-e": true},
	}
)

// maxDepth bounds how many wrappers and shells are looked through.
const maxDepth = 6

// OffensiveTool reports whether argv runs a known offensive security tool,
// and which. It looks through sudo, doas, env, timeout, nice, nohup,
// proxychains, `sh -c` and `cmd /c` command strings and interpreters
// running a tool script ("python3 sqlmap.py"). Only a tool name is returned, never an
// argument.
func OffensiveTool(argv []string) (tool string, ok bool) {
	return offensiveTool(argv, 0)
}

func offensiveTool(argv []string, depth int) (string, bool) {
	if len(argv) == 0 || depth > maxDepth {
		return "", false
	}
	base := baseName(argv[0])
	name := stripScriptExt(base)
	rest := argv[1:]
	switch {
	case name == "sudo" || name == "doas":
		return offensiveTool(skipOptions(rest, sudoArgFlags, true), depth+1)
	case name == "env":
		return envTool(rest, depth)
	case name == "exec":
		return offensiveTool(skipOptions(rest, execArgFlags, false), depth+1)
	case name == "timeout":
		args := skipOptions(rest, timeoutArgFlags, false)
		if len(args) == 0 {
			return "", false
		}
		return offensiveTool(args[1:], depth+1) // args[0] is the duration
	case name == "nice" || name == "nohup" || name == "proxychains" || name == "proxychains4" ||
		name == "time" || name == "stdbuf":
		return offensiveTool(skipOptions(rest, wrapperArgFlags, false), depth+1)
	case isShell(name):
		return shellTool(rest, depth)
	case name == "cmd":
		return cmdTool(rest, depth)
	case interpreterFamily(name) != "":
		return interpreterTool(interpreterFamily(name), rest)
	}
	return lookup(base, rest, false)
}

// lookup finds a tool by its lowercased base name (with any script
// extension). args decide httpx; run by an interpreter, httpx is Python's
// library and never a tool.
func lookup(base string, args []string, interpreted bool) (string, bool) {
	name := stripScriptExt(base)
	if name == "httpx" {
		return name, !interpreted && isPDHttpx(args)
	}
	if offensiveTools[name] {
		return name, !isHomonym(name, args)
	}
	for _, p := range offensivePrefixes {
		if suffix, ok := strings.CutPrefix(name, p); ok && suffix != "" {
			return familyName(p, suffix)
		}
	}
	if impacketScripts[name] && strings.HasSuffix(base, ".py") {
		return "impacket-" + name, true
	}
	return "", false
}

// isHomonym reports whether args show an ordinary program of the tool's
// name (see homonyms).
func isHomonym(name string, args []string) bool {
	cmds := homonyms[name]
	if cmds == nil || len(args) == 0 {
		return false
	}
	a := strings.ToLower(args[0])
	if name == "hydra" && strings.HasPrefix(a, "--") && len(a) > 2 {
		return true
	}
	return cmds[a]
}

// familyName names a match of a tool family prefix. The suffix must look
// like part of a program name; one too long is dropped.
func familyName(prefix, suffix string) (string, bool) {
	for _, c := range suffix {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "", false
		}
	}
	if len(suffix) > maxFamilySuffix {
		return strings.TrimRight(prefix, "-_"), true
	}
	return prefix + suffix, true
}

// isPDHttpx reports whether args carry a flag only ProjectDiscovery's httpx
// has.
func isPDHttpx(args []string) bool {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		f := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(f, '='); i >= 0 {
			f = f[:i]
		}
		if pdHttpxFlags[f] {
			return true
		}
	}
	return false
}

// skipOptions drops leading options (and the values of argFlags) up to
// "--" and, when assigns, NAME=VALUE words.
func skipOptions(args []string, argFlags map[string]bool, assigns bool) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return args[i+1:]
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if argFlags[a] {
				i++
			}
		case assigns && isAssign(a):
		default:
			return args[i:]
		}
	}
	return nil
}

// envTool looks through env's options and assignments; -S splits its
// string into words.
func envTool(args []string, depth int) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-S" || a == "--split-string":
			if i+1 < len(args) {
				return offensiveTool(append(strings.Fields(args[i+1]), args[i+2:]...), depth+1)
			}
			return "", false
		case strings.HasPrefix(a, "--split-string="):
			words := strings.Fields(strings.TrimPrefix(a, "--split-string="))
			return offensiveTool(append(words, args[i+1:]...), depth+1)
		case a == "--":
			return offensiveTool(skipOptions(args[i+1:], nil, true), depth+1)
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if envArgFlags[a] {
				i++
			}
		case isAssign(a):
		default:
			return offensiveTool(args[i:], depth+1)
		}
	}
	return "", false
}

// isAssign reports whether a is NAME=VALUE with a shell variable name.
func isAssign(a string) bool {
	i := strings.IndexByte(a, '=')
	if i <= 0 {
		return false
	}
	for j, c := range a[:i] {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || j > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func isShell(name string) bool {
	switch name {
	case "sh", "bash", "zsh", "dash", "ksh", "ash", "busybox":
		return true
	}
	return false
}

// shellTool checks the command string of `sh -c`. A script file is not
// read.
func shellTool(args []string, depth int) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case i == 0 && isShell(a): // busybox sh -c
		case shellArgFlags[a]:
			i++
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") && strings.Contains(a, "c"):
			if i+1 < len(args) {
				return commandString(args[i+1], depth)
			}
			return "", false
		case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+"):
		default:
			return "", false
		}
	}
	return "", false
}

// commandString checks each simple command of a shell command string.
// Words are split on spaces and quotes are trimmed, not parsed.
func commandString(s string, depth int) (string, bool) {
	for _, sep := range []string{"&&", "||", ";", "|", "&", "\n", "(", ")", "`"} {
		s = strings.ReplaceAll(s, sep, "\x00")
	}
	for _, cmd := range strings.Split(s, "\x00") {
		var words []string
		for _, w := range strings.Fields(cmd) {
			if w = strings.Trim(w, `"'{}`); w != "" && (len(words) > 0 || !isAssign(w)) {
				words = append(words, w)
			}
		}
		if tool, ok := offensiveTool(words, depth+1); ok {
			return tool, true
		}
	}
	return "", false
}

// cmdTool checks the command line of Windows' `cmd /c` (or /k, /r).
func cmdTool(args []string, depth int) (string, bool) {
	for i, a := range args {
		switch strings.ToLower(a) {
		case "/c", "/k", "/r":
			return commandString(strings.Join(args[i+1:], " "), depth)
		}
	}
	return "", false
}

// interpreterFamily returns "python" for python, python3, python3.12,
// pypy3 and py, "perl", "ruby", or "" for anything else.
func interpreterFamily(name string) string {
	switch name {
	case "py":
		return "python"
	case "perl", "ruby":
		return name
	}
	for _, p := range []string{"python", "pypy"} {
		if strings.HasPrefix(name, p) && strings.Trim(name[len(p):], "0123456789.") == "" {
			return "python"
		}
	}
	return ""
}

// interpreterTool checks the script or module an interpreter of family runs.
// Inline code (-c, -e) is not checked.
func interpreterTool(family string, args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case interpreterCodeFlags[family][a]:
			return "", false
		case a == "-m" && family == "python":
			if i+1 >= len(args) {
				return "", false
			}
			return lookup(moduleBase(args[i+1]), args[i+2:], true)
		case interpreterArgFlags[family][a]:
			i++
		case a == "--":
			if i+1 < len(args) {
				return lookup(baseName(args[i+1]), args[i+2:], true)
			}
			return "", false
		case strings.HasPrefix(a, "-"):
		default:
			return lookup(baseName(a), args[i+1:], true)
		}
	}
	return "", false
}

// moduleBase names a Python module like a script: impacket.examples.X is
// "x.py", any other module its top-level package ("sqlmap").
func moduleBase(mod string) string {
	parts := strings.Split(strings.ToLower(mod), ".")
	if len(parts) > 1 && parts[0] == "impacket" {
		return parts[len(parts)-1] + ".py"
	}
	return parts[0]
}

// stripScriptExt drops a script extension from a base name.
func stripScriptExt(name string) string {
	for _, e := range scriptExts {
		if strings.HasSuffix(name, e) && len(name) > len(e) {
			return strings.TrimSuffix(name, e)
		}
	}
	return name
}
