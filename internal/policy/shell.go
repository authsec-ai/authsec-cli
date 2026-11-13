package policy

import (
	"bytes"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A command line is decided per simple command, the way a shell runs it:
// "cd x && git push --force" is two commands, and the second is denied
// whatever the first is. Each simple command gives:
//
//   - deny candidates: every form a deny or ask rule should see (with and
//     without wrappers such as sudo or env, the program's base name,
//     canonical git and rm forms);
//   - one allow form: the command after only harmless wrappers (env,
//     nice, timeout, ...) are removed. sudo stays, so "git status*" does
//     not allow "sudo git status".
//
// A line is allowed by rule only if every simple command in it is.

type simpleCmd struct {
	deny  []string
	allow string // "" when the command needs no allow of its own (sh -c: its inner commands do)
}

type parsedLine struct {
	cmds  []simpleCmd
	pipes []string // whole pipelines, for rules such as "curl *|*sh"
}

const maxShellDepth = 4

// parseLine parses a shell command line. ok is false when it does not parse.
func parseLine(line string) (parsedLine, bool) {
	var out parsedLine
	return out, parseInto(&out, line, 0)
}

func parseInto(out *parsedLine, line string, depth int) bool {
	if depth > maxShellDepth {
		return false
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(line), "")
	if err != nil {
		return false
	}
	ok := true
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CallExpr:
			if len(x.Args) > 0 && !literalWord(x.Args[0]) {
				// The program name comes from an expansion ($cmd, $(...)):
				// what runs cannot be known from the text.
				ok = false
				return true
			}
			argv := make([]string, 0, len(x.Args))
			for _, w := range x.Args {
				argv = append(argv, wordString(w))
			}
			if len(argv) > 0 && !addArgv(out, argv, depth) {
				ok = false
			}
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				var stages []string
				collectPipe(x, &stages)
				if len(stages) > 1 {
					out.pipes = append(out.pipes, strings.Join(stages, " | "))
				}
			}
		}
		return true
	})
	return ok
}

// collectPipe lists the stages of a pipeline in order, each in its
// innermost normal form.
func collectPipe(b *syntax.BinaryCmd, stages *[]string) {
	for _, st := range []*syntax.Stmt{b.X, b.Y} {
		if st == nil {
			continue
		}
		switch c := st.Cmd.(type) {
		case *syntax.BinaryCmd:
			if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
				collectPipe(c, stages)
				continue
			}
			*stages = append(*stages, "?")
		case *syntax.CallExpr:
			argv := make([]string, 0, len(c.Args))
			for _, w := range c.Args {
				argv = append(argv, wordString(w))
			}
			inner, _ := unwrap(argv, false)
			*stages = append(*stages, strings.Join(inner, " "))
		default:
			*stages = append(*stages, "?")
		}
	}
}

// literalWord reports whether a word is plain text (quotes allowed, no
// expansions).
func literalWord(w *syntax.Word) bool {
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, q := range x.Parts {
				if _, ok := q.(*syntax.Lit); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// wordString renders a word as the shell would before expansion: quotes
// removed, parameters and substitutions kept as written.
func wordString(w *syntax.Word) string {
	var b strings.Builder
	for _, p := range w.Parts {
		writePart(&b, p)
	}
	return b.String()
}

func writePart(b *strings.Builder, p syntax.WordPart) {
	switch x := p.(type) {
	case *syntax.Lit:
		b.WriteString(x.Value)
	case *syntax.SglQuoted:
		b.WriteString(x.Value)
	case *syntax.DblQuoted:
		for _, q := range x.Parts {
			writePart(b, q)
		}
	default:
		var buf bytes.Buffer
		_ = syntax.NewPrinter().Print(&buf, x)
		b.WriteString(buf.String())
	}
}

// DecideArgv decides a program run with these arguments (an exec seen by
// the sensor): the same rules as a command line, without shell parsing of
// the arguments themselves.
func (p *Policy) DecideArgv(argv []string) Decision {
	if len(argv) == 0 {
		return Decision{orAllow(p.Commands.Default), "commands.default"}
	}
	var pl parsedLine
	if !addArgv(&pl, argv, 0) {
		return p.unparsed()
	}
	return p.decideParsed(pl)
}

// addArgv adds one simple command (and, for sh -c, the commands inside).
func addArgv(out *parsedLine, argv []string, depth int) bool {
	argv = append([]string(nil), argv...)
	argv[0] = baseProgram(argv[0])
	var c simpleCmd
	c.deny = append(c.deny, strings.Join(argv, " "))
	allowArgv, _ := unwrap(argv, true)
	c.allow = strings.Join(allowArgv, " ")
	inner, script := unwrap(argv, false)
	if script != "" {
		// sh -c 'script': the script's commands are decided themselves.
		if !parseInto(out, script, depth+1) {
			return false
		}
		c.allow = ""
	}
	if len(inner) > 0 {
		c.deny = append(c.deny, strings.Join(inner, " "))
		c.deny = append(c.deny, canonical(inner)...)
	}
	out.cmds = append(out.cmds, c)
	return true
}

var (
	benignWrappers = map[string]bool{"env": true, "command": true, "nice": true, "ionice": true, "timeout": true, "time": true, "nohup": true, "exec": true, "stdbuf": true, "builtin": true}
	privWrappers   = map[string]bool{"sudo": true, "doas": true, "su": false, "xargs": true, "watch": true, "flock": false}
	shellNames     = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true}
)

// unwrap removes leading wrapper programs. With benignOnly, it stops at the
// first privilege wrapper (sudo, doas, xargs). script is the -c argument of
// a shell, when the command is one.
func unwrap(argv []string, benignOnly bool) (out []string, script string) {
	for guard := 0; guard < 8 && len(argv) > 0; guard++ {
		prog := baseProgram(argv[0])
		switch {
		case benignWrappers[prog]:
			argv = skipWrapperArgs(prog, argv[1:])
		case privWrappers[prog] && !benignOnly:
			argv = skipWrapperArgs(prog, argv[1:])
		case shellNames[prog]:
			for i := 1; i < len(argv); i++ {
				a := argv[i]
				if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "c") {
					if i+1 < len(argv) {
						return argv, argv[i+1]
					}
					return argv, ""
				}
				if !strings.HasPrefix(a, "-") {
					break
				}
			}
			return argv, ""
		default:
			if len(argv) > 0 {
				argv = append([]string{baseProgram(argv[0])}, argv[1:]...)
			}
			return argv, ""
		}
	}
	return argv, ""
}

// skipWrapperArgs drops a wrapper's own options and operands (env's
// VAR=val, nice -n N, timeout DURATION, sudo -u USER).
func skipWrapperArgs(prog string, args []string) []string {
	withValue := map[string]map[string]bool{
		"env":     {"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true},
		"nice":    {"-n": true, "--adjustment": true},
		"ionice":  {"-c": true, "-n": true, "-p": true},
		"timeout": {"-s": true, "--signal": true, "-k": true, "--kill-after": true},
		"sudo":    {"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-r": true, "-t": true, "-U": true, "-D": true},
		"doas":    {"-u": true, "-C": true},
		"stdbuf":  {"-i": true, "-o": true, "-e": true},
		"xargs":   {"-I": true, "-n": true, "-P": true, "-L": true, "-d": true, "-E": true, "-s": true, "-a": true},
		"watch":   {"-n": true, "-d": false},
		"flock":   {},
	}[prog]
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--":
			i++
			goto done
		case strings.HasPrefix(a, "-"):
			if withValue[a] && !strings.Contains(a, "=") {
				i += 2
			} else {
				i++
			}
		case prog == "env" && strings.Contains(a, "="):
			i++
		case prog == "timeout":
			i++ // the duration
			goto done
		default:
			goto done
		}
	}
done:
	if i > len(args) {
		i = len(args)
	}
	return args[i:]
}

// canonical gives extra forms of well-known commands so simple rules catch
// their variants: git without its global options, rm with its recursive and
// force flags written as -rf, one form per target.
func canonical(argv []string) []string {
	if sub, ok := strings.CutPrefix(argv[0], "git-"); ok && sub != "" {
		// git-push is git push (git's dashed form, still installed).
		argv = append([]string{"git", sub}, argv[1:]...)
		return append([]string{strings.Join(argv, " ")}, canonical(argv)...)
	}
	switch argv[0] {
	case "git":
		rest := argv[1:]
		aliases := map[string]string{}
		for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
			switch rest[0] {
			case "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path":
				if len(rest) > 1 {
					if rest[0] == "-c" {
						if k, v, ok := strings.Cut(rest[1], "="); ok && strings.HasPrefix(strings.ToLower(k), "alias.") {
							aliases[strings.ToLower(strings.TrimPrefix(k, k[:6]))] = v
						}
					}
					rest = rest[2:]
					continue
				}
			}
			rest = rest[1:]
		}
		var out []string
		if len(rest) < len(argv)-1 {
			out = append(out, strings.Join(append([]string{"git"}, rest...), " "))
		}
		// git -c alias.p='push --force' p: the alias is what runs.
		if len(rest) > 0 {
			if v, ok := aliases[strings.ToLower(rest[0])]; ok {
				v = strings.TrimPrefix(v, "!")
				out = append(out, strings.Join(append([]string{"git", v}, rest[1:]...), " "), strings.Join(append([]string{v}, rest[1:]...), " "))
			}
		}
		return out
	case "rm":
		var recursive, force bool
		var targets []string
		for _, a := range argv[1:] {
			switch {
			case a == "--recursive":
				recursive = true
			case a == "--force":
				force = true
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
				recursive = recursive || strings.ContainsAny(a, "rR")
				force = force || strings.Contains(a, "f")
			case !strings.HasPrefix(a, "-"):
				targets = append(targets, a)
			}
		}
		if recursive && force {
			var out []string
			for _, t := range targets {
				out = append(out, "rm -rf "+t)
			}
			return out
		}
	}
	return nil
}

func baseProgram(p string) string {
	if strings.ContainsAny(p, `/\`) {
		return filepath.Base(strings.ReplaceAll(p, `\`, "/"))
	}
	return p
}

func (p *Policy) unparsed() Decision {
	if orAllow(p.Commands.Default) == Allow {
		return Decision{Ask, "commands (the line could not be parsed)"}
	}
	return Decision{Deny, "commands (the line could not be parsed)"}
}

// decideParsed applies the rules: any part matching deny denies, any part
// matching ask asks, and the line is allowed by rule only when every part
// matches an allow rule. Deny and ask ignore case (DROP TABLE, drop table).
func (p *Policy) decideParsed(pl parsedLine) Decision {
	cands := append([]string(nil), pl.pipes...)
	for _, c := range pl.cmds {
		cands = append(cands, c.deny...)
	}
	for i, pat := range p.Commands.Deny {
		for _, c := range cands {
			if globMatch(pat, c, true) {
				return Decision{Deny, ruleName("commands.deny", i)}
			}
		}
	}
	for i, pat := range p.Commands.Ask {
		for _, c := range cands {
			if globMatch(pat, c, true) {
				return Decision{Ask, ruleName("commands.ask", i)}
			}
		}
	}
	if len(p.Commands.Allow) > 0 && len(pl.cmds) > 0 {
		rule := ""
		all := true
		for _, c := range pl.cmds {
			if c.allow == "" {
				continue
			}
			matched := false
			for i, pat := range p.Commands.Allow {
				if globMatch(pat, c.allow, false) {
					matched, rule = true, ruleName("commands.allow", i)
					break
				}
			}
			if !matched {
				all = false
				break
			}
		}
		if all && rule != "" {
			return Decision{Allow, rule}
		}
	}
	return Decision{orAllow(p.Commands.Default), "commands.default"}
}

func ruleName(list string, i int) string { return list + "[" + itoa(i) + "]" }
