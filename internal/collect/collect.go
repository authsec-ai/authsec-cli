// Package collect turns the catalogue's files into findings, one collector per
// tool. Collectors read only through env.Reader and keep only scrubbed values
// (package parse).
package collect

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/authsec-ai/authsec-cli/internal/catalogue"
	"github.com/authsec-ai/authsec-cli/internal/finding"
	"github.com/authsec-ai/authsec-cli/internal/fsread"
	"github.com/authsec-ai/authsec-cli/internal/parse"
)

// Env is what a scan runs against.
type Env struct {
	Cat      catalogue.Env
	Projects []string // absolute project directories to read per-project files from
	Reader   *fsread.Reader
	// LookPath finds an executable; nil means "not found". Injected so tests do
	// not depend on what is installed.
	LookPath func(name string) string
}

// Collector reads one tool's files.
type Collector interface {
	Tool() string        // tool id, e.g. claude-code
	DisplayName() string // e.g. Claude Code
	Collect(env *Env, out *Out)
}

// ProjectLister is a collector that knows which projects its tool has been
// used in (Claude Code and Codex keep a list). Those projects are scanned too.
type ProjectLister interface {
	KnownProjects(env *Env) []string
}

// All is every collector, in display order.
func All() []Collector {
	return []Collector{Claude{}, Codex{}, vscode, cursor, gemini, claudeDesktop, windsurf}
}

// DisplayName returns the human name of a tool id.
func DisplayName(tool string) string {
	for _, c := range All() {
		if c.Tool() == tool {
			return c.DisplayName()
		}
	}
	return tool
}

// Out accumulates findings.
type Out struct {
	Findings []finding.Finding
}

// Add records a finding.
func (o *Out) Add(f finding.Finding) {
	if f.Evidence == "" {
		f.Evidence = finding.Declared
	}
	o.Findings = append(o.Findings, f)
}

// Unreadable records a catalogue file that exists but could not be read or
// parsed: a gap in coverage is reported, never dropped.
func (o *Out) Unreadable(tool, rule, scope, path, project string, err error) {
	o.Add(finding.Finding{
		Kind: finding.Unreadable, Tool: tool, Name: filepath.Base(path), Scope: scope,
		Path: path, Project: project, Rule: rule,
		Attrs: map[string]any{"error": errString(err)},
	})
}

// readJSONC reads and decodes one catalogue file. ok is false when the file is
// absent (nothing to report) or unreadable (an Unreadable finding is added).
func readJSONC(env *Env, out *Out, tool, rule, scope, path, project string) (map[string]any, *fsread.File, bool) {
	f, err := env.Reader.ReadFile(path)
	if err != nil {
		if !fsread.IsNotExist(err) {
			out.Unreadable(tool, rule, scope, path, project, err)
		}
		return nil, nil, false
	}
	if len(bytes.TrimSpace(f.Data)) == 0 {
		return map[string]any{}, f, true // an empty file is an empty configuration (VS Code creates them)
	}
	m, err := parse.JSONC(f.Data)
	if err != nil {
		out.Unreadable(tool, rule, scope, path, project, fmt.Errorf("not valid JSON: %w", err))
		return nil, nil, false
	}
	return m, f, true
}

// DiscoverProjects returns the projects to scan: the ones given, plus those
// the tools list, deduplicated, existing, and never the home directory itself
// (its files are read as user scope).
func DiscoverProjects(env *Env, given []string, known bool) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		if seen[p] || p == filepath.Clean(env.Cat.Home) {
			return
		}
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range given {
		if abs, err := filepath.Abs(p); err == nil {
			add(abs)
		}
	}
	if known {
		for _, c := range All() {
			if l, ok := c.(ProjectLister); ok {
				for _, p := range l.KnownProjects(env) {
					add(p)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Run runs every collector and returns their findings.
func Run(env *Env, collectors []Collector) []finding.Finding {
	out := &Out{}
	for _, c := range collectors {
		c.Collect(env, out)
	}
	return out.Findings
}

// errString keeps error text short and free of file contents.
func errString(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
