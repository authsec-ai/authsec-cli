// Package finding is the one record every collector produces and every
// output (table, JSON, SARIF, push) reads.
package finding

import (
	"fmt"
	"path/filepath"
	"sort"
)

// Kind is what a finding is about.
type Kind string

const (
	Agent      Kind = "agent"            // an AI agent or assistant on the machine
	Policy     Kind = "agent_policy"     // what an agent may do without a human
	Extension  Kind = "agent_extension"  // hooks, skills, sub-agents, commands
	MCPServer  Kind = "mcp_server"       // a tool server an agent loads
	Identity   Kind = "identity"         // a credential source an agent can reach
	SecretRef  Kind = "secret_reference" // a credential NAME where agents read it
	Unreadable Kind = "unreadable"       // a catalogue file that could not be parsed
)

// Kinds lists every kind in display order.
func Kinds() []Kind {
	return []Kind{Agent, Policy, Extension, MCPServer, Identity, SecretRef, Unreadable}
}

// Scope says whose configuration a finding comes from.
const (
	ScopeUser    = "user"    // the user's own settings, every project
	ScopeProject = "project" // checked into a project, shared with its team
	ScopeLocal   = "local"   // per project, but only for this user
	ScopeManaged = "managed" // set by an administrator for the machine
)

// Evidence says how a finding was seen.
const (
	Declared = "declared" // in a configuration file
	Observed = "observed" // a running process
)

// Signal is one risk hint on a finding, with the reason it fired.
type Signal struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Finding is one row of a report. Attrs never hold a secret value: collectors
// put only names, shapes and scrubbed text in it (package parse).
type Finding struct {
	Fingerprint string         `json:"fingerprint"`
	Kind        Kind           `json:"kind"`
	Tool        string         `json:"tool"`
	Name        string         `json:"name"`
	Scope       string         `json:"scope"`
	Path        string         `json:"path"`
	Project     string         `json:"project,omitempty"`
	Evidence    string         `json:"evidence"`
	Rule        string         `json:"rule"`
	Attrs       map[string]any `json:"attrs,omitempty"`
	Signals     []Signal       `json:"signals,omitempty"`
	FileSHA256  string         `json:"file_sha256,omitempty"`
}

// SetFingerprint gives the finding its stable id on this machine:
// host:{machine}:{kind}:{tool}:{path}#{name}[@{project}]. The same file and
// name give the same id on every run, so an item that disappears is "gone".
func (f *Finding) SetFingerprint(machineID string) {
	fp := fmt.Sprintf("host:%s:%s:%s:%s#%s", machineID, f.Kind, f.Tool, filepath.ToSlash(f.Path), f.Name)
	if f.Project != "" {
		fp += "@" + filepath.ToSlash(f.Project)
	}
	f.Fingerprint = fp
}

// AddSignal records a signal once; a second reason for the same id is kept
// only if the first was empty.
func (f *Finding) AddSignal(id, reason string) {
	for i, s := range f.Signals {
		if s.ID == id {
			if s.Reason == "" {
				f.Signals[i].Reason = reason
			}
			return
		}
	}
	f.Signals = append(f.Signals, Signal{ID: id, Reason: reason})
}

// HasSignal reports whether the finding carries signal id.
func (f *Finding) HasSignal(id string) bool {
	for _, s := range f.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}

// Sort orders findings for stable output: tool, kind, path, project, name.
func Sort(fs []Finding) {
	order := map[Kind]int{}
	for i, k := range Kinds() {
		order[k] = i
	}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		switch {
		case a.Tool != b.Tool:
			return a.Tool < b.Tool
		case a.Kind != b.Kind:
			return order[a.Kind] < order[b.Kind]
		case a.Path != b.Path:
			return a.Path < b.Path
		case a.Project != b.Project:
			return a.Project < b.Project
		default:
			return a.Name < b.Name
		}
	})
}
