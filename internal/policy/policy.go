// Package policy is the agent policy: a YAML file per agent saying where it
// may connect, which files it may touch, which commands it may run and which
// MCP servers it may load. Policies are generated from what an agent was
// seen doing (Generate), edited by people (vi), checked (Load, Validate,
// Simulate) and enforced (Decide*, used by `enforce`).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// API version and kind of a policy file.
const (
	APIVersion = "authsec.ai/v1"
	Kind       = "AgentPolicy"
)

// Modes.
const (
	Monitor = "monitor" // decisions are logged, nothing is blocked
	Enforce = "enforce" // denied actions are blocked
)

// Actions.
const (
	Allow = "allow"
	Deny  = "deny"
	Ask   = "ask" // commands: a person must approve
)

// AnyAgent is the agent id of the default policy, applied to agents that
// have no policy of their own (unknown agents included).
const AnyAgent = "*"

// Policy is one agent's policy file.
type Policy struct {
	APIVersion string     `yaml:"apiVersion"`
	Kind       string     `yaml:"kind"`
	Agent      AgentRef   `yaml:"agent"`
	Mode       string     `yaml:"mode"`
	Network    Network    `yaml:"network"`
	Filesystem Filesystem `yaml:"filesystem"`
	Commands   Commands   `yaml:"commands"`
	MCPServers MCPServers `yaml:"mcp_servers"`

	// confined is set by Expand when the policy had path lists, even if
	// none is left after expansion ({project} without a project): such a
	// policy must not fall back to "no path lists, allow everything".
	confined bool
}

// AgentRef names the agent a policy applies to: a recogniser id
// (claude-code, codex, unknown, ...) or "*" for every agent without a policy.
type AgentRef struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name,omitempty"`
}

// Network says where the agent may connect. Deny rules win over allow rules;
// a destination matching neither gets Default.
type Network struct {
	Default string `yaml:"default"`
	Allow   []Rule `yaml:"allow,omitempty"`
	Deny    []Rule `yaml:"deny,omitempty"`
}

// Rule matches a destination by host name (exact, or "*.example.com" for
// any subdomain) or by address range, and optionally by port (0: any).
type Rule struct {
	Host string `yaml:"host,omitempty"`
	CIDR string `yaml:"cidr,omitempty"`
	Port int    `yaml:"port,omitempty"`
}

// Filesystem lists paths by prefix. {home} and {project} are expanded when
// the policy is applied. Deny wins; when ReadWrite or ReadOnly is set, other
// paths are outside the policy (system paths are always readable).
type Filesystem struct {
	ReadWrite []string `yaml:"read_write,omitempty"`
	ReadOnly  []string `yaml:"read_only,omitempty"`
	Deny      []string `yaml:"deny,omitempty"`
}

// Commands are shell command patterns: '*' matches any text, including
// spaces; '\*' is a literal star. A command line is split into the simple
// commands a shell would run (&&, ;, |, $(...), sh -c '...'), wrappers such
// as env, nice and sudo are looked through, and program paths are reduced to
// their names. Deny and ask rules match any part, ignoring case; allow rules
// must match every part. Deny wins over ask, ask over allow; others get
// Default.
type Commands struct {
	Default string   `yaml:"default"`
	Allow   []string `yaml:"allow,omitempty"`
	Ask     []string `yaml:"ask,omitempty"`
	Deny    []string `yaml:"deny,omitempty"`
}

// MCPServers lists MCP servers by name ('*' patterns allowed).
type MCPServers struct {
	Default string   `yaml:"default"`
	Allow   []string `yaml:"allow,omitempty"`
	Deny    []string `yaml:"deny,omitempty"`
}

// Issue is a problem found in a policy file. Errors make the policy
// unusable; warnings are shown and the policy still applies.
type Issue struct {
	Line    int    `json:"line,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Warning bool   `json:"warning,omitempty"`
}

func (i Issue) String() string {
	level := "error"
	if i.Warning {
		level = "warning"
	}
	loc := ""
	if i.Line > 0 {
		loc = fmt.Sprintf("line %d: ", i.Line)
	}
	if i.Field != "" {
		loc += i.Field + ": "
	}
	return fmt.Sprintf("%s: %s%s", level, loc, i.Message)
}

// File is a loaded policy file.
type File struct {
	Path   string
	Policy *Policy // nil if the file could not be parsed
	Issues []Issue
}

// OK reports whether the file has no errors.
func (f *File) OK() bool {
	if f.Policy == nil {
		return false
	}
	for _, i := range f.Issues {
		if !i.Warning {
			return false
		}
	}
	return true
}

// Parse reads and validates one policy document.
func Parse(data []byte) (*Policy, []Issue) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, yamlIssues(err, data)
	}
	if len(root.Content) == 0 {
		return nil, []Issue{{Message: "empty file"}}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a misspelled key is an error, not silently ignored
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, yamlIssues(err, data)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		line := extra.Line
		if err != nil {
			line = 0
		}
		return nil, []Issue{{Line: line, Message: "more than one YAML document (---): a policy file holds one policy"}}
	}
	l := &lines{root.Content[0]}
	issues := wholeNumberPorts(l)
	issues = append(issues, p.validate(l)...)
	return &p, issues
}

// wholeNumberPorts rejects ports that YAML reads as decimals (80.9 would
// otherwise become 80).
func wholeNumberPorts(l *lines) []Issue {
	var out []Issue
	for _, list := range []string{"allow", "deny"} {
		seq := l.node("network", list)
		if seq == nil || seq.Kind != yaml.SequenceNode {
			continue
		}
		for i, item := range seq.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(item.Content); j += 2 {
				if k, v := item.Content[j], item.Content[j+1]; k.Value == "port" && v.ShortTag() != "!!int" {
					out = append(out, Issue{Line: v.Line, Field: fmt.Sprintf("network.%s[%d]", list, i),
						Message: fmt.Sprintf("port %s must be a whole number", v.Value)})
				}
			}
		}
	}
	return out
}

// Load reads and validates a policy file.
func Load(path string) *File {
	f := &File{Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		f.Issues = []Issue{{Message: err.Error()}}
		return f
	}
	f.Policy, f.Issues = Parse(data)
	return f
}

// LoadDir loads every *.yaml and *.yml file of a directory, sorted by name.
// Two files for the same agent are an error on the second.
func LoadDir(dir string) ([]*File, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []*File
	seen := map[string]string{}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || !(strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			continue
		}
		f := Load(filepath.Join(dir, n))
		if f.Policy != nil {
			id := f.Policy.Agent.ID
			if prev, ok := seen[id]; ok {
				f.Issues = append(f.Issues, Issue{Field: "agent.id", Message: fmt.Sprintf("agent %q already has a policy in %s", id, prev)})
			} else {
				seen[id] = n
			}
		}
		files = append(files, f)
	}
	return files, nil
}

// Set is the usable policies of a directory, by agent id, and the agents
// whose own policy file is broken.
type Set struct {
	ok     map[string]*Policy
	broken map[string]string // agent id -> file
	// unnamed is a file that did not parse, so its agent is unknown: it
	// may be any agent's policy (or the default), so no agent without a
	// usable policy of its own falls back to the default.
	unnamed string
}

// ErrBrokenPolicy is returned for an agent whose own policy has errors: it
// does not silently fall back to the default policy.
var ErrBrokenPolicy = errors.New("the agent's policy file has errors")

// NewSet keeps the files without errors and remembers the broken ones (by
// agent id, or by file name when the file did not parse).
func NewSet(files []*File) Set {
	s := Set{ok: map[string]*Policy{}, broken: map[string]string{}}
	for _, f := range files {
		id := ""
		if f.Policy != nil {
			id = f.Policy.Agent.ID
		} else {
			id = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(f.Path), ".yaml"), ".yml")
			if !f.OK() && s.unnamed == "" {
				s.unnamed = f.Path
			}
		}
		if f.OK() {
			if _, dup := s.ok[id]; !dup {
				s.ok[id] = f.Policy
			}
		} else if _, good := s.ok[id]; !good {
			s.broken[id] = f.Path
		}
	}
	for id := range s.ok {
		delete(s.broken, id)
	}
	return s
}

// For returns the policy of an agent: its own, else the default ("*").
// An agent whose own file is broken gets ErrBrokenPolicy, not the default.
func (s Set) For(agentID string) (*Policy, error) {
	if p, ok := s.ok[agentID]; ok {
		return p, nil
	}
	if f, ok := s.broken[agentID]; ok {
		return nil, fmt.Errorf("%w: %s", ErrBrokenPolicy, f)
	}
	// Falling back to the default is safe only when the default is usable
	// and no broken file could be this agent's own policy.
	if f, ok := s.broken[AnyAgent]; ok {
		return nil, fmt.Errorf("%w: the default policy %s", ErrBrokenPolicy, f)
	}
	if s.unnamed != "" {
		return nil, fmt.Errorf("%w: %s does not parse, so it may be this agent's policy", ErrBrokenPolicy, s.unnamed)
	}
	return s.ok[AnyAgent], nil
}

// Has reports whether an agent has a policy of its own (usable or not).
func (s Set) Has(agentID string) bool {
	_, ok := s.ok[agentID]
	_, bad := s.broken[agentID]
	return ok || bad
}

// Len is the number of usable policies.
func (s Set) Len() int { return len(s.ok) }

// SortedIDs returns the agent ids of a set.
func (s Set) SortedIDs() []string {
	ids := make([]string, 0, len(s.ok))
	for id := range s.ok {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ErrNoPolicies is returned when a directory has no policy files.
var ErrNoPolicies = errors.New("no policy files")
