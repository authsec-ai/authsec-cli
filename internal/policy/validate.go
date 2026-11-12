package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	yamlLine      = regexp.MustCompile(`^(?:yaml: )?line (\d+): (.*)$`)
	fieldNotFound = regexp.MustCompile(`^field (\S+) not found in type policy\.(\w+)$`)
)

// yamlIssues turns a yaml.v3 error into issues, one per problem, with line
// numbers and plain wording.
func yamlIssues(err error, src []byte) []Issue {
	var msgs []string
	var te *yaml.TypeError
	if errors.As(err, &te) {
		msgs = te.Errors
	} else {
		msgs = []string{strings.TrimSpace(err.Error())}
	}
	srcLines := strings.Split(string(src), "\n")
	var out []Issue
	for _, msg := range msgs {
		msg = strings.TrimPrefix(msg, "yaml: ")
		is := Issue{Message: msg}
		if m := yamlLine.FindStringSubmatch(msg); m != nil {
			fmt.Sscan(m[1], &is.Line)
			is.Message = m[2]
		}
		text := ""
		if is.Line > 0 && is.Line <= len(srcLines) {
			text = srcLines[is.Line-1]
		}
		is.Message = friendlyYAML(is.Message, text)
		out = append(out, is)
	}
	return out
}

// friendlyYAML rewrites yaml.v3's Go-flavoured messages. line is the source
// line the message is about, when known.
func friendlyYAML(msg, line string) string {
	if m := fieldNotFound.FindStringSubmatch(msg); m != nil {
		return fmt.Sprintf("unknown key %q (in %s); check the spelling", m[1], strings.ToLower(m[2]))
	}
	switch {
	case strings.Contains(msg, "did not find expected alphabetic or numeric character") &&
		(strings.Contains(line, ": *") || strings.Contains(line, "- *") || strings.Contains(line, "[*")):
		return `a value starting with * must be quoted, e.g. "*" or "*.example.com"`
	case strings.Contains(msg, "found character that cannot start any token") && strings.Contains(line, "\t"):
		return "use spaces, not tabs, to indent"
	}
	for _, r := range [][2]string{{"!!str", "text"}, {"!!int", "a number"}, {"!!seq", "a list"}, {"!!map", "a map"}, {"!!bool", "true/false"}, {"!!float", "a decimal number"}} {
		msg = strings.ReplaceAll(msg, r[0], r[1])
	}
	return msg
}

// lines finds fields in the parsed document, for messages.
type lines struct{ root *yaml.Node }

// node returns the value node at path, or nil.
func (l *lines) node(path ...string) *yaml.Node {
	n := l.root
	for _, k := range path {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == k {
				next = n.Content[i+1]
				break
			}
		}
		n = next
	}
	return n
}

// at returns the line of the value at path (keys and list indexes); 0 if
// absent, falling back to the nearest parent that exists.
func (l *lines) at(path ...any) int {
	n := l.root
	line := 0
	for _, step := range path {
		if n == nil {
			break
		}
		switch k := step.(type) {
		case string:
			var next *yaml.Node
			if n.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(n.Content); i += 2 {
					if n.Content[i].Value == k {
						line = n.Content[i].Line
						next = n.Content[i+1]
						break
					}
				}
			}
			n = next
		case int:
			if n.Kind == yaml.SequenceNode && k < len(n.Content) {
				n = n.Content[k]
				line = n.Line
			} else {
				n = nil
			}
		}
	}
	return line
}

var (
	hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	agentID   = regexp.MustCompile(`^(\*|[a-z0-9][a-z0-9._-]*)$`)
)

func (p *Policy) validate(l *lines) []Issue {
	var out []Issue
	add := func(warn bool, field string, path []any, format string, a ...any) {
		out = append(out, Issue{Line: l.at(path...), Field: field, Message: fmt.Sprintf(format, a...), Warning: warn})
	}
	if p.APIVersion != APIVersion {
		add(false, "apiVersion", []any{"apiVersion"}, "must be %q", APIVersion)
	}
	if p.Kind != Kind {
		add(false, "kind", []any{"kind"}, "must be %q", Kind)
	}
	if !agentID.MatchString(p.Agent.ID) {
		add(false, "agent.id", []any{"agent", "id"}, `must be an agent id such as "claude-code" (see 'authsec-cli agents --json'), or "*" for every agent without a policy`)
	}
	switch p.Mode {
	case Monitor, Enforce:
	case "":
		add(false, "mode", []any{"mode"}, "missing; use %q (log only) or %q (block)", Monitor, Enforce)
	default:
		add(false, "mode", []any{"mode"}, "%q is not a mode; use %q or %q", p.Mode, Monitor, Enforce)
	}

	checkDefault := func(field string, path []any, v string) {
		if v != "" && v != Allow && v != Deny {
			add(false, field, path, "%q: use %q or %q", v, Allow, Deny)
		}
	}
	checkDefault("network.default", []any{"network", "default"}, p.Network.Default)
	for _, list := range []struct {
		name  string
		rules []Rule
	}{{"allow", p.Network.Allow}, {"deny", p.Network.Deny}} {
		for i, r := range list.rules {
			field := fmt.Sprintf("network.%s[%d]", list.name, i)
			path := []any{"network", list.name, i}
			switch {
			case r.Host == "" && r.CIDR == "":
				add(false, field, path, "needs host or cidr")
			case r.Host != "" && r.CIDR != "":
				add(false, field, path, "has both host and cidr; use one rule for each")
			case r.Host != "" && !validHost(r.Host):
				add(false, field, path, "host %q is not a host name (use example.com or *.example.com; for an address use cidr)", r.Host)
			case r.CIDR != "":
				ip, n, err := net.ParseCIDR(r.CIDR)
				if err != nil {
					add(false, field, path, "cidr %q is not an address range such as 10.0.0.0/8 or 203.0.113.7/32", r.CIDR)
				} else if !ip.Equal(n.IP) {
					_, bits := n.Mask.Size()
					add(true, field, path, "cidr %s has host bits set: it covers all of %s (use %s/%d for one address)", r.CIDR, n, ip, bits)
				}
			}
			if r.Port < 0 || r.Port > 65535 {
				add(false, field, path, "port %d is out of range", r.Port)
			}
		}
	}

	for _, list := range []struct {
		name  string
		paths []string
	}{{"read_write", p.Filesystem.ReadWrite}, {"read_only", p.Filesystem.ReadOnly}, {"deny", p.Filesystem.Deny}} {
		for i, path := range list.paths {
			field := fmt.Sprintf("filesystem.%s[%d]", list.name, i)
			at := []any{"filesystem", list.name, i}
			switch {
			case path == "":
				add(false, field, at, "empty path")
			case !(strings.HasPrefix(path, "/") || placeholderStart(path, "{home}") || placeholderStart(path, "{project}")):
				add(false, field, at, "%q must be absolute, or {home} or {project} followed by /", path)
			case strings.Contains(strings.TrimPrefix(strings.TrimPrefix(path, "{home}"), "{project}"), "{"):
				add(false, field, at, "%q: {home} and {project} may only start a path", path)
			case strings.Contains(path, ".."):
				add(false, field, at, "%q must not contain ..", path)
			}
		}
	}
	for i, d := range p.Filesystem.Deny {
		for j, rw := range p.Filesystem.ReadWrite {
			if under(rw, d) {
				add(true, fmt.Sprintf("filesystem.read_write[%d]", j), []any{"filesystem", "read_write", j},
					"%q is inside denied %q (filesystem.deny[%d]); deny wins", rw, d, i)
			}
		}
	}
	for i, ro := range p.Filesystem.ReadOnly {
		for j, rw := range p.Filesystem.ReadWrite {
			if under(ro, rw) {
				add(true, fmt.Sprintf("filesystem.read_only[%d]", i), []any{"filesystem", "read_only", i},
					"%q is inside read_write %q (filesystem.read_write[%d]): read_write wins, so it is writable; use deny to protect it", ro, rw, j)
			}
		}
	}

	checkDefault("commands.default", []any{"commands", "default"}, p.Commands.Default)
	for _, list := range []struct {
		name string
		pats []string
	}{{"allow", p.Commands.Allow}, {"ask", p.Commands.Ask}, {"deny", p.Commands.Deny}} {
		for i, pat := range list.pats {
			if strings.TrimSpace(pat) == "" {
				add(false, fmt.Sprintf("commands.%s[%d]", list.name, i), []any{"commands", list.name, i}, "empty pattern")
			}
		}
	}
	checkDefault("mcp_servers.default", []any{"mcp_servers", "default"}, p.MCPServers.Default)

	// Mistakes that would break the agent once enforced.
	if p.Mode == Enforce && p.Network.Default == Deny && p.Agent.ID != AnyAgent && p.Agent.ID != "unknown" {
		if model := ModelHosts[p.Agent.ID]; len(model) > 0 {
			reached := false
			for _, h := range model {
				if d := p.DecideNetwork(h, nil, 443); d.Action == Allow {
					reached = true
				}
			}
			if !reached {
				add(true, "network", []any{"network"}, "the agent's model API (%s) is not allowed: %s will not work", strings.Join(model, ", "), p.Agent.ID)
			}
		}
	}
	if p.Mode == Enforce && p.Network.Default == Deny && len(p.Network.Allow) == 0 {
		add(true, "network", []any{"network"}, "enforced with default deny and nothing allowed: the agent has no network")
	}
	if p.Mode == Enforce && p.Network.Default == "" {
		add(true, "network.default", []any{"network"}, "not set: destinations not listed are allowed")
	}
	return out
}

// placeholderStart reports whether path is the placeholder or starts with
// it followed by "/" ("{home}.ssh" would expand to a sibling directory).
func placeholderStart(path, ph string) bool {
	return path == ph || strings.HasPrefix(path, ph+"/")
}

func validHost(h string) bool {
	h = strings.TrimPrefix(strings.ToLower(h), "*.")
	if net.ParseIP(h) != nil || len(h) > 253 || !strings.Contains(h, ".") && h != "localhost" {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// Marshal renders a policy as YAML (no comments; see Render for generated
// files).
func Marshal(p *Policy) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Expand replaces {home} and {project} in every path. An empty project
// drops the paths that need it; the policy stays confined (see confined).
func (p *Policy) Expand(home, project string) *Policy {
	cp := *p
	cp.confined = p.confined || len(p.Filesystem.ReadWrite) > 0 || len(p.Filesystem.ReadOnly) > 0
	exp := func(in []string) []string {
		var out []string
		for _, s := range in {
			if strings.Contains(s, "{project}") && project == "" {
				continue
			}
			s = strings.ReplaceAll(s, "{home}", home)
			s = strings.ReplaceAll(s, "{project}", project)
			out = append(out, filepath.Clean(s))
		}
		return out
	}
	cp.Filesystem = Filesystem{ReadWrite: exp(p.Filesystem.ReadWrite), ReadOnly: exp(p.Filesystem.ReadOnly), Deny: exp(p.Filesystem.Deny)}
	return &cp
}
