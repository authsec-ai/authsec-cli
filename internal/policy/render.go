package policy

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Render writes a generated policy as YAML with its reasons as comments, in
// the order a person reads it. Parse(Render(g)) gives back g.Policy.
func Render(g *Generated) []byte {
	p := g.Policy
	var b bytes.Buffer
	for _, h := range g.Header {
		fmt.Fprintf(&b, "# %s\n", commentSafe(h))
	}
	fmt.Fprintf(&b, "apiVersion: %s\nkind: %s\n", APIVersion, Kind)
	fmt.Fprintf(&b, "agent:\n  id: %s\n", scalar(p.Agent.ID))
	if p.Agent.Name != "" {
		fmt.Fprintf(&b, "  name: %s\n", scalar(p.Agent.Name))
	}
	fmt.Fprintf(&b, "mode: %s   # monitor | enforce\n", p.Mode)

	b.WriteString("\n# Where the agent may connect. deny wins over allow; anything else gets default.\n")
	b.WriteString("# A rule is host (example.com, *.example.com) or cidr (10.0.0.0/8), with an optional port.\n")
	fmt.Fprintf(&b, "network:\n  default: %s\n", p.Network.Default)
	writeRules(&b, "allow", p.Network.Allow, "network.allow", g.Notes)
	writeRules(&b, "deny", p.Network.Deny, "network.deny", g.Notes)

	b.WriteString("\n# Files, by path prefix. deny wins. With read_write or read_only set, other paths\n")
	b.WriteString("# are outside the policy (system paths stay readable). {home} and {project} are\n")
	b.WriteString("# filled in when applied. Enforced for agents started with `authsec-cli run --enforce`.\n")
	b.WriteString("filesystem:\n")
	empty := true
	for _, l := range []struct {
		key   string
		paths []string
	}{{"read_write", p.Filesystem.ReadWrite}, {"read_only", p.Filesystem.ReadOnly}, {"deny", p.Filesystem.Deny}} {
		if len(l.paths) == 0 {
			continue
		}
		empty = false
		writeList(&b, l.key, l.paths, "filesystem."+l.key, g.Notes)
	}
	if empty {
		b.WriteString("  read_write: []\n")
	}

	b.WriteString("\n# Shell commands. '*' matches any text. deny wins over ask, ask over allow.\n")
	if n := g.Notes["commands"]; n != "" {
		fmt.Fprintf(&b, "# Seen: %s\n", commentSafe(n))
	}
	fmt.Fprintf(&b, "commands:\n  default: %s\n", p.Commands.Default)
	writeList(&b, "allow", p.Commands.Allow, "commands.allow", g.Notes)
	writeList(&b, "ask", p.Commands.Ask, "commands.ask", g.Notes)
	writeList(&b, "deny", p.Commands.Deny, "commands.deny", g.Notes)

	b.WriteString("\n# MCP servers the agent may load, by name.\n")
	fmt.Fprintf(&b, "mcp_servers:\n  default: %s\n", p.MCPServers.Default)
	writeList(&b, "allow", p.MCPServers.Allow, "mcp_servers.allow", g.Notes)
	writeList(&b, "deny", p.MCPServers.Deny, "mcp_servers.deny", g.Notes)
	return b.Bytes()
}

func writeRules(b *bytes.Buffer, key string, rules []Rule, field string, notes map[string]string) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s:\n", key)
	for i, r := range rules {
		var parts []string
		if r.Host != "" {
			parts = append(parts, "host: "+scalar(r.Host))
		}
		if r.CIDR != "" {
			parts = append(parts, "cidr: "+scalar(r.CIDR))
		}
		if r.Port != 0 {
			parts = append(parts, fmt.Sprintf("port: %d", r.Port))
		}
		line := "    - { " + strings.Join(parts, ", ") + " }"
		if n := notes[fmt.Sprintf("%s[%d]", field, i)]; n != "" {
			line = pad(line, 58) + "# " + commentSafe(n)
		}
		b.WriteString(line + "\n")
	}
}

func writeList(b *bytes.Buffer, key string, items []string, field string, notes map[string]string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "  %s:\n", key)
	for i, it := range items {
		line := "    - " + scalar(it)
		if n := notes[fmt.Sprintf("%s[%d]", field, i)]; n != "" {
			line = pad(line, 44) + "# " + commentSafe(n)
		}
		b.WriteString(line + "\n")
	}
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s + "  "
	}
	return s + strings.Repeat(" ", n-len(s))
}

// commentSafe keeps text on one comment line: line breaks and other
// control characters (which would end the comment and start YAML) become
// spaces.
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '\u0085' {
			return ' '
		}
		return r
	}, s)
}

// scalar renders one string as a YAML scalar: plain when that reads back as
// the same string, otherwise double-quoted with escapes.
func scalar(s string) string {
	plain := s != "" && !strings.ContainsAny(s, ",[]{}#&*!|>'\"%@`:\\") && strings.TrimSpace(s) == s && safeText(s)
	if plain {
		var back string
		if err := yaml.Unmarshal([]byte("v: "+s), &struct {
			V *string `yaml:"v"`
		}{&back}); err == nil && back == s {
			var anyV map[string]any
			if yaml.Unmarshal([]byte("v: "+s), &anyV) == nil {
				if _, isStr := anyV["v"].(string); isStr {
					return s
				}
			}
		}
	}
	return strconv.Quote(s)
}
