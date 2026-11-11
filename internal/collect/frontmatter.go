package collect

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/authsec-ai/authsec-cli/internal/parse"
)

// frontMatter is the YAML header of a Markdown file (skills, sub-agents,
// commands). Only the fields that say what the extension may do are kept.
type frontMatter struct {
	Name         string
	Description  string
	AllowedTools []string
	Tools        []string
	Model        string
}

// readFrontMatter parses the leading "---" block of a Markdown file. A file
// without one has an empty front matter, which is not an error.
func readFrontMatter(data []byte) (frontMatter, error) {
	var fm frontMatter
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !bytes.HasPrefix(data, []byte("---")) {
		return fm, nil
	}
	rest := data[3:]
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return fm, nil
	}
	var m map[string]any
	if err := yaml.Unmarshal(rest[:end], &m); err != nil {
		return fm, err
	}
	str := func(k string) string {
		s, _ := m[k].(string)
		return strings.TrimSpace(s)
	}
	fm.Name = str("name")
	fm.Description = parse.Text(truncate(str("description"), 200))
	fm.Model = str("model")
	fm.AllowedTools = scrubAll(toolList(m["allowed-tools"]))
	fm.Tools = scrubAll(toolList(m["tools"]))
	return fm, nil
}

// toolList reads a tools field written either as a YAML list or as one
// comma-separated string ("Read, Grep, Bash(git:*)").
func toolList(v any) []string {
	switch t := v.(type) {
	case string:
		var out []string
		for _, s := range splitTools(t) {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

// splitTools splits on commas outside parentheses: "Bash(git add:*, git
// status:*), Read" is two tools.
func splitTools(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

func scrubAll(in []string) []string {
	for i := range in {
		in[i] = parse.Text(in[i])
	}
	return in
}

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
