// Package parse reads configuration formats and scrubs values that could be
// secrets before a collector keeps anything.
package parse

import (
	"bytes"
	"encoding/json"
)

// StripJSONC turns JSON with comments and trailing commas (VS Code, Claude
// Desktop and Cursor write it) into plain JSON. Strings are left untouched.
func StripJSONC(in []byte) []byte {
	in = bytes.TrimPrefix(in, []byte("\xef\xbb\xbf"))
	out := make([]byte, 0, len(in))
	lastComma := -1 // index in out of a comma seen since the last value
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '"':
			lastComma = -1
			j := i + 1
			for j < len(in) && in[j] != '"' {
				if in[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(in) {
				j = len(in) - 1
			}
			out = append(out, in[i:j+1]...)
			i = j
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && !(in[i] == '*' && in[i+1] == '/') {
				i++
			}
			i++ // past the closing '/'
			out = append(out, ' ')
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			out = append(out, c)
		case c == ',':
			lastComma = len(out)
			out = append(out, c)
		case c == '}' || c == ']':
			if lastComma >= 0 {
				out = append(out[:lastComma], out[lastComma+1:]...)
			}
			lastComma = -1
			out = append(out, c)
		default:
			lastComma = -1
			out = append(out, c)
		}
	}
	return out
}

// JSONC decodes JSON with comments and trailing commas into a generic value.
// Numbers stay json.Number so nothing is rounded.
func JSONC(in []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(StripJSONC(in)))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if v == nil {
		v = map[string]any{}
	}
	return v, nil
}

// Map returns m[key] as an object, or nil.
func Map(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	return v
}

// String returns m[key] as a string, or "".
func String(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// Bool returns m[key] as a bool, and whether it was set to one.
func Bool(m map[string]any, key string) (value, ok bool) {
	value, ok = m[key].(bool)
	return
}

// Strings returns m[key] as a list of strings, skipping anything else.
func Strings(m map[string]any, key string) []string {
	list, _ := m[key].([]any)
	var out []string
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
