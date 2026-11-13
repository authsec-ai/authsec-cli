package siem

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// Escaping follows "Implementing ArcSight Common Event Format (CEF)",
// version 26, section Character Encoding: in the header a pipe and a
// backslash take a backslash; in the extension an equal sign and a
// backslash take a backslash, and a newline is written as \n (or \r).
// Newlines are allowed only in extension values, so the header turns them
// (and other control characters) into spaces.

// FormatCEF renders r as one CEF:0 line with no trailing newline.
func FormatCEF(r events.Record, version, host string) string {
	var b strings.Builder
	b.WriteString("CEF:0|AuthSec|Agent Kit|")
	b.WriteString(cefHeader(clip(version, 31)))
	b.WriteByte('|')
	b.WriteString(cefHeader(clip(signature(r), 1023)))
	b.WriteByte('|')
	b.WriteString(cefHeader(clip(eventName(r), 512)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(severity(r)))
	b.WriteByte('|')
	for i, kv := range extension(r, host) {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(cefValue(kv[1]))
	}
	return b.String()
}

// severity is the CEF severity (0-10) of r: detections high 9, medium 6,
// low 3; quarantine 8; an enforced deny 7, a logged one 5; others 1.
func severity(r events.Record) int {
	switch r.Type {
	case events.Detection:
		switch strings.ToLower(r.Severity) {
		case "critical":
			return 10
		case "medium":
			return 6
		case "low":
			return 3
		}
		return 9 // high, or unset: a detection is high unless it says otherwise
	case events.Decision:
		switch r.Action {
		case "quarantine":
			return 8
		case "deny", "kill":
			if r.Enforced {
				return 7
			}
			return 5
		}
	}
	return 1
}

// signature is the CEF signature id: the record type, then the kind and
// action of a decision or the rule of a detection.
func signature(r events.Record) string {
	parts := []string{r.Type}
	switch r.Type {
	case events.Decision:
		parts = append(parts, orDash(r.Kind), orDash(r.Action))
	case events.Detection:
		parts = append(parts, orDash(r.Rule))
	}
	return strings.Join(parts, ":")
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// eventName is a short human-readable name that repeats nothing the
// extension carries.
func eventName(r events.Record) string {
	switch r.Type {
	case events.Decision:
		kind := r.Kind
		if kind == "" {
			kind = "agent"
		}
		return "Agent " + kind + " " + orDash(r.Action)
	case events.Detection:
		return "Detection " + orDash(r.Rule)
	case events.AgentStarted:
		return "Agent started"
	case events.AgentStopped:
		return "Agent stopped"
	case events.Sensor:
		return "Sensor status"
	case events.Process:
		return "Agent process"
	case events.Network:
		return "Agent connection"
	case events.File:
		return "Agent file access"
	}
	return "Agent event " + r.Type
}

// extension returns the key-value pairs in a fixed order, skipping empty
// values. Keys are standard CEF keys; cs1-cs6 carry what has none.
func extension(r events.Record, host string) [][2]string {
	var kv [][2]string
	add := func(k, v string, max int) {
		if v != "" {
			kv = append(kv, [2]string{k, clip(v, max)})
		}
	}
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	add("rt", strconv.FormatInt(t.UnixMilli(), 10), 32)
	add("dvchost", host, 100)
	if a := r.Agent; a != nil {
		add("suser", a.User, 1023)
		add("sproc", a.Name, 1023)
		if a.PID > 0 {
			add("spid", strconv.Itoa(a.PID), 16)
		}
		add("cs5Label", label(a.ID, "agent_id"), 1023)
		add("cs5", a.ID, 4000)
	}
	add("act", r.Action, 63)
	if r.Type == events.Decision {
		outcome := "logged"
		if r.Enforced {
			outcome = "blocked"
		}
		add("outcome", outcome, 63)
	}
	add("cs1Label", label(r.Rule, "rule"), 1023)
	add("cs1", r.Rule, 4000)
	tags := strings.Join(Tags(r), ",")
	add("cs2Label", label(tags, "tags"), 1023)
	add("cs2", tags, 4000)
	if r.Comm != "" || len(r.Args) > 0 || r.Exe != "" {
		proc := r.Comm
		if proc == "" {
			proc = filepath.Base(r.Exe)
		}
		add("dproc", proc, 1023)
		if r.PID > 0 {
			add("dpid", strconv.Itoa(r.PID), 16)
		}
		add("filePath", r.Exe, 1023)
		cmd := strings.Join(r.Args, " ")
		add("cs3Label", label(cmd, "command"), 1023)
		add("cs3", cmd, 4000)
	}
	if d := r.Dst; d != nil {
		if ip := net.ParseIP(d.IP); ip != nil && ip.To4() == nil {
			add("c6a3", ip.String(), 64)
			add("c6a3Label", "Destination IPv6 Address", 1023)
		} else {
			add("dst", d.IP, 64)
		}
		if d.Port > 0 {
			add("dpt", strconv.Itoa(d.Port), 8)
		}
		add("dhost", d.Host, 1023)
		add("app", d.Service, 31)
	}
	if r.Path != "" && r.Exe == "" {
		add("fname", filepath.Base(r.Path), 1023)
		add("filePath", r.Path, 1023)
	}
	add("cs6Label", label(r.Access, "access"), 1023)
	add("cs6", r.Access, 4000)
	add("cs4Label", label(r.Source, "source"), 1023)
	add("cs4", r.Source, 4000)
	add("msg", r.Note, 1023)
	return kv
}

// label returns l when v is set, so a label is sent only with its value.
func label(v, l string) string {
	if v == "" {
		return ""
	}
	return l
}

// cefHeader escapes a header field.
func cefHeader(s string) string {
	var b strings.Builder
	for _, c := range clean(s) {
		switch {
		case c == '\\' || c == '|':
			b.WriteByte('\\')
			b.WriteRune(c)
		case unicode.IsControl(c):
			b.WriteByte(' ')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// cefValue escapes an extension value.
func cefValue(s string) string {
	var b strings.Builder
	for _, c := range clean(s) {
		switch {
		case c == '\\' || c == '=':
			b.WriteByte('\\')
			b.WriteRune(c)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case unicode.IsControl(c):
			b.WriteByte(' ')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// clean replaces invalid UTF-8 and the Unicode line and paragraph
// separators, which some parsers treat as line breaks.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.NewReplacer("\u2028", " ", "\u2029", " ", "\u0085", " ").Replace(s)
}

// clip cuts s to at most n bytes without splitting a character.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
