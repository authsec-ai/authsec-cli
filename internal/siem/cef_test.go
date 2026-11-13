package siem

import (
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 123e6, time.UTC)

// parseCEF splits a CEF line into its 7 header fields and its extension,
// undoing the escapes. It fails the test on a malformed line.
func parseCEF(t *testing.T, line string) ([]string, map[string]string) {
	t.Helper()
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("raw line break in %q", line)
	}
	if !utf8.ValidString(line) {
		t.Fatalf("invalid UTF-8 in %q", line)
	}
	var header []string
	var cur strings.Builder
	i := 0
	for ; i < len(line) && len(header) < 7; i++ {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line):
			i++
			if line[i] != '\\' && line[i] != '|' {
				t.Fatalf("bad header escape \\%c in %q", line[i], line)
			}
			cur.WriteByte(line[i])
		case c == '|':
			header = append(header, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if len(header) != 7 {
		t.Fatalf("want 7 header fields, got %d in %q", len(header), line)
	}
	return header, parseExt(t, line[i:])
}

func parseExt(t *testing.T, ext string) map[string]string {
	t.Helper()
	// Positions of unescaped '=': each starts a value; its key is the word
	// before it.
	var eqs []int
	for i := 0; i < len(ext); i++ {
		if ext[i] == '\\' {
			i++
			continue
		}
		if ext[i] == '=' {
			eqs = append(eqs, i)
		}
	}
	out := map[string]string{}
	for n, eq := range eqs {
		ks := strings.LastIndexByte(ext[:eq], ' ') + 1
		key := ext[ks:eq]
		end := len(ext)
		if n+1 < len(eqs) {
			end = strings.LastIndexByte(ext[:eqs[n+1]], ' ')
		}
		raw := ext[eq+1 : end]
		var v strings.Builder
		for i := 0; i < len(raw); i++ {
			if raw[i] != '\\' {
				v.WriteByte(raw[i])
				continue
			}
			i++
			if i >= len(raw) {
				t.Fatalf("dangling backslash in %q", raw)
			}
			switch raw[i] {
			case '\\', '=':
				v.WriteByte(raw[i])
			case 'n':
				v.WriteByte('\n')
			case 'r':
				v.WriteByte('\r')
			default:
				t.Fatalf("bad extension escape \\%c in %q", raw[i], raw)
			}
		}
		if _, dup := out[key]; dup {
			t.Fatalf("duplicate key %s", key)
		}
		out[key] = v.String()
	}
	return out
}

func TestFormatCEFNetworkDeny(t *testing.T) {
	r := events.Record{Time: t0, Type: events.Decision, Kind: "network", Action: "deny", Rule: "egress-default",
		Enforced: true, Source: "daemon",
		Agent: &events.Agent{ID: "claude-code", Name: "Claude Code", PID: 4242, User: "alice"},
		Dst:   &events.Dst{IP: "93.184.216.34", Port: 443, Host: "example.com", Service: "https"}}
	line := FormatCEF(r, "1.2.3", "build-01")
	if !strings.HasPrefix(line, "CEF:0|AuthSec|Agent Kit|1.2.3|decision:network:deny|Agent network deny|7|") {
		t.Fatalf("header: %s", line)
	}
	_, ext := parseCEF(t, line)
	want := map[string]string{
		"rt": strconv.FormatInt(t0.UnixMilli(), 10), "dvchost": "build-01", "suser": "alice", "sproc": "Claude Code", "spid": "4242",
		"act": "deny", "outcome": "blocked", "cs1": "egress-default", "cs1Label": "rule", "cs2Label": "tags",
		"dst": "93.184.216.34", "dpt": "443", "dhost": "example.com", "app": "https",
		"cs4": "daemon", "cs4Label": "source", "cs5": "claude-code", "cs5Label": "agent_id",
	}
	for k, v := range want {
		if ext[k] != v {
			t.Errorf("%s = %q, want %q", k, ext[k], v)
		}
	}
	if !strings.Contains(ext["cs2"], asi02) || !strings.Contains(ext["cs2"], "authsec:decision") {
		t.Errorf("cs2 = %q", ext["cs2"])
	}
}

func TestFormatCEFHostileValues(t *testing.T) {
	hostile := "a|b\\c=d\ne\rf  g 🔥 ünï"
	r := events.Record{Time: t0, Type: events.Decision, Kind: "comm|and", Action: "deny", Rule: hostile,
		Note:  "x=y\\z\nnext line",
		Agent: &events.Agent{ID: "id=1", Name: "na|me\\", User: "us\ter"},
		Path:  "/tmp/we ird=name\\x|y", Args: nil}
	line := FormatCEF(r, "1.0|evil\\ver\nsion", "host=1|2")
	h, ext := parseCEF(t, line)
	if h[0] != "CEF:0" || h[1] != "AuthSec" || h[2] != "Agent Kit" {
		t.Fatalf("header %q", h)
	}
	if h[3] != "1.0|evil\\ver sion" {
		t.Errorf("version %q", h[3])
	}
	if h[4] != "decision:comm|and:deny" {
		t.Errorf("signature %q", h[4])
	}
	if h[6] != "5" {
		t.Errorf("severity %q (a logged deny is 5)", h[6])
	}
	checks := map[string]string{
		"cs1":      "a|b\\c=d\ne\rf  g 🔥 ünï", // U+2028 becomes a space
		"msg":      "x=y\\z\nnext line",
		"sproc":    "na|me\\",
		"suser":    "us er",
		"cs5":      "id=1",
		"dvchost":  "host=1|2",
		"filePath": "/tmp/we ird=name\\x|y",
		"fname":    "we ird=name\\x|y",
		"outcome":  "logged",
	}
	for k, v := range checks {
		if ext[k] != v {
			t.Errorf("%s = %q, want %q", k, ext[k], v)
		}
	}
}

func TestFormatCEFInvalidUTF8(t *testing.T) {
	r := events.Record{Time: t0, Type: events.Detection, Rule: "bad\xff\xfe", Severity: "high"}
	line := FormatCEF(r, "1", "h")
	h, ext := parseCEF(t, line)
	if h[4] != "detection:bad�" || ext["cs1"] != "bad�" {
		t.Fatalf("got %q %q", h[4], ext["cs1"])
	}
}

func TestFormatCEFSeverity(t *testing.T) {
	cases := []struct {
		r    events.Record
		want int
	}{
		{events.Record{Type: events.Detection, Severity: "high"}, 9},
		{events.Record{Type: events.Detection, Severity: "medium"}, 6},
		{events.Record{Type: events.Detection, Severity: "low"}, 3},
		{events.Record{Type: events.Detection}, 9},
		{events.Record{Type: events.Decision, Action: "deny", Enforced: true}, 7},
		{events.Record{Type: events.Decision, Action: "deny"}, 5},
		{events.Record{Type: events.Decision, Action: "kill", Enforced: true}, 7},
		{events.Record{Type: events.Decision, Action: "quarantine", Enforced: true}, 8},
		{events.Record{Type: events.Decision, Action: "allow"}, 1},
		{events.Record{Type: events.AgentStarted}, 1},
		{events.Record{Type: events.Sensor}, 1},
	}
	for _, c := range cases {
		h, _ := parseCEF(t, FormatCEF(c.r, "1", "h"))
		if h[6] != strconv.Itoa(c.want) {
			t.Errorf("%+v: severity %s, want %d", c.r, h[6], c.want)
		}
	}
}

func TestFormatCEFSignatures(t *testing.T) {
	cases := map[string]events.Record{
		"detection:artex_present":   {Type: events.Detection, Rule: "artex_present"},
		"decision:command:kill":     {Type: events.Decision, Kind: "command", Action: "kill"},
		"decision:-:-":              {Type: events.Decision},
		"agent_started":             {Type: events.AgentStarted},
		"sensor":                    {Type: events.Sensor, Note: "started"},
		"decision:agent:quarantine": {Type: events.Decision, Kind: "agent", Action: "quarantine"},
	}
	for want, r := range cases {
		r.Time = t0
		if h, _ := parseCEF(t, FormatCEF(r, "1", "h")); h[4] != want {
			t.Errorf("signature %q, want %q", h[4], want)
		}
	}
}

func TestFormatCEFIPv6AndProcess(t *testing.T) {
	r := events.Record{Time: t0, Type: events.Decision, Kind: "command", Action: "deny", PID: 77, Comm: "curl",
		Exe: "/usr/bin/curl", Args: []string{"curl", "https://x.test/?a=b"}, Agent: &events.Agent{Name: "goose", PID: 70}}
	_, ext := parseCEF(t, FormatCEF(r, "1", "h"))
	if ext["dproc"] != "curl" || ext["dpid"] != "77" || ext["filePath"] != "/usr/bin/curl" ||
		ext["cs3"] != "curl https://x.test/?a=b" || ext["cs3Label"] != "command" || ext["spid"] != "70" {
		t.Errorf("process fields: %v", ext)
	}
	r = events.Record{Time: t0, Type: events.Network, Dst: &events.Dst{IP: "2001:db8::1", Port: 53}}
	_, ext = parseCEF(t, FormatCEF(r, "1", "h"))
	if ext["c6a3"] != "2001:db8::1" || ext["c6a3Label"] != "Destination IPv6 Address" || ext["dst"] != "" || ext["dpt"] != "53" {
		t.Errorf("ipv6 fields: %v", ext)
	}
}

func TestFormatCEFClipsLongValues(t *testing.T) {
	r := events.Record{Time: t0, Type: events.Sensor, Note: strings.Repeat("é", 2000)}
	_, ext := parseCEF(t, FormatCEF(r, "1", "h"))
	if len(ext["msg"]) > 1023 || !utf8.ValidString(ext["msg"]) {
		t.Fatalf("msg is %d bytes", len(ext["msg"]))
	}
}
