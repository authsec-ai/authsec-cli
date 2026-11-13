package siem

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

func TestTags(t *testing.T) {
	cases := []struct {
		name string
		r    events.Record
		want []string
	}{
		{"command deny", events.Record{Type: events.Decision, Kind: "command", Action: "deny"},
			[]string{"authsec:decision", asi02, llm06}},
		{"command kill", events.Record{Type: events.Decision, Kind: "command", Action: "kill"},
			[]string{"authsec:decision", asi02, llm06}},
		{"command allow", events.Record{Type: events.Decision, Kind: "command", Action: "allow"},
			[]string{"authsec:decision"}},
		{"network deny", events.Record{Type: events.Decision, Kind: "network", Action: "deny"},
			[]string{"authsec:decision", asi02, llm06}},
		{"web deny", events.Record{Type: events.Decision, Kind: "web", Action: "deny"},
			[]string{"authsec:decision", asi02, llm06}},
		{"mcp deny", events.Record{Type: events.Decision, Kind: "mcp", Action: "deny"},
			[]string{"authsec:decision", asi02, asi04}},
		{"file deny", events.Record{Type: events.Decision, Kind: "file", Action: "deny"},
			[]string{"authsec:decision", llm06}},
		{"credential file deny", events.Record{Type: events.Decision, Kind: "file", Action: "deny", Sensitive: true},
			[]string{"authsec:decision", asi03, llm02, llm06}},
		{"credential file read", events.Record{Type: events.File, Path: "/home/a/.aws/credentials", Sensitive: true},
			[]string{"authsec:file", asi03, llm02}},
		{"plain file read", events.Record{Type: events.File, Path: "/tmp/x"}, []string{"authsec:file"}},
		{"quarantine", events.Record{Type: events.Decision, Kind: "agent", Action: "quarantine"},
			[]string{"authsec:decision", asi10}},
		{"release", events.Record{Type: events.Decision, Kind: "agent", Action: "release"},
			[]string{"authsec:decision"}},
		{"detection", events.Record{Type: events.Detection, Rule: "artex_present"},
			[]string{"authsec:detection", asi10}},
		{"agent started", events.Record{Type: events.AgentStarted}, []string{"authsec:agent_started"}},
		{"sensor", events.Record{Type: events.Sensor}, []string{"authsec:sensor"}},
	}
	for _, c := range cases {
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if got := Tags(c.r); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v, want %v", c.name, got, want)
		}
	}
}

func TestTagsUseRealOWASPIDs(t *testing.T) {
	for _, tag := range []string{asi02, asi03, asi04, asi10, llm02, llm06} {
		if !strings.HasPrefix(tag, "owasp-agentic:ASI") && !strings.HasPrefix(tag, "owasp-llm:LLM") {
			t.Errorf("tag %q", tag)
		}
		if strings.ContainsAny(tag, " ,|=") {
			t.Errorf("tag %q has a separator character", tag)
		}
	}
}
