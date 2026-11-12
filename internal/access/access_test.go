package access

import (
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

func TestSummarize(t *testing.T) {
	t0 := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cl := &events.Agent{ID: "claude-code", Name: "Claude Code", PID: 10, User: "dev"}
	cl2 := &events.Agent{ID: "claude-code", Name: "Claude Code", PID: 99, User: "dev"}
	cx := &events.Agent{ID: "codex", Name: "Codex", PID: 20}
	recs := []events.Record{
		{Time: t0, Type: events.AgentStarted, Agent: cl},
		{Time: t0, Type: events.AgentStarted, Agent: cx},
		{Time: t0.Add(1), Type: events.File, Agent: cl, Path: "/w/main.go", Access: "read"},
		{Time: t0.Add(2), Type: events.File, Agent: cl, Path: "/w/main.go", Access: "write"},
		{Time: t0.Add(3), Type: events.File, Agent: cl, Path: "/h/.aws/credentials", Access: "read", Sensitive: true},
		{Time: t0.Add(4), Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "160.79.104.10", Port: 443, Host: "api.anthropic.com", LLM: true}},
		{Time: t0.Add(5), Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "10.0.0.5", Port: 5432, Service: "postgres"}},
		{Time: t0.Add(6), Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "47.88.1.1", Port: 443, Host: "oss-cn-hangzhou.aliyuncs.com"}},
		{Time: t0.Add(7), Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "10.0.0.9", Port: 6379, Service: "redis"}},
		{Time: t0.Add(8), Type: events.Process, Agent: cl, Exe: "/usr/bin/git", Args: []string{"git", "status"}},
		{Time: t0.Add(9), Type: events.Process, Agent: cl, Exe: "/usr/bin/git", Args: []string{"git", "push"}},
		{Time: t0.Add(10), Type: events.AgentStopped, Agent: cl},
		{Time: t0.Add(11), Type: events.AgentStarted, Agent: cl2},
	}
	sums := Summarize(recs, nil)
	if len(sums) != 2 || sums[0].ID != "claude-code" || sums[1].ID != "codex" {
		t.Fatalf("summaries = %+v", sums)
	}
	s := sums[0]
	if !s.Running || len(s.PIDs) != 2 {
		t.Errorf("runs: running %v pids %v", s.Running, s.PIDs)
	}
	if len(s.Files) != 2 || !s.Files[0].Sensitive || s.Files[1].Access != "write" || s.Files[1].Count != 2 {
		t.Errorf("files = %+v", s.Files)
	}
	want := []string{"alibaba-cloud", "llm", "postgres", "redis"}
	if len(s.Services) != len(want) {
		t.Fatalf("services = %v", s.Services)
	}
	for i := range want {
		if s.Services[i] != want[i] {
			t.Errorf("services = %v, want %v", s.Services, want)
		}
	}
	if len(s.Commands) != 1 || s.Commands[0].Program != "git" || s.Commands[0].Count != 2 {
		t.Errorf("commands = %+v", s.Commands)
	}
	if got := Summarize(recs, func(a events.Agent) bool { return a.ID == "codex" }); len(got) != 1 {
		t.Errorf("filter: %+v", got)
	}
}

func TestCategory(t *testing.T) {
	for d, want := range map[events.Dst]string{
		{IP: "1.2.3.4", Port: 443, Host: "raw.githubusercontent.com"}: "github",
		{IP: "1.2.3.4", Port: 8200, Service: "vault"}:                 "vault",
		{IP: "127.0.0.1", Port: 9999}:                                 "localhost",
		{IP: "192.168.1.4", Port: 9999}:                               "private-network",
		{IP: "8.8.8.8", Port: 443, Host: "example.com"}:               "internet",
		{IP: "8.8.8.8", Port: 443, Host: "notgithub.com"}:             "internet",
	} {
		if got := Category(d); got != want {
			t.Errorf("%+v: %s, want %s", d, got, want)
		}
	}
}
