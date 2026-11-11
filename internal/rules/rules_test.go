package rules

import (
	"testing"

	"github.com/authsec-ai/authsec-cli/internal/finding"
)

func TestBroadAndShell(t *testing.T) {
	shell := []string{"Bash", "Bash(*)", "Bash(:*)", "*"}
	for _, r := range shell {
		if !isShellAll(r) || !isBroad(r) {
			t.Errorf("%q should be shell-all and broad", r)
		}
	}
	broad := []string{"Write", "WebFetch", "mcp__*", "mcp__github__*(*)", "Edit(**)"}
	for _, r := range broad {
		if !isBroad(r) || isShellAll(r) {
			t.Errorf("%q should be broad only", r)
		}
	}
	narrow := []string{"Bash(git status:*)", "Bash(go test ./...)", "Read", "Read(**)", "WebFetch(domain:docs.example.com)", "mcp__github__get_issue"}
	for _, r := range narrow {
		if isBroad(r) || isShellAll(r) {
			t.Errorf("%q should be narrow", r)
		}
	}
}

func TestApply(t *testing.T) {
	fs := []finding.Finding{
		{Kind: finding.Policy, Attrs: map[string]any{"default_mode": "bypassPermissions", "allow": []string{"Bash(*)", "Read"}}},
		{Kind: finding.Policy, Attrs: map[string]any{"default_mode": "default", "allow": []string{"Bash(git status:*)"}}},
		{Kind: finding.MCPServer, Attrs: map[string]any{"launcher": "npx", "package": "pkg", "pinned": false, "env_names": []string{"LOG_LEVEL", "GITHUB_TOKEN"}}},
		{Kind: finding.MCPServer, Attrs: map[string]any{"launcher": "npx", "package": "pkg@1.0.0", "pinned": true}},
		{Kind: finding.Extension, Attrs: map[string]any{"hook_type": "command", "command": "echo hi\nmore", "event": "Stop"}},
		{Kind: finding.Extension, Attrs: map[string]any{"type": "skill", "allowed_tools": []string{"Bash"}}},
	}
	Apply(fs)
	want := [][]string{
		{AutoApproveShell, BroadAllow},
		nil,
		{MCPUnpinned, SecretInMCPEnv},
		nil,
		{HookRunsCommand},
		{AutoApproveShell, BroadAllow},
	}
	for i, w := range want {
		var got []string
		for _, s := range fs[i].Signals {
			got = append(got, s.ID)
			if s.Reason == "" {
				t.Errorf("finding %d: signal %s has no reason", i, s.ID)
			}
		}
		if len(got) != len(w) {
			t.Errorf("finding %d: signals %v, want %v", i, got, w)
			continue
		}
		for j := range w {
			if got[j] != w[j] {
				t.Errorf("finding %d: signals %v, want %v", i, got, w)
			}
		}
	}
	if r := fs[2].Signals[1].Reason; r != "given GITHUB_TOKEN" {
		t.Errorf("secret reason = %q", r)
	}
	if r := fs[4].Signals[0].Reason; r != `runs "echo hi …" on Stop` {
		t.Errorf("hook reason = %q", r)
	}
}
