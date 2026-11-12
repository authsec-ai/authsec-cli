package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
)

// writeLog writes an event log with one Claude Code session.
func writeLog(t *testing.T, path string) {
	t.Helper()
	w, err := events.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cl := &events.Agent{ID: "claude-code", Name: "Claude Code", PID: 10}
	now := time.Now().Add(-time.Hour)
	for _, r := range []events.Record{
		{Time: now, Type: events.AgentStarted, Agent: cl},
		{Time: now, Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "160.79.104.10", Port: 443, Host: "api.anthropic.com", LLM: true}},
		{Time: now, Type: events.Network, Agent: cl, Dst: &events.Dst{IP: "140.82.112.3", Port: 443, Host: "github.com"}},
		{Time: now, Type: events.File, Agent: cl, Path: "/srv/app/main.go", Access: "write"},
		{Time: now, Type: events.Process, Agent: cl, Exe: "/usr/bin/git", Args: []string{"git", "push", "--force"}},
	} {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
}

func run(args ...string) (string, error) {
	var out, errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String() + errOut.String(), err
}

func TestPolicyGenerateCheckTest(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")
	writeLog(t, logPath)
	pol := filepath.Join(dir, "policies")

	out, err := run("policy", "generate", "--dir", pol, "--log", logPath, "--agent", "claude-code")
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(pol, "claude-code.yaml")); err != nil {
		t.Fatalf("no policy written:\n%s", out)
	}
	// A second run keeps the edited file.
	if out, _ := run("policy", "generate", "--dir", pol, "--log", logPath, "--agent", "claude-code"); !strings.Contains(out, "kept") {
		t.Errorf("existing policy overwritten:\n%s", out)
	}

	out, err = run("policy", "check", "--dir", pol, "--log", logPath)
	if err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "[ok]") || !strings.Contains(out, "deny  command  git push --force") {
		t.Errorf("check output:\n%s", out)
	}

	out, err = run("policy", "test", "claude-code", "--dir", pol, "--host", "example.com")
	if err != nil || !strings.Contains(out, "DENY by network.default (monitor mode") {
		t.Errorf("test: %v\n%s", err, out)
	}
	out, _ = run("policy", "test", "claude-code", "--dir", pol, "--host", "github.com")
	if !strings.Contains(out, "ALLOW") {
		t.Errorf("observed destination not allowed:\n%s", out)
	}

	// A broken file fails the check with exit code 1 and a line number.
	if err := os.WriteFile(filepath.Join(pol, "bad.yaml"), []byte("apiVersion: authsec.ai/v1\nkind: AgentPolicy\nagent: {id: codex}\nmode: block\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = run("policy", "check", "--dir", pol, "--log", logPath)
	if exitCode(err) != ExitSignal || !strings.Contains(out, "line 4: mode") {
		t.Errorf("broken policy: exit %d\n%s", exitCode(err), out)
	}
}

func TestPolicyEditRunsEditorAndChecks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as the editor")
	}
	dir := t.TempDir()
	pol := filepath.Join(dir, "policies")
	logPath := filepath.Join(dir, "events.jsonl")
	writeLog(t, logPath)
	if out, err := run("policy", "generate", "--dir", pol, "--log", logPath, "--agent", "claude-code"); err != nil {
		t.Fatalf("generate: %v %s", err, out)
	}
	// The "editor" switches the policy to enforce mode.
	editor := filepath.Join(dir, "ed.sh")
	if err := os.WriteFile(editor, []byte("#!/bin/sh\nsed -i.bak 's/^mode: monitor/mode: enforce/' \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", editor)
	out, err := run("policy", "edit", "claude-code", "--dir", pol)
	if err != nil || !strings.Contains(out, "ok (mode enforce)") {
		t.Fatalf("edit: %v\n%s", err, out)
	}
	// An editor that breaks the file: the user declines to edit again.
	if err := os.WriteFile(editor, []byte("#!/bin/sh\nsed -i.bak 's/^mode: enforce/mode: nope/' \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var outBuf bytes.Buffer
	root := NewRoot(&outBuf, &outBuf)
	root.SetIn(strings.NewReader("n\n"))
	root.SetArgs([]string{"policy", "edit", "claude-code", "--dir", pol})
	err = root.Execute()
	if exitCode(err) != ExitSignal || !strings.Contains(outBuf.String(), "Edit again?") {
		t.Errorf("broken edit: exit %d\n%s", exitCode(err), outBuf.String())
	}
}
