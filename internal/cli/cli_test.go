package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execute(args ...string) (string, error) {
	var out, errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestScanJSON(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"permissions": {"allow": ["Bash"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := execute("scan", "--home", home, "--no-known-projects", "--json", "--only", "policies")
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Findings []struct{ Kind string } `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if len(r.Findings) != 1 || r.Findings[0].Kind != "agent_policy" {
		t.Errorf("findings = %+v", r.Findings)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--only", "bogus"},
		{"scan", "--no-such-flag"},
		{"scan", "extra-arg"},
	} {
		_, err := execute(args...)
		if got := exitCode(err); got != ExitUsage {
			t.Errorf("%v: exit %d (%v), want %d", args, got, err, ExitUsage)
		}
	}
	if got := exitCode(ioErr(errors.New("x"))); got != ExitIO {
		t.Errorf("io error: exit %d", got)
	}
	if got := exitCode(nil); got != ExitOK {
		t.Errorf("nil: exit %d", got)
	}
}

func TestCatalogueListsEveryEntry(t *testing.T) {
	out, err := execute("catalogue", "--all")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"{home}/.claude/settings.json", "{project}/.mcp.json", "/etc/claude-code/managed-settings.json  [linux]"} {
		if !strings.Contains(out, want) {
			t.Errorf("catalogue missing %q", want)
		}
	}
}

func TestEveryErrorIsPrinted(t *testing.T) {
	// Exit code 1 errors (policy errors, refused daemon calls) must reach
	// the user: only an empty message is silent.
	for _, err := range []error{&ExitError{Code: ExitSignal, Err: errors.New("quarantine needs root (sudo)")}, ioErr(errors.New("x"))} {
		if err.Error() == "" {
			t.Fatal("empty")
		}
	}
	var out, errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	root.SetArgs([]string{"policy", "check", "--dir", t.TempDir()})
	err := root.Execute()
	if exitCode(err) != ExitUsage || err == nil || err.Error() == "" {
		t.Errorf("empty policy folder: %v", err)
	}
}

func TestDay5CLIHelpers(t *testing.T) {
	if got := termSafe("ok\x1b[2Jfake\nline x"); strings.ContainsAny(got, "\x1b\n ") {
		t.Errorf("termSafe kept control characters: %q", got)
	}
	t.Setenv("AUTHSEC_TEST_TOKEN", "")
	if _, err := tokenEnvFor(true, "AUTHSEC_TEST_TOKEN"); err == nil {
		t.Error("an explicit, unset token variable was accepted")
	}
	if te, err := tokenEnvFor(false, "AUTHSEC_TEST_TOKEN"); err != nil || te != "" {
		t.Errorf("default, unset: %q %v", te, err)
	}
	u := unit("/usr/local/bin/authsec-cli", "/var/lib/authsec/events.jsonl", []string{"--siem", "webhook+https://h/p?a=1&b=$X%", "--quarantine-threats"})
	if !strings.Contains(u, `"webhook+https://h/p?a=1&b=$$X%%"`) || !strings.Contains(u, "EnvironmentFile=-/etc/authsec/siem.env") || !strings.Contains(u, "--quarantine-threats") {
		t.Errorf("unit:\n%s", u)
	}
}
