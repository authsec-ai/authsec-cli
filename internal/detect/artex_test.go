package detect

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const planted = "sk-ant-api03-PLANTEDsecretVALUEdoNOTleak0123456789"

// files returns a statFile that reports the given paths (joined under dir)
// as existing and records every path asked.
func files(dir string, rel ...string) (func(string) bool, *[]string) {
	set := map[string]bool{}
	for _, r := range rel {
		set[filepath.Join(dir, filepath.FromSlash(r))] = true
	}
	var asked []string
	return func(p string) bool {
		asked = append(asked, p)
		return set[p]
	}, &asked
}

func noLeak(t *testing.T, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), planted) || strings.Contains(string(b), "PLANTED") {
		t.Fatalf("secret in output: %s", b)
	}
}

func TestARTEXProcess(t *testing.T) {
	dir := filepath.Join(string(filepath.Separator)+"opt", "artex")
	exe := filepath.Join(dir, "artex")
	other := filepath.Join(string(filepath.Separator)+"opt", "app", "server")
	appDir := filepath.Dir(other)
	cases := []struct {
		name     string
		p        Process
		stat     []string // existing files, relative to the exe's dir
		severity string   // "" = no detection
		evidence []string // substrings that must appear
	}{
		{name: "binary name", p: Process{PID: 7, Comm: "artex", Exe: exe,
			Args: []string{exe, "-addr", "127.0.0.1:8787", "-proxy", "127.0.0.1:8788"}},
			severity: High, evidence: []string{"binary name artex", "ARTEX flags: -addr, -proxy"}},
		{name: "windows binary", p: Process{PID: 8, Comm: "artex.exe", Exe: `C:\tools\ARTEX.exe`},
			severity: High, evidence: []string{"binary name artex"}},
		{name: "comm only", p: Process{PID: 9, Comm: "artex"}, severity: High},
		{name: "env names", p: Process{PID: 10, Comm: "start.sh", Exe: "/bin/sh",
			EnvNames: []string{"HOME", "ARTEX_PG_DSN", "ARTEX_JWT_KEY_DIR", "ARTEX_PG_DSN"}},
			severity: High, evidence: []string{"ARTEX environment variables: ARTEX_JWT_KEY_DIR, ARTEX_PG_DSN"}},
		{name: "renamed binary with ARTEX layout", p: Process{PID: 11, Comm: "server", Exe: other},
			stat: []string{"jwt.key", "data", "skills"}, severity: High,
			evidence: []string{"next to the binary: jwt.key, data/, skills/"}},
		{name: "docker layout", p: Process{PID: 12, Comm: "server", Exe: other},
			stat: []string{"keys/jwt.key", "data", "skills"}, severity: High,
			evidence: []string{"keys/jwt.key"}},
		{name: "ports with flags", p: Process{PID: 13, Comm: "server", Exe: other,
			Args: []string{other, "--addr=:8787", "-proxy", ":8788"}, Listen: []int{8787, 8788}},
			severity: Medium, evidence: []string{"8787 (ARTEX web UI) and 8788", "-addr, -proxy"}},
		{name: "port with partial layout", p: Process{PID: 14, Comm: "server", Exe: other, Listen: []int{8788}},
			stat: []string{"jwt.key", "data", "config.json"}, severity: Medium,
			evidence: []string{"8788 (ARTEX traffic proxy)", "config.json"}},
		// Near misses: no detection.
		{name: "ports only", p: Process{PID: 20, Comm: "python3", Exe: "/usr/bin/python3", Listen: []int{8787, 8788}}},
		{name: "one flag and a port", p: Process{PID: 21, Comm: "server", Exe: other,
			Args: []string{other, "-addr", ":8787"}, Listen: []int{8787}}},
		{name: "similar names", p: Process{PID: 22, Comm: "artexplorer", Exe: "/usr/bin/artexplorer",
			EnvNames: []string{"ARTEX", "MYARTEX_X", "ARTEXT_FOO"}}},
		{name: "jwt.key alone", p: Process{PID: 23, Comm: "server", Exe: other}, stat: []string{"jwt.key"}},
		{name: "data and skills alone", p: Process{PID: 24, Comm: "server", Exe: other}, stat: []string{"data", "skills"}},
		{name: "flag value is not a flag", p: Process{PID: 25, Comm: "curl", Exe: "/usr/bin/curl",
			Args: []string{"curl", "addr", "proxy", "data"}, Listen: []int{8787}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.p.Args = append(c.p.Args, "--api-key", planted)
			stat, _ := files(filepath.Dir(c.p.Exe), c.stat...)
			if c.p.Exe == other {
				stat, _ = files(appDir, c.stat...)
			}
			d := ARTEXProcess(c.p, stat)
			if c.severity == "" {
				if d != nil {
					t.Fatalf("unexpected detection: %+v", d)
				}
				return
			}
			if d == nil {
				t.Fatal("no detection")
			}
			if d.Rule != RuleARTEX || d.Severity != c.severity || d.PID != c.p.PID || d.AgentID != "artex" || d.Title == "" {
				t.Fatalf("detection = %+v", d)
			}
			all := strings.Join(d.Evidence, "\n")
			for _, e := range c.evidence {
				if !strings.Contains(all, e) {
					t.Errorf("evidence %q missing in %q", e, all)
				}
			}
			noLeak(t, d)
		})
	}
}

func TestARTEXProcessStatsCheaply(t *testing.T) {
	stat, asked := files("/nowhere")
	if d := ARTEXProcess(Process{PID: 1, Comm: "bash", Exe: "/usr/bin/bash"}, stat); d != nil {
		t.Fatalf("unexpected %+v", d)
	}
	if len(*asked) != 2 {
		t.Fatalf("an ordinary process should cost two stats (the key files), got %v", *asked)
	}
	if d := ARTEXProcess(Process{PID: 1, Comm: "artex"}, nil); d == nil {
		t.Fatal("nil statFile must skip the file checks only")
	}
	_, asked = files("/nowhere")
	if d := ARTEXProcess(Process{PID: 1, Comm: "x", Exe: "x"}, func(p string) bool { *asked = append(*asked, p); return true }); d != nil || len(*asked) != 0 {
		t.Fatalf("a relative exe has no directory to check: %+v %v", d, *asked)
	}
}

func TestARTEXContainers(t *testing.T) {
	cases := []struct {
		names []string
		want  []string // container names in the evidence; nil = no detection
	}{
		{[]string{"artex-artex-1", "artex-postgres-1"}, []string{"artex-artex-1", "artex-postgres-1"}},
		{[]string{"pentest-artex-1", "pentest-postgres-1"}, []string{"pentest-artex-1"}},
		{[]string{"pentest_artex_2"}, []string{"pentest_artex_2"}},
		{[]string{"artex-bench"}, []string{"artex-bench"}},
		{[]string{"artex-pg"}, []string{"artex-pg"}},
		{[]string{"/ARTEX"}, []string{"ARTEX"}},
		{[]string{"web,artex-artex-1"}, []string{"artex-artex-1"}},
		// Near misses.
		{[]string{"artexplorer", "cartex-1", "my-artexx-1", "postgres-1", "smartex", "x-artex-db", "x-artex-", "artex1"}, nil},
		{nil, nil},
	}
	for _, c := range cases {
		d := ARTEXContainers(c.names)
		if c.want == nil {
			if d != nil {
				t.Errorf("%v: unexpected %+v", c.names, d)
			}
			continue
		}
		if d == nil || d.Rule != RuleARTEX || d.Severity != High || d.AgentID != "artex" {
			t.Fatalf("%v: detection = %+v", c.names, d)
		}
		ev := strings.Join(d.Evidence, " ")
		for _, w := range c.want {
			if !strings.Contains(ev, w) {
				t.Errorf("%v: %q missing in %q", c.names, w, ev)
			}
		}
	}
}

func fakeRuntimes(t *testing.T, installed map[string]bool, out map[string]string, fail map[string]bool) *[]string {
	t.Helper()
	oldLook, oldRun := lookPath, runCommand
	t.Cleanup(func() { lookPath, runCommand = oldLook, oldRun })
	var calls []string
	lookPath = func(name string) (string, error) {
		if installed[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	runCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("no timeout")
		}
		calls = append(calls, name+" "+strings.Join(args, " "))
		rt := filepath.Base(name)
		if fail[rt] {
			return nil, errors.New("daemon not running")
		}
		return []byte(out[rt]), nil
	}
	return &calls
}

func TestContainers(t *testing.T) {
	calls := fakeRuntimes(t, map[string]bool{"docker": true, "podman": true},
		map[string]string{"docker": "artex-artex-1\n\nweb\n", "podman": "artex-pg\n"}, nil)
	got := Containers()
	if strings.Join(got, ",") != "artex-artex-1,web,artex-pg" {
		t.Fatalf("Containers = %v", got)
	}
	if len(*calls) != 2 || (*calls)[0] != "/usr/bin/docker ps --format {{.Names}}" {
		t.Fatalf("calls = %v", *calls)
	}

	fakeRuntimes(t, map[string]bool{"podman": true}, map[string]string{"podman": "a\n"}, nil)
	if got := Containers(); len(got) != 1 || got[0] != "a" {
		t.Fatalf("podman only = %v", got)
	}

	fakeRuntimes(t, nil, nil, nil)
	if got := Containers(); got != nil {
		t.Fatalf("no runtime = %v", got)
	}

	fakeRuntimes(t, map[string]bool{"docker": true, "podman": true}, map[string]string{"podman": "a\n"}, map[string]bool{"docker": true})
	if got := Containers(); got != nil {
		t.Fatalf("error must give nil, got %v", got)
	}
}

func TestARTEXEnvNamesNeverCarryValues(t *testing.T) {
	d := ARTEXProcess(Process{PID: 7, Comm: "bash", EnvNames: []string{"ARTEX_PG_DSN=postgres://artex:" + planted + "@db/artex", "PATH"}}, nil)
	if d == nil || d.Severity != High || !strings.Contains(strings.Join(d.Evidence, " "), "ARTEX_PG_DSN") {
		t.Fatalf("detection = %+v", d)
	}
	noLeak(t, d)
}

func TestRunCommandStopsAtTheDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	// The background sleep keeps stdout open after sh is killed.
	_, _ = runCommand(ctx, sh, "-c", "sleep 4 & sleep 4")
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("runCommand took %s after a 100ms deadline", d)
	}
}
