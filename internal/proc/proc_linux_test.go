//go:build linux

package proc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const planted = "sk-ant-api03-PLANTEDsecretVALUEdoNOTleak0123456789"

// fakeProc builds a /proc tree with a shell (100) and a claude (200) that has
// a secret on its command line and in its environment, an HTTPS connection
// to 160.79.104.10 and a listening socket.
func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	w := func(rel, data string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	w("stat", "cpu 1 2 3\nbtime 1700000000\n")
	w("100/stat", "100 (bash) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0")
	w("100/status", "Name:\tbash\nUid:\t1000\t1000\t1000\t1000\n")
	w("100/cmdline", "bash\x00")
	w("100/environ", "HOME=/home/u\x00")
	link("/usr/bin/bash", "100/exe")

	w("200/stat", "200 (claude code) S 100 200 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1000 0 0")
	w("200/status", "Name:\tclaude\nUid:\t1000\t1000\t1000\t1000\n")
	w("200/cmdline", "claude\x00--api-key\x00"+planted+"\x00")
	w("200/environ", "ANTHROPIC_API_KEY="+planted+"\x00PATH=/usr/bin\x00")
	link("/home/u/.local/share/claude/versions/2.1.3", "200/exe")
	link("socket:[5555]", "200/fd/3")
	link("socket:[6666]", "200/fd/4")
	link("/dev/null", "200/fd/0")

	w("net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 6666 1\n"+
		"   1: 0201A8C0:D431 0A684FA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 5555 1\n"+
		"   2: 0201A8C0:D432 0A684FA0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 7777 1\n")
	return root
}

func TestReadProc(t *testing.T) {
	s, err := readProc(fakeProc(t))
	if err != nil {
		t.Fatal(err)
	}
	c := s.Procs[200]
	if c == nil || c.Comm != "claude code" || c.PPID != 100 || c.UID != 1000 {
		t.Fatalf("claude = %+v", c)
	}
	if c.Exe != "/home/u/.local/share/claude/versions/2.1.3" {
		t.Errorf("exe = %q", c.Exe)
	}
	if strings.Join(c.EnvNames, ",") != "ANTHROPIC_API_KEY,PATH" {
		t.Errorf("env names = %v", c.EnvNames)
	}
	if c.Started.Unix() != 1700000000+10 {
		t.Errorf("started = %v", c.Started)
	}
	if len(s.Conns) != 2 {
		t.Fatalf("conns = %+v (socket 7777 belongs to no process and must be dropped)", s.Conns)
	}
	var est, lis *Conn
	for i := range s.Conns {
		if s.Conns[i].Listen {
			lis = &s.Conns[i]
		} else {
			est = &s.Conns[i]
		}
	}
	if est == nil || est.PID != 200 || est.RemoteIP.String() != "160.79.104.10" || est.RemotePort != 443 || est.LocalIP.String() != "192.168.1.2" {
		t.Errorf("established = %+v", est)
	}
	if lis == nil || lis.LocalPort != 8080 || lis.LocalIP.String() != "127.0.0.1" {
		t.Errorf("listen = %+v", lis)
	}
	// Environment values are never kept.
	for _, p := range s.Procs {
		for _, n := range p.EnvNames {
			if strings.Contains(n, planted) {
				t.Fatal("environment value kept")
			}
		}
	}
}

func TestHexAddrV6(t *testing.T) {
	// ::1 in /proc/net/tcp6 word order.
	ip, port, ok := hexAddr("00000000000000000000000001000000:01BB")
	if !ok || ip.String() != "::1" || port != 443 {
		t.Errorf("got %v %d %v", ip, port, ok)
	}
}

func TestEnvNames(t *testing.T) {
	got := envNames([]byte("B=1\x00A=x=y\x00=bad\x00NOVALUE\x00"))
	if strings.Join(got, ",") != "A,B" {
		t.Errorf("got %v", got)
	}
}
