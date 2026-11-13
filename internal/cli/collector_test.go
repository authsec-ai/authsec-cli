package cli

import (
	"reflect"
	"testing"
)

func TestAliasArgs(t *testing.T) {
	cases := []struct {
		argv0 string
		in    []string
		want  []string
	}{
		{"/usr/local/bin/authsec-local", []string{"run", "--enrollment-token-file", "/tmp/t"}, []string{"collector", "run", "--enrollment-token-file", "/tmp/t"}},
		{"authsec-local", []string{"status"}, []string{"collector", "status"}},
		{"authsec-local", []string{"agents"}, []string{"agents"}},
		{"authsec-cli", []string{"run", "--enforce"}, []string{"run", "--enforce"}},
	}
	for _, c := range cases {
		if got := AliasArgs(c.argv0, c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %v: %v, want %v", c.argv0, c.in, got, c.want)
		}
	}
}

func TestSplitCollectorFlags(t *testing.T) {
	u, tok, d, help, rest, err := splitCollectorFlags([]string{"--url=https://x", "--enrollment-token-file", "/tmp/t", "--no-ebpf", "--state-dir", "/s", "--poll", "2s"})
	if err != nil || u != "https://x" || tok != "/tmp/t" || d != "/s" || help || !reflect.DeepEqual(rest, []string{"--no-ebpf", "--poll", "2s"}) {
		t.Errorf("%q %q %q %v %v %v", u, tok, d, help, rest, err)
	}
	if _, _, _, _, _, err := splitCollectorFlags([]string{"--url"}); err == nil {
		t.Error("a flag without its value was accepted")
	}
}
