package detect

import "testing"

func TestRules(t *testing.T) {
	want := map[string]string{RuleARTEX: High, RuleOffensiveTool: High, RuleFanOut: Medium}
	rs := Rules()
	if len(rs) != len(want) {
		t.Fatalf("rules = %+v", rs)
	}
	for _, r := range rs {
		if want[r.ID] != r.Severity || r.Title == "" || r.Description == "" {
			t.Errorf("rule %+v", r)
		}
		delete(want, r.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing rules %v", want)
	}
}

func TestHelpers(t *testing.T) {
	if got := joinCapped([]string{"a", "b", "c"}, 2); got != "a, b and 1 more" {
		t.Errorf("joinCapped = %q", got)
	}
	if got := joinCapped([]string{"a"}, 2); got != "a" {
		t.Errorf("joinCapped = %q", got)
	}
	for in, want := range map[string]string{
		"/usr/bin/nmap": "nmap", `C:\x\Nmap.EXE`: "nmap", "artex": "artex", "": "", "/": "",
	} {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q) = %q, want %q", in, got, want)
		}
	}
}
