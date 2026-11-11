package parse

import (
	"reflect"
	"strings"
	"testing"
)

func TestJSONC(t *testing.T) {
	in := "\xef\xbb\xbf" + `{
  // a line comment with a "quote"
  "a": "has // no comment, and /* none */ either",
  /* a block
     comment */
  "b": [1, 2, 3,],
  "c": {"d": "x\"y",},
}`
	m, err := JSONC([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := String(m, "a"); got != `has // no comment, and /* none */ either` {
		t.Errorf("string altered: %q", got)
	}
	if got := String(Map(m, "c"), "d"); got != `x"y` {
		t.Errorf("escaped quote: %q", got)
	}
	if l, _ := m["b"].([]any); len(l) != 3 {
		t.Errorf("trailing comma in list: %v", m["b"])
	}
}

func TestJSONCRejectsGarbage(t *testing.T) {
	if _, err := JSONC([]byte(`{"a": `)); err == nil {
		t.Fatal("want an error for truncated JSON")
	}
}

func TestLooksSecret(t *testing.T) {
	secret := []string{
		"sk-ant-api03-abcdefghijklmnop",
		"ghp_abcdefghijklmnopqrstuvwxyz0123",
		"AKIAABCDEFGHIJKLMNOP",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl",
		"aid_abcdefghijklmnopqrstu",
		"q8Zr3LmX9vB2nT7kW4pY1sD6fH0jG5cE",         // random run
		"d5f0b3c8e2a19f7c6b4d8e0a3f2c1b9e7d6a5c4b", // sha1-like hex
	}
	for _, s := range secret {
		if !LooksSecret(s) {
			t.Errorf("LooksSecret(%q) = false", s)
		}
	}
	notSecret := []string{
		"103_add_user_flow_permissions.sql",
		"21e0a45c-9b3d-4942-b912-1aaae3cf930e", // a UUID (client id)
		"@modelcontextprotocol/server-github",
		"/home/user/projects/something-long-path",
		"short",
		"Screenshot_from_2024-01-01_12-00-00.png",
		"mcp-server-kubernetes-integration",
	}
	for _, s := range notSecret {
		if LooksSecret(s) {
			t.Errorf("LooksSecret(%q) = true", s)
		}
	}
}

func TestSensitiveName(t *testing.T) {
	for _, n := range []string{"OPENAI_API_KEY", "GITHUB_PERSONAL_ACCESS_TOKEN", "--password", "DATABASE_URL", "Authorization", "AWS_SECRET_ACCESS_KEY", "GITHUB_PAT", "PG_DSN", "x-api-key"} {
		if !SensitiveName(n) {
			t.Errorf("SensitiveName(%q) = false", n)
		}
	}
	for _, n := range []string{"PATH", "HOME", "LOG_LEVEL", "Content-Type", "--port", "REGION"} {
		if SensitiveName(n) {
			t.Errorf("SensitiveName(%q) = true", n)
		}
	}
}

func TestArgs(t *testing.T) {
	in := []string{"-y", "@scope/pkg@1.2.0", "--api-key", "plain-value", "--token=abc123", "GITHUB_TOKEN=xyz", "--port", "8080", "https://u:p@host/x?k=v&token=t"}
	want := []string{"-y", "@scope/pkg@1.2.0", "--api-key", Redacted, "--token=" + Redacted, "GITHUB_TOKEN=" + Redacted, "--port", "8080", "https://host/x?k=v&token=" + Redacted}
	if got := Args(in); !reflect.DeepEqual(got, want) {
		t.Errorf("Args:\n got %q\nwant %q", got, want)
	}
}

func TestURL(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@api.example.com/v1?b=2&a=1":            "https://api.example.com/v1?a=1&b=2",
		"https://api.example.com/x?access_token=abc&code=xyz&q=1": "https://api.example.com/x?access_token=" + Redacted + "&code=" + Redacted + "&q=1",
		"https://h.example.com/p#frag":                            "https://h.example.com/p",
	}
	for in, want := range cases {
		if got := URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestText(t *testing.T) {
	in := `curl -H "Authorization: Bearer sk-live-PLANTEDsecretVALUE123456" https://x.example.com/?token=t PGPASSWORD=hunter2 psql`
	got := Text(in)
	for _, leak := range []string{"PLANTEDsecretVALUE", "hunter2", "token=t"} {
		if strings.Contains(got, leak) {
			t.Errorf("Text leaked %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "curl") || !strings.Contains(got, "psql") {
		t.Errorf("Text removed ordinary words: %s", got)
	}
	plain := "go test ./...\nmake lint"
	if Text(plain) != plain {
		t.Errorf("Text changed text with nothing to scrub: %q", Text(plain))
	}
}
