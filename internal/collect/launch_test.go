package collect

import "testing"

func TestAnalyzeLaunch(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		ok   bool
		want launch
	}{
		{"npx", []string{"-y", "@modelcontextprotocol/server-github"}, true, launch{"npx", "@modelcontextprotocol/server-github", false}},
		{"npx", []string{"-y", "@modelcontextprotocol/server-github@2025.4.8"}, true, launch{"npx", "@modelcontextprotocol/server-github@2025.4.8", true}},
		{"npx", []string{"mcp-remote@latest", "https://x"}, true, launch{"npx", "mcp-remote@latest", false}},
		{"npx", []string{"--package", "pkg@1.0.0", "bin"}, true, launch{"npx", "pkg@1.0.0", true}},
		{`C:\Program Files\nodejs\npx.cmd`, []string{"-y", "pkg"}, true, launch{"npx", "pkg", false}},
		{"pnpm", []string{"dlx", "pkg@^1"}, true, launch{"pnpm dlx", "pkg@^1", false}},
		{"uvx", []string{"mcp-server-fetch"}, true, launch{"uvx", "mcp-server-fetch", false}},
		{"uvx", []string{"mcp-server-fetch==0.6.2"}, true, launch{"uvx", "mcp-server-fetch==0.6.2", true}},
		{"uvx", []string{"--from", "git+https://x/repo", "tool"}, true, launch{"uvx", "git+https://x/repo", false}},
		{"docker", []string{"run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server"}, true, launch{"docker", "ghcr.io/github/github-mcp-server", false}},
		{"docker", []string{"run", "-i", "ghcr.io/github/github-mcp-server:v0.5.0"}, true, launch{"docker", "ghcr.io/github/github-mcp-server:v0.5.0", true}},
		{"docker", []string{"run", "localhost:5000/img@sha256:abc"}, true, launch{"docker", "localhost:5000/img@sha256:abc", true}},
		{"node", []string{"server.js"}, false, launch{}},
		{"/usr/local/bin/my-mcp", nil, false, launch{}},
	}
	for _, c := range cases {
		got, ok := analyzeLaunch(c.cmd, c.args)
		if ok != c.ok || got != c.want {
			t.Errorf("analyzeLaunch(%q, %q) = %+v, %v; want %+v, %v", c.cmd, c.args, got, ok, c.want, c.ok)
		}
	}
}

func TestToolList(t *testing.T) {
	got := toolList("Read, Grep, Bash(git add:*, git status:*)")
	if len(got) != 3 || got[2] != "Bash(git add:*, git status:*)" {
		t.Errorf("toolList = %q", got)
	}
	got = toolList([]any{"Read", "Write"})
	if len(got) != 2 {
		t.Errorf("toolList list = %q", got)
	}
}
