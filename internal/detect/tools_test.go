package detect

import (
	"strings"
	"testing"
)

func TestOffensiveTool(t *testing.T) {
	cases := []struct {
		argv string // split on spaces; "|" in place of a space inside one argument
		want string // "" = no match
	}{
		{"nmap -sV 10.0.0.0/24", "nmap"},
		{"/usr/bin/masscan -p1-65535 10.0.0.1", "masscan"},
		{`C:\Tools\Nmap\NMAP.EXE -sS host`, "nmap"},
		{"sqlmap -u http://x/?id=1 --batch", "sqlmap"},
		{"nuclei -u https://x -t cves/", "nuclei"},
		{"ffuf -w words -u https://x/FUZZ", "ffuf"},
		{"gobuster dir -u x", "gobuster"},
		{"feroxbuster -u x", "feroxbuster"},
		{"hydra -l admin -P pw.txt ssh://x", "hydra"},
		{"msfconsole -q -x use", "msfconsole"},
		{"msfvenom -p linux/x64/shell", "msfvenom"},
		{"hashcat -m 1000 h.txt", "hashcat"},
		{"nxc smb 10.0.0.0/24", "nxc"},
		{"chisel client x R:socks", "chisel"},
		{"ligolo-ng -selfcert", "ligolo-ng"},
		{"ligolo-proxy -selfcert", "ligolo-proxy"},
		{"impacket-secretsdump dom/u@x", "impacket-secretsdump"},
		{"katana -u https://x", "katana"},
		{"dalfox url https://x", "dalfox"},
		{"bbot -t x -p subdomain-enum", "bbot"},
		{"subfinder -d x.com -silent", "subfinder"},
		{"httpx -l hosts.txt -sc -title", "httpx"},
		{"httpx -u https://x -silent", "httpx"},
		{"httpx --status-code -l x", "httpx"},
		// Through wrappers.
		{"sudo nmap -sS x", "nmap"},
		{"sudo -u root -E -- masscan x", "masscan"},
		{"sudo FOO=1 nmap x", "nmap"},
		{"doas nmap x", "nmap"},
		{"env -i PATH=/usr/bin TOKEN=x nmap x", "nmap"},
		{"env -u HOME nuclei -u x", "nuclei"},
		{"env -S nuclei|-u|x", "nuclei"},
		{"timeout 300 ffuf -u x", "ffuf"},
		{"timeout -s KILL --preserve-status 5m nmap x", "nmap"},
		{"nohup chisel server", "chisel"},
		{"nice -n 10 hashcat x", "hashcat"},
		{"proxychains4 -q sqlmap -u x", "sqlmap"},
		{"sudo timeout 60 env A=b nmap x", "nmap"},
		// Interpreters running a tool script.
		{"python3 sqlmap.py -u x", "sqlmap"},
		{"python3 -u /opt/sqlmap/sqlmap.py -u x", "sqlmap"},
		{"/usr/bin/python3.12 -W ignore dirsearch.py -u x", "dirsearch"},
		{"python /opt/Responder/Responder.py -I eth0", "responder"},
		{"python3 secretsdump.py dom/u@x", "impacket-secretsdump"},
		{"python3 -m impacket.examples.psexec dom/u@x", "impacket-psexec"},
		{"perl nikto.pl -h x", "nikto"},
		{"./sqlmap.py -u x", "sqlmap"},
		// Shell command strings.
		{"bash -c nmap|-sV|x", "nmap"},
		{"/bin/bash -lc cd|/tmp|&&|nuclei|-u|x", "nuclei"},
		{"sh -c FOO=1|ffuf|-u|x", "ffuf"},
		{"bash --norc -o pipefail -c echo|x|;|sudo|masscan|x", "masscan"},
		{"busybox sh -c nmap|x", "nmap"},
		{"bash -c cat|out|>|f|$(sqlmap|-u|x)", "sqlmap"},

		// Near misses: must not match.
		{"pip install httpx", ""},
		{"pip3 install sqlmap nmap", ""},
		{"python3 -m pip install sqlmap", ""},
		{"python3 -m httpx https://x", ""},
		{"python3 -c import|httpx", ""},
		{"httpx https://example.com --follow-redirects", ""},
		{"httpx https://x -m GET -h a b -j {}", ""},
		{"httpx", ""},
		{"apt install nmap", ""},
		{"man nmap", ""},
		{"which nmap", ""},
		{"cat sqlmap.py", ""},
		{"vim nuclei.yaml", ""},
		{"grep -r hydra .", ""},
		{"hydrate --all", ""},
		{"john-doe-report", ""},
		{"ligolo-", ""},
		{"impacket-", ""},
		{"PsExec.exe \\\\host cmd", ""},
		{"psexec \\\\host cmd", ""},
		{"bash build.sh", ""},
		{"bash -c echo|nmap", ""},
		{"sudo -i", ""},
		{"timeout 5", ""},
		{"env", ""},
		{"python3", ""},
		{"node nmap.js", ""},
		{"", ""},
	}
	for _, c := range cases {
		var argv []string
		if c.argv != "" {
			for _, w := range strings.Split(c.argv, " ") {
				argv = append(argv, strings.ReplaceAll(w, "|", " "))
			}
		}
		argv = append(argv, "--password="+planted)
		if c.argv == "" {
			argv = nil
		}
		got, ok := OffensiveTool(argv)
		if ok != (c.want != "") || got != c.want && ok {
			t.Errorf("OffensiveTool(%q) = %q, %v; want %q", c.argv, got, ok, c.want)
		}
		if strings.Contains(strings.ToLower(got), "planted") {
			t.Errorf("secret in tool name %q", got)
		}
	}
}

func TestOffensiveToolDepthBounded(t *testing.T) {
	argv := []string{}
	for i := 0; i < 50; i++ {
		argv = append(argv, "sudo")
	}
	argv = append(argv, "nmap")
	if _, ok := OffensiveTool(argv); ok {
		t.Fatal("wrappers beyond the depth limit must not be followed")
	}
	if got, ok := OffensiveTool([]string{"sudo", "sudo", "nmap"}); !ok || got != "nmap" {
		t.Fatalf("got %q %v", got, ok)
	}
}

// Review fixes: homonyms, interpreter options, cmd /c and family names.
func TestOffensiveToolReviewCases(t *testing.T) {
	cases := []struct {
		argv []string
		want string // "" = no match
	}{
		// Ory Hydra (an OAuth2 server AuthSec itself runs) is not THC Hydra.
		{[]string{"hydra", "serve", "all", "--dev"}, ""},
		{[]string{"/usr/bin/hydra", "migrate", "sql", "-e", "--yes"}, ""},
		{[]string{"hydra", "create", "client", "--endpoint", "http://x"}, ""},
		{[]string{"hydra", "version"}, ""},
		{[]string{"hydra", "--skip-tls-verify", "list", "clients"}, ""},
		{[]string{"sh", "-c", "hydra serve all -c /etc/hydra.yml"}, ""},
		{[]string{"hydra", "-l", "admin", "-P", "pw.txt", "10.0.0.1", "ssh"}, "hydra"},
		{[]string{"hydra", "ssh://10.0.0.1", "-l", "root", "-p", "x"}, "hydra"},
		// Canonical's chisel cuts package slices; jpillora's chisel tunnels.
		{[]string{"chisel", "cut", "--release", "ubuntu-24.04", "--root", "/r", "base-files_base"}, ""},
		{[]string{"chisel", "info", "openssl_bins"}, ""},
		{[]string{"chisel", "server", "--reverse", "--port", "8000"}, "chisel"},
		// Python's -I (isolated mode) takes no value.
		{[]string{"python3", "-I", "sqlmap.py", "-u", "x"}, "sqlmap"},
		{[]string{"python3", "-I", "-W", "ignore", "-m", "impacket.examples.secretsdump", "x"}, "impacket-secretsdump"},
		{[]string{"python3", "-X", "dev", "dirsearch.py"}, "dirsearch"},
		// Perl and Ruby options that take a value.
		{[]string{"perl", "-I", "/opt/lib", "nikto.pl", "-h", "x"}, "nikto"},
		{[]string{"ruby", "-r", "json", "-I", "lib", "/opt/msf/msfconsole", "-q"}, "msfconsole"},
		{[]string{"perl", "-E", "say 1", "nikto.pl"}, ""},
		// bash options that take a file.
		{[]string{"bash", "--rcfile", "/tmp/rc", "-c", "nmap -sV x"}, "nmap"},
		// Windows cmd.exe, as Node's child_process spawns a shell there.
		{[]string{`C:\Windows\System32\cmd.exe`, "/d", "/s", "/c", `"nmap.exe -sV 10.0.0.1"`}, "nmap"},
		{[]string{"cmd", "/C", "cd", `C:\x`, "&&", "sqlmap", "-u", "x"}, "sqlmap"},
		{[]string{"cmd", "/c", "dir"}, ""},
		{[]string{"cmd", "nmap"}, ""},
		// Family names are program names, never query strings.
		{[]string{"sh", "-c", `curl "https://h/x?a=1&impacket-key=` + planted + `"`}, ""},
		{[]string{"ligolo-ng_agent_0.7.5_linux_amd64", "-connect", "x"}, "ligolo-ng_agent_0.7.5_linux_amd64"},
		{[]string{"/tmp/ligolo-" + strings.ToLower(strings.ReplaceAll(planted, "-", "")) + "x"}, "ligolo"},
		{[]string{"impacket-" + strings.Repeat("a", 40)}, "impacket"},
	}
	for _, c := range cases {
		got, ok := OffensiveTool(c.argv)
		if ok != (c.want != "") || ok && got != c.want {
			t.Errorf("OffensiveTool(%q) = %q, %v; want %q", c.argv, got, ok, c.want)
		}
		if strings.Contains(strings.ToLower(got), "planted") {
			t.Errorf("secret in tool name %q", got)
		}
	}
}
