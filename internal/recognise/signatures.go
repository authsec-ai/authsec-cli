package recognise

import (
	"regexp"
	"strings"
)

// Role is what a recognised process is.
type Role string

const (
	RoleAgent       Role = "agent"
	RoleModelServer Role = "model_server" // serves models to agents (Ollama, LM Studio)
)

// Signature recognises one known agent from its process. Any one match is
// enough.
type Signature struct {
	ID   string
	Name string
	Role Role
	// Exe matches the binary name (case-insensitive, without .exe), checked
	// against the exe path, the kernel comm and argv[0].
	Exe []string
	// Path matches a substring of the binary path (an install location).
	Path []string
	// Args matches a substring of the command line (an npm package path).
	Args []string
	// Threat marks an offensive tool: its presence is itself a finding.
	Threat bool
}

// Signatures is the table of known agents. Order matters: the first match
// wins, so specific entries (Claude Desktop) come before general ones.
var Signatures = []Signature{
	{ID: "claude-desktop", Name: "Claude Desktop", Path: []string{"/Claude.app/", `\AnthropicClaude\`, "/claude-desktop/"}, Exe: []string{"claude-desktop"}},
	{ID: "claude-code", Name: "Claude Code", Exe: []string{"claude"}, Path: []string{"/share/claude/versions/", "anthropic.claude-code-"}, Args: []string{"@anthropic-ai/claude-code"}},
	{ID: "codex", Name: "Codex", Exe: []string{"codex"}, Args: []string{"@openai/codex"}},
	{ID: "gemini-cli", Name: "Gemini CLI", Exe: []string{"gemini"}, Args: []string{"@google/gemini-cli"}},
	{ID: "copilot", Name: "GitHub Copilot", Exe: []string{"copilot", "copilot-runtime", "copilot-language-server", "copilot-agent"}, Args: []string{"@github/copilot"}},
	{ID: "cursor-agent", Name: "Cursor Agent", Exe: []string{"cursor-agent"}},
	{ID: "aider", Name: "Aider", Exe: []string{"aider"}, Args: []string{"/bin/aider ", "-m aider"}},
	{ID: "opencode", Name: "OpenCode", Exe: []string{"opencode"}, Args: []string{"opencode-ai/"}},
	{ID: "goose", Name: "Goose", Exe: []string{"goose"}},
	{ID: "openclaw", Name: "OpenClaw", Exe: []string{"openclaw"}, Args: []string{"node_modules/openclaw/"}},
	{ID: "amp", Name: "Amp", Exe: []string{"amp"}, Args: []string{"@sourcegraph/amp"}},
	{ID: "qwen-code", Name: "Qwen Code", Exe: []string{"qwen"}, Args: []string{"@qwen-code/qwen-code"}},
	{ID: "kiro", Name: "Kiro", Exe: []string{"kiro", "kiro-cli"}},
	{ID: "artex", Name: "ARTEX (AI pentest agent)", Exe: []string{"artex"}, Threat: true},
	{ID: "ollama", Name: "Ollama", Role: RoleModelServer, Exe: []string{"ollama"}},
	{ID: "lm-studio", Name: "LM Studio", Role: RoleModelServer, Exe: []string{"lm-studio", "lms"}},
}

// Editors host AI features (Copilot Chat, Cursor, Windsurf) inside the editor
// itself. An editor counts as an agent when its processes talk to an LLM API.
var Editors = map[string]string{
	"code": "VS Code", "code-insiders": "VS Code Insiders", "cursor": "Cursor",
	"windsurf": "Windsurf", "zed": "Zed", "zed-editor": "Zed",
}

// editorIDs are the tool ids of editors, the same as the config collectors'.
var editorIDs = map[string]string{
	"code": "vscode", "code-insiders": "vscode", "cursor": "cursor",
	"windsurf": "windsurf", "zed": "zed", "zed-editor": "zed",
}

// browsers are never reported as agents: their LLM traffic is a person
// using a chat site.
var browsers = set("chrome", "chromium", "chromium-browser", "firefox", "firefox-bin", "msedge", "brave", "opera", "safari", "vivaldi", "google chrome")

// shells mark an agent started from a terminal.
var shells = set("bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh", "pwsh", "powershell", "cmd", "nu")

// interpreters run self-built agents (LangChain, CrewAI, scripts).
var interpreters = regexp.MustCompile(`^(python[0-9.]*|node|bun|deno|uv|ruby|java|php)$`)

// LLMHosts are LLM API endpoints. A process connecting to one is using a
// model. The CLI resolves them to addresses (and the sensor reads DNS).
var LLMHosts = []string{
	"api.anthropic.com", "api.openai.com", "chatgpt.com",
	"generativelanguage.googleapis.com", "us-central1-aiplatform.googleapis.com",
	"api.githubcopilot.com", "api.individual.githubcopilot.com", "api.business.githubcopilot.com",
	"api.enterprise.githubcopilot.com", "copilot-proxy.githubusercontent.com",
	"api.mistral.ai", "api.groq.com", "openrouter.ai", "api.together.xyz", "api.deepseek.com",
	"api.x.ai", "api.cohere.com", "api.perplexity.ai", "api2.cursor.sh", "server.codeium.com",
	"bedrock-runtime.us-east-1.amazonaws.com", "bedrock-runtime.us-west-2.amazonaws.com",
	"bedrock-runtime.eu-west-1.amazonaws.com", "bedrock-runtime.eu-central-1.amazonaws.com",
	"bedrock-runtime.ap-south-1.amazonaws.com",
}

// LLMHostSuffixes are matched on names the sensor sees in DNS answers.
var LLMHostSuffixes = []string{".openai.azure.com", ".services.ai.azure.com", "-aiplatform.googleapis.com", ".githubcopilot.com"}

// localModelPorts are model servers on loopback.
var localModelPorts = map[int]string{11434: "ollama", 1234: "lm-studio"}

// LLMKeyNames are environment variables that hold LLM credentials. Only the
// name is ever read.
var LLMKeyNames = set("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY",
	"GEMINI_API_KEY", "GOOGLE_API_KEY", "MISTRAL_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY",
	"COHERE_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY", "TOGETHER_API_KEY", "HF_TOKEN",
	"HUGGINGFACE_API_KEY", "AWS_BEARER_TOKEN_BEDROCK", "PERPLEXITY_API_KEY")

// Services names well-known ports, for the access review.
var Services = map[int]string{
	22: "ssh", 80: "http", 443: "https", 1433: "mssql", 1521: "oracle", 2379: "etcd",
	3306: "mysql", 3389: "rdp", 5432: "postgres", 5439: "redshift", 5672: "rabbitmq",
	6379: "redis", 6443: "kubernetes-api", 8200: "vault", 9092: "kafka", 9200: "elasticsearch",
	11434: "ollama", 27017: "mongodb",
}

var mcpWord = regexp.MustCompile(`(?i)(^|[^a-z])mcp([^a-z]|$)|modelcontextprotocol`)

// extensionPath finds "<publisher>.<name>-<version>" in an editor extension
// install path; claudeVersion the native Claude Code install.
var (
	extensionPath = regexp.MustCompile(`[/\\]extensions[/\\]([a-z0-9-]+\.[a-z0-9-]+?)-(\d+\.\d+\.\d+)`)
	claudeVersion = regexp.MustCompile(`/share/claude/versions/(\d[\w.]*)`)
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// baseName is a binary name without directory or .exe, lower-cased.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(p, ".exe"), ".EXE"))
}

// names returns the candidate binary names of a process.
func names(exe, comm string, args []string) []string {
	out := []string{baseName(comm)}
	if exe != "" {
		out = append(out, baseName(exe))
	}
	if len(args) > 0 {
		out = append(out, baseName(args[0]))
	}
	return out
}

// match returns the signature a process matches and why, or nil.
func match(exe, comm string, args []string) (*Signature, string) {
	ns := names(exe, comm, args)
	joined := strings.Join(args, " ") + " "
	for i := range Signatures {
		s := &Signatures[i]
		for _, p := range s.Path {
			if exe != "" && strings.Contains(exe, p) {
				return s, "install path has " + strings.Trim(p, `/\`)
			}
		}
		for _, e := range s.Exe {
			for _, n := range ns {
				if n == e {
					return s, "binary " + e
				}
			}
		}
		for _, a := range s.Args {
			if strings.Contains(joined, a) {
				return s, "command line has " + strings.TrimSpace(a)
			}
		}
	}
	return nil, ""
}

// IsLLMHostName reports whether a DNS name is an LLM API endpoint.
func IsLLMHostName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, h := range LLMHosts {
		if name == h {
			return true
		}
	}
	for _, s := range LLMHostSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}
