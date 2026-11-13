# authsec-cli (AuthSec Agent Kit)

Finds the AI agents on a machine, what each one may do without asking, and what
it actually does: the programs it runs, the files it opens and where it
connects.

```text
authsec-cli agents                    # AI agents running now (and installed)
authsec-cli agents --watch 5s         # print agents as they start and stop
authsec-cli scan                      # agent settings, MCP servers, risks (offline)
sudo authsec-cli daemon               # follow agents, log what they do
sudo authsec-cli daemon install       # the same as a systemd service
authsec-cli access claude-code        # files, network, services, programs
authsec-cli policy generate           # one YAML policy per agent in ./policies
authsec-cli policy edit claude-code   # opens vi, checks the file on save
authsec-cli policy check              # validate, and replay recent activity
sudo authsec-cli daemon --policies ./policies   # enforce mode: enforce policies
sudo authsec-cli quarantine codex     # freeze an agent and cut its network
sudo authsec-cli release codex
sudo authsec-cli enforce claude install         # Claude Code hook (managed settings)
authsec-cli run --enforce -- claude   # re-run an agent confined by its policy
authsec-cli detect                    # ARTEX and agents running attack tools, now
sudo authsec-cli daemon --quarantine-threats --siem syslog+tls://siem:6514
authsec-cli logs --since 1h --format cef        # or --siem splunk+https://...:8088
authsec-cli cloud agents --env .env   # Bedrock, AgentCore, Azure OpenAI, AI Foundry
authsec-cli cloud quarantine my-agent --apply   # AWS: deny-all on the agent's role
authsec-cli catalogue                 # every config file a scan may read
```

**Enforcement** (policies with `mode: enforce`):

| What | Running agents (daemon, root) | `run --enforce` |
|---|---|---|
| Network | nftables per agent cgroup: only the policy's hosts and ports | Landlock: only the policy's TCP ports; hosts too when the daemon runs |
| Commands | a denied program the agent starts is stopped at once | same |
| Files | logged | Landlock: only the policy's paths |
| Claude Code | PreToolUse hook decides every tool call; fails closed | same |
| Quarantine | frozen, no network; new instances too, until released | — |

Limits (details in [docs/notes/enforcement-formats.md](docs/notes/enforcement-formats.md)):
- files of an already-running agent are only logged;
- work handed to processes outside the agent's tree (`systemd-run --user`, `docker run`, an existing tmux) is not enforced, so generated policies ask before those commands;
- IP rules cannot tell apart host names that share an address.

**Detections** (daemon, and `authsec-cli detect`): `artex_present` (ARTEX, an
autonomous AI pentest agent, by its binary, `ARTEX_*` variables, ports, files
or containers; a renamed binary is still found), `offensive_tool` (an agent
starts nmap, sqlmap, nuclei, ffuf, hydra, ...), `connection_fanout` (an agent
connects to many destinations in a minute). With `--quarantine-threats`, a
high-severity detection quarantines the agent.

**SIEM:** records go out as CEF over syslog (UDP, TCP, TLS), as JSON to a
webhook, or to Splunk HEC, each with compliance tags (OWASP Top 10 for LLM and
agentic applications). The token is read from an environment variable named
with `--siem-token-env`.

**Agents recognised:** Claude Code, Claude Desktop, Codex, Gemini CLI, GitHub
Copilot, Cursor, Windsurf, VS Code AI features, Aider, OpenCode, Goose,
OpenClaw, Amp, Qwen Code, Kiro, model servers (Ollama, LM Studio), ARTEX
(flagged as a threat), and any process that talks to an LLM API ("unknown
agent").

**Sensor:** on Linux as root, eBPF (kernel 5.8+ with BTF): process start and
exit, outgoing TCP connections, DNS answers, and file opens of agent processes
only. Elsewhere, or without root, it polls the process table. The service is
capped at 128 MB and 20% CPU; measured use is about 22 MB and under 2% of one
core.

**Secrets:** never read or printed. Environment variables and headers are kept
by name; command lines, URLs and arguments are scrubbed. The event log is 0600.

## Develop

```text
make build      # bin/authsec-cli
make test
make lint
make golden     # after an intended change to the report; review the diff
make bpf        # rebuild internal/sensor/bpf/sensor.o (clang in Docker)
make ebpf-test  # load the sensor as root in a privileged container and check it
bash scripts/enforce-smoke.sh   # enforcement end to end as root (own network namespace)
```

See [docs/PLAN.md](docs/PLAN.md).
