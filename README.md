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
authsec-cli catalogue                 # every config file a scan may read
```

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
```

See [docs/PLAN.md](docs/PLAN.md).
