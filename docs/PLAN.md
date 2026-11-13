# authsec-cli (AuthSec Agent Kit): 7-day plan

Every story in the sheet works end to end by day 7. Depth is cut where noted.

| Day | Build | Demo at end of day |
|---|---|---|
| 0 ✅ | Config scan: Claude Code settings, MCP, hooks, skills | `authsec-cli scan` |
| 1 ✅ | Running agents: process list, connections, signatures, process tree. Configs for Codex, Cursor, Gemini, Claude Desktop | `authsec-cli agents` |
| 2 ✅ | eBPF sensor (exec, connect, file open for agent PIDs), `daemon` with JSONL event log, systemd unit, `access` | `sudo authsec-cli daemon`, then `authsec-cli access claude-code` |
| 3 ✅ | Policy YAML: schema, `policy generate` into `./policies/`, `policy check`, OpenShell export | generate, `vi`, check |
| 4 ✅ | Enforcement: agent cgroup + nftables network allow list, quarantine/release (cgroup freeze), Claude Code PreToolUse hook for commands, `run --enforce` through OpenShell | blocked host fails, quarantine freezes |
| 5 ✅ | Detections: ARTEX and offensive agent. SIEM: syslog (CEF) and webhook. Cloud mode from `.env`: AWS Bedrock agents and AgentCore runtimes, Azure AI Foundry/OpenAI | ARTEX in Docker is detected; `--cloud agents` |
| 6 | Control plane: connect with an ingest token from the console, push agents and events to discovery, policy and action pull (quarantine, block) | the machine shows in the console |
| 7 | Console screens (agents, access, policy, quarantine and block actions), release build, demo script, fixes | full demo |

## Cut for the week

- Kernel monitoring on Linux only. macOS and Windows use process polling.
- Network enforcement uses nftables matched on the agent's cgroup (eBPF connect hooks come later).
- File restrictions only through `run --enforce` (OpenShell). A running process cannot be confined.
- Cloud: AWS and Azure discovery. Cloud enforcement reuses the console's access policies.
- Compliance tags: a fixed OWASP Agentic Top 10 mapping.
- No package repos: one install script and release binaries.

## Risks

- Day 6–7 needs backend and UI changes. If they slip, the console shows machines and agents through existing discovery, and policies and actions stay CLI-only.
- The ARTEX signatures come from its README. Day 5 checks them against a real run.
