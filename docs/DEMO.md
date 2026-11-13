# AuthSec Agent Kit: demo

About 20 minutes. Linux machine with root, kernel 5.8+, an AI agent installed
(Claude Code or Codex), and a console login with discovery:admin.

## 1. Install and discover (local)

```sh
curl -fsSL https://github.com/authsec-ai/authsec-cli/releases/latest/download/install.sh | sudo sh
authsec-cli agents                  # agents running now, and installed
authsec-cli scan                    # their settings, MCP servers, risks
sudo authsec-cli daemon install     # eBPF sensor as a service (about 22 MB, under 2% CPU)
authsec-cli access claude-code      # after a few minutes: files, hosts, services, programs
```

## 2. Policy and enforcement (local)

```sh
authsec-cli policy generate         # ./policies/<agent>.yaml from what was seen
authsec-cli policy edit claude-code # vi; checked on save. Set mode: enforce, deny a host
sudo install -D -m 644 -t /etc/authsec/policies policies/*.yaml   # the service reads /etc/authsec/policies
sudo authsec-cli enforce reload
curl https://<denied host>          # from inside the agent: blocked, logged
sudo authsec-cli quarantine claude-code   # frozen, no network
sudo authsec-cli release claude-code
authsec-cli run --enforce -- claude # re-run confined: files and ports by Landlock
sudo authsec-cli enforce claude install   # Claude Code hook: every tool call checked
```

## 3. Console (control plane)

1. Console › IGA › Machines › Add machine. Name it, run the three commands it shows.
2. The machine appears as Connected; Agents lists what runs on it.
3. Access: files, destinations and services per agent. Right-click a row › Block.
4. Policies: edit an agent's YAML, save. The machine applies it within a minute
   (`ls /var/lib/authsec/console-policies`).
5. Enforcement and SIEM › Turn on. Agents › right-click › Quarantine… The agent
   freezes on the machine; Release resumes it.
6. Logs: the block and the quarantine, with OWASP tags. Filter by tag.

## 4. Threats and SIEM

```sh
sudo authsec-cli daemon install --quarantine-threats --siem syslog+tls://siem:6514
authsec-cli detect                  # start ARTEX (or nmap from an agent): detected
authsec-cli logs --since 1h --format cef
```

The detection shows in the console's Logs (ASI10 Rogue agents) and in the SIEM.

## 5. Cloud agents

```sh
authsec-cli cloud agents --env .env           # Bedrock, AgentCore, Azure OpenAI, AI Foundry
authsec-cli cloud quarantine my-agent --apply # AWS: deny-all on the agent's role
```

## Checks behind the demo

- `scripts/enforce-smoke.sh`: blocking, killed commands, quarantine and release, as root in a container.
- `scripts/console-smoke.sh`: console quarantine freezes the agent, release resumes it, both logged in the console.
- `scripts/detect-smoke.sh`: ARTEX and offensive tools detected.

## Not covered

- Files of an agent that is already running are logged, not blocked (use `run --enforce`).
- Work an agent hands to processes outside its tree (`docker run`, `systemd-run --user`, an existing tmux) is not enforced; generated policies ask before those commands.
- Microsoft IGA (Entra ID Governance) was not evaluated.
