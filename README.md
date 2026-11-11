# authsec-cli

Finds the AI agents on a machine, what each one may do without asking, the MCP
servers and extensions they load, and the credentials they can reach.

```text
authsec-cli scan                      # table, grouped by agent
authsec-cli scan --json               # the full report
authsec-cli scan --project ~/work/api # also scan a project
authsec-cli catalogue                 # every file a scan may read
```

`scan` works offline and sends nothing. It reads only the files listed by
`authsec-cli catalogue` (each at most 1 MiB) and never reads or prints a
secret value: environment variables and headers are kept by name, and
arguments, URLs and commands are scrubbed before anything is kept.

Coverage today: Claude Code (settings, managed settings, MCP servers, hooks,
skills, sub-agents, commands). Next: Codex, VS Code, Cursor, Gemini CLI,
Windsurf, Claude Desktop, then identities (AWS, kube, Azure, gcloud, gh,
Docker). See [docs/PLAN.md](docs/PLAN.md).

## Develop

```text
make build   # bin/authsec-cli
make test
make lint
make golden  # after an intended change to the report; review the diff
```
