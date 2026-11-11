# authsec-cli: build plan

The order of work for SPEC.md. Each milestone ends with something that runs.

## Ground rules

- Go 1.23 (the same as iga-agent). Module `github.com/authsec-ai/authsec-cli`.
- Few dependencies: cobra, BurntSushi/toml, yaml.v3. JSONC and INI parsing are written in-house.
- Secret values never leave the parser. Every collector has a test that fails if a fixture's secret shows up in the output.
- Only catalogue paths are opened. Files are capped at 1 MiB.
- Backend changes go to the `authsec` repo on a feature branch, never straight to `authsec-staging`.

## Layout

```text
cmd/authsec-cli/        main
internal/cli/           cobra commands
internal/catalogue/     paths per tool and OS, with a version
internal/collect/       one collector per tool or identity source
internal/parse/         JSONC, TOML, YAML, INI and the redactor
internal/finding/       Finding, fingerprint, machine id
internal/rules/         risk signals
internal/report/        table, JSON, SARIF, Markdown
internal/auth/          device login and token storage   (M4)
internal/push/          registration, sightings, resync  (M4)
testdata/               redacted fixture homes, one per tool
```

## M1: scan Claude Code (week 1)

1. Repo scaffold: go.mod, Makefile (`build test lint`), `version`, CI for Linux, macOS and Windows.
2. `finding`: the Finding type, a machine id (sha256 of the OS machine id) and fingerprints.
3. `parse`: a JSONC reader and a redactor (keys kept, values become `<redacted:len>`).
4. `catalogue`: Claude Code paths (`~/.claude/settings.json`, `~/.claude.json`, and in each project `.claude/settings*.json` and `.mcp.json`).
5. Claude Code collector: agent, policy (allow, deny, ask, defaultMode), hooks, skills, sub-agents, commands, MCP servers.
6. `scan` with table and `--json` output, `--home` and `--project`.
7. Tests: fixture home → golden JSON; a planted key never appears in the output.

**Done when:** `authsec-cli scan` on this laptop lists Claude Code and everything it is allowed to do.

## M2: other agents (week 2)

1. Codex (`~/.codex/config.toml`: approval_policy, sandbox_mode, mcp_servers).
2. VS Code / Copilot (user `settings.json`, `mcp.json`, `.vscode/mcp.json`).
3. Cursor, Gemini CLI, Windsurf and Claude Desktop (MCP and settings).
4. Project files: `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`.
5. Paths per OS (macOS `Library/Application Support`, Windows `%APPDATA%`), each checked against the tool's docs.

**Done when:** each tool has a fixture test, and `authsec-cli catalogue` prints every path.

## M3: identities, risks, CI (week 3)

1. AWS (`config` and `credentials`: profiles, role_arn, sso account; key values never read).
2. Kubernetes (contexts, server URL, user, auth type), Azure, gcloud, `gh` and Docker.
3. Secret names: env var names and `.env` files in projects.
4. Rules: the six risk signals, plus `--prod` patterns.
5. `--fail-on` with exit codes, SARIF and Markdown output.

**Done when:** `scan --sarif --fail-on auto_approve_shell` works as a CI gate.

## M4: connect to AuthSec (weeks 4–5)

Backend (authsec repo):

1. Migration: the `cli_device_authorizations` table.
2. `POST /authsec/discovery/cli/device` and `/device/token`, unauthenticated and rate-limited.
3. `GET` and `POST /authsec/discovery/cli/device/:user_code` for approval, needing `discovery:admin`. Approving creates the `vm_sensor` source.
4. The token is minted when the CLI collects it, bound to that source, and returned once with the `workspace_id` and source id.
5. Resync for `vm_sensor`: today a manifest needs namespaces (k8s). Decide what a machine sends instead.
6. Tests: RFC 8628 states, expired and reused codes, cross-workspace isolation.

CLI:

7. `login`, `logout`, `status`; the token goes in the OS keychain (or a 0600 file).
8. `push`: registration, one sighting per finding, resync; `--dry-run`.
9. `doctor`.

**Done when:** `login && push` makes this laptop show up in the console's Discovery.

## M5: console (week 6)

1. Approve page `/iga/connect/machine`.
2. Connections › Add › Machine: two pre-filled lines, then wait for the machine.
3. Discovery: a Machines provider (`vm_sensor`) and a finding detail view.

## M6: release and correlation (week 7)

1. GoReleaser: signed builds, checksums, SBOM; install script; Homebrew tap.
2. Link machine identities to graph nodes (AWS role ARN, kube server URL, Azure subscription).

**Done when:** `curl … | sh` installs a release, and the graph shows which machines' agents reach prod.
