# Enforcement formats: OpenShell and Claude Code

Verified on 2026-11-13. Sources:
- NVIDIA/OpenShell at 8606ee3b (v0.1.8): `crates/openshell-policy-schema`, `docs/how-it-works/policies/*`.
- code.claude.com docs: permissions, settings-reference, managed-settings, hooks, sandboxing.

Each claim was read from the source and then checked by a second reviewer.

## OpenShell policy (schema version 1)

- **Top-level keys:** only `version` (must be 1), `filesystem_policy`, `landlock`, `process`, `network_policies` and `network_middlewares`. Any unknown key at any level is rejected.
- **`filesystem_policy`:** `{include_workdir, read_only, read_write}`.
  - There is **no deny**. Landlock is allow-only.
  - Paths are absolute and literal: no `..`, no `~`, no globs, at most 256 of them.
  - `read_write: /` is rejected.
- **Network baseline:** when a policy has network rules, OpenShell adds read-only `/usr /lib /etc /app /var/log /proc /dev/urandom` and read-write `/tmp /dev/null` at startup.
- **`network_policies`:** `{key: {name, endpoints[], binaries[{path}]}}`.
  - Deny by default.
  - A connection is allowed only when both its endpoint and its binary are listed. An empty `binaries` list allows nothing.
  - **Binaries:**
    - Each entry is matched against the real path of the connecting executable, or of any ancestor process.
    - Scripts are matched as their interpreter, so an npm-installed `claude` is `node`.
    - The hash of each binary is pinned on first use.
- **Endpoint:** `host` (or `allowed_ips` with no host) plus `port` or `ports`.
  - In a wildcard, `*` covers one label and `**` (whole first label) covers any depth. `*.com` is rejected.
  - Loopback, link-local and 169.254.169.254 are never allowed. Ports 2379, 2380, 6443, 10250 and 10255 are blocked.
  - Endpoints that can match the same host and port must agree.
- **Workspace:** the working directory is the image's `WORKDIR`, not a fixed `/sandbox`. The project is copied in with `--upload`; there is no bind mount by default.
- **Run:**
  1. `openshell sandbox create --name N --from <image> --policy P --upload . --detach`
  2. `openshell sandbox exec -n N --tty -- claude`
  3. Live network changes: `openshell policy set N --policy P --wait`.
  4. Filesystem changes need a new sandbox.
- **Offline check:** `openshell-prover check P --boundary P`.
  - It catches schema errors (`result: error`).
  - It cannot reason about host-less endpoints (`unsupported`).
  - It does not run every gateway rule; for example, it accepts `*.com`.
- **Needs:**
  - Linux 6.2+ (Landlock ABI 3) or macOS on Apple Silicon.
  - Docker 28+, Podman 5, or a microVM.

`authsec-cli policy export --openshell` writes this format. Whatever it cannot carry over is listed as `# note:` lines.

## Claude Code

- **Managed settings:**
  - Paths:
    - Linux: `/etc/claude-code/managed-settings.json`
    - macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
    - Windows: `C:\Program Files\ClaudeCode\managed-settings.json` (ProgramData is not read)
  - Drop-ins go in `managed-settings.d/*.json`. Users cannot override managed settings.
- **Permission rules:**
  - `Tool(specifier)`, checked in the order deny, then ask, then allow.
  - `Bash(git push *)` matches on the text of the command. The docs say this is not a security boundary: `/bin/rm`, `bash -c` and `git -C . push` all get past it.
  - Real enforcement needs a hook or the sandbox.
- **Locks** (in managed settings):
  - `allowManagedPermissionRulesOnly`, `allowManagedHooksOnly`, `allowManagedMcpServersOnly` (top level).
  - `permissions.disableBypassPermissionsMode: "disable"`.
  - `disableAutoMode` (top level).
- **MCP lists:**
  - `allowedMcpServers` and `deniedMcpServers` are merged from every settings file. The deny list always applies.
  - `[]` blocks every server a user adds.
- **PreToolUse hook:**
  - Settings shape: `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/abs/path", "timeout": 30, "onFailure": "block"}]}]}}`.
  - stdin carries `tool_name`, `tool_input` (Bash: `command`), `cwd`, `session_id` and `permission_mode`.
  - To block: exit 2 (stderr is the reason), or print `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "..."}}`. `ask` and `allow` work the same way.
  - A hook's `allow` does not override a deny or ask rule.
- **Traps:**
  - **Hooks fail open.** A crash, any exit code other than 0 or 2, invalid JSON or a timeout lets the call through. Set `"onFailure": "block"` (v2.1.295+).
  - **Hook location:** keep the hook in a root-owned path, never under the repo (`$CLAUDE_PROJECT_DIR`).
  - **Do not gate on `if`:** a hook's `if` field is best-effort.
  - **Network allowlist:** `sandbox.network.allowedDomains` only prompts. It blocks only with `sandbox.network.strictAllowlist: true` or the managed `allowManagedDomainsOnly: true`.
  - **Sandbox escapes:** set `sandbox.allowUnsandboxedCommands: false`, otherwise Claude retries blocked commands outside the sandbox. Set `sandbox.failIfUnavailable: true`, otherwise commands run unsandboxed when bubblewrap or socat are missing.
  - **Tools outside the sandbox:** Read, Edit, Write, WebFetch, local MCP servers and hooks run outside Claude's sandbox. Permission rules and the hook cover them; OpenShell covers everything.

## authsec-cli enforcement: what is and is not covered

Checked with `make ebpf-test`-style container runs (root, real kernel) and on Ubuntu with Landlock ABI 8.

- **Running agents (daemon, root):**
  - Each agent's whole process tree is moved into `/sys/fs/cgroup/authsec/<agent>-<pid>-<start>`. Processes it starts later inherit the group, and a sweep each tick catches any that were missed.
  - Connections opened before the move are closed (sock_diag `SOCK_DESTROY`); the program sees an error on its next write.
  - nftables matches the group with `socket cgroupv2`. Outgoing traffic: established flows pass, DNS to the configured resolvers passes, and otherwise only the policy's addresses pass. Any-port entries cover every protocol. Incoming: new connections are dropped except on loopback.
  - Host names become addresses through the daemon's own lookups, and through DNS answers that come only from the configured resolvers.
- **Not covered for running agents:**
  - **Files:** only logged.
  - **Work handed to processes outside the tree** (`systemd-run --user`, `docker run`, an existing tmux server, cron): not enforced. Generated policies send these commands to "ask"; the Claude Code hook asks, and the daemon logs them.
  - **Shared addresses:** IP rules cannot tell apart host names that share an address.
- **`run --enforce` (Landlock):**
  - **Files and ports:** only the policy's paths, the agent's own state, and system paths read-only. `/tmp`, `/var/tmp` and `/dev` are writable but not executable. Only the policy's TCP ports are reachable.
  - **Scoping:** abstract UNIX sockets and signals to outside processes are refused (ABI 6+).
  - **Environment:** session variables (D-Bus, ssh-agent, Docker, tmux, display) are removed.
  - **Refused setups:** it refuses to run without the daemon (unless `--no-daemon`), with the home directory as the project, or when a denied credential store would stay readable.
- **Isolation (hiding session sockets):** Landlock cannot block `connect()` to named UNIX sockets. `run --enforce` therefore runs the agent in its own user and mount namespace and covers `/run/user/<uid>`, `docker.sock`, X11, tmux and the ssh-agent socket.
  - On Ubuntu 24.04+ AppArmor blocks this for unprofiled programs, and the CLI says so at start.
  - To allow it, install this profile as root:

```
# /etc/apparmor.d/authsec-cli   (then: sudo apparmor_parser -r /etc/apparmor.d/authsec-cli)
abi <abi/4.0>,
include <tunables/global>
profile authsec-cli /usr/local/bin/authsec-cli flags=(unconfined) {
  userns,
  include if exists <local/authsec-cli>
}
```
- **Claude Code:**
  - The hook decides commands per simple command, web fetches (including Monitor WebSockets), file paths (as given and as resolved, never through `/proc/<pid>/root` or `/dev/fd`), and MCP tools under every name form. PowerShell is asked about.
  - In enforce mode the drop-in also sets `allowManagedHooksOnly`, `allowManagedMcpServersOnly` (when MCP is deny by default) and `requiredMinimumVersion: 2.1.295`.
  - If the machine gets settings from the admin console, MDM or the registry, the drop-in applies only when that source sets `managedSourcesBehavior: "merge"`.
