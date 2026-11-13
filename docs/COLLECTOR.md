# authsec-cli as the host collector (authsec-local)

authsec-cli runs as a TRD 2 `linux_collector` against the `/api/iga/v2`
collector API on the `experimental` branch (contract package 2.2.0, schema 2.0).
The console's enrollment command works unchanged:

```sh
docker run -d --name authsec-collector --privileged --pid host \
  -e AUTHSEC_URL=https://<api> -v authsec-collector-state:/var/lib/authsec-local \
  authsec/iga-host-collector:latest \
  sh -c 'printf "%s" "<token>" > /tmp/t && exec authsec-local run --enrollment-token-file /tmp/t'
```

Add `--network host --cgroupns host` to also block on the host; without them the
daemon observes and reports, and says why it does not block. Without Docker:
`sudo AUTHSEC_URL=... authsec-cli collector run --enrollment-token-file /tmp/t`.
`make collector-image` builds the image.

## What it does

| Contract | authsec-cli |
|---|---|
| Enrollment | One-time token, Ed25519 installation key, nonce. A lost answer is fetched again with the same key and nonce. State in `/var/lib/authsec-local/collector.json` (0600). |
| Credential (24 h) | Rotated in its last 6 hours, signed with the installation key (`authsec.collector.rotate.v1`). |
| agent-sync | gzip batches; epoch and sequence persist across restarts. Objects: `linux.process_group` per running agent (`exe`, scrubbed `argv`, `systemd_unit`, `user`). Observations: process exec/exit, network connect, file open, and denied or would-deny decisions. No secret-like key names. Capabilities and their digest are sent with every batch. |
| Desired | Both shapes (one object, or `{"bindings":[...]}`). The signed manifest is verified against the policy keys (fetched again for an unknown key id). Both artifacts must match the manifest's hashes. `policy.rego` must be the pinned `authsec.runtime.v1` template, and `data.json` is evaluated natively. |
| Controls | egress becomes nftables per agent cgroup, exec becomes the command policy, filesystem becomes path lists (Landlock under `run --enforce`). observe maps to monitor, enforce to enforce, `revoked` removes the policy, and `quarantine` freezes the agent and cuts its network. secret, admission and broker are reported `unsupported`. |
| Receipts | Per delivery and per control: state, test, controls sha256, runtime generation (`boot_id:agent`). |

Tested against the `experimental` backend: enroll → sync → server-side
promotion → policy create, validate, simulate, approve, publish (observe) →
delivery verified and in force → receipt stored; credential rotation; the
console's `docker run` command.

## Gaps found on the server (`experimental`)

1. **The server does not say which local process a delivery is for.** Receipt
   mappings are always empty. A host with several agents cannot place a
   policy. Branch `feat/collector-workload-identity` (authsec, off
   `experimental`) adds `workload` (exe, argv, unit, path, container_id) to each
   desired binding, from the adopted discovered agent.
2. **Host observations never become activity.** `ActivityProjector` is never
   called, so host agents get no `metadata.activity`. That means no workload,
   and no auto-drafted policy. In the test the workload was inserted as
   `ensureActivityWorkload` would.
3. **A workload with no estate scope is published to the first active
   collector by id**, which may be any machine in the workspace.
4. **Host agents are fingerprinted by full argv.** Agents whose argv carries a
   session id (Claude Code `--resume=<id>`) become a new discovered agent each
   session.
5. **`IGA_POLICY_SIGNING_KEY_PEM` is a file path**, not PEM text. Unset or
   wrong, publish answers 503 and enrollment returns no policy keys.
6. **No real capability digest is certified** in `linux-managed-v1`, so only
   observe can be published to a real collector.
7. The credential lasts 24 hours. A collector that does not rotate fails with
   "credential rejected", which matches the report's host collector failure.
