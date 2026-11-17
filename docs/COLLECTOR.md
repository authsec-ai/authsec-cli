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

Branch `feat/collector-workload-identity` (authsec, off `experimental`)
fixes 1-3. With it, the full chain runs with no hand-made rows: host activity
→ workload on the collector's estate → drafted policy → approve, publish →
delivered to the right agent → receipt.

1. **Fixed on the branch: no target process.** Receipt mappings are always
   empty, so a host with several agents could not place a policy. Each
   desired binding now carries `workload` (exe, argv, unit, path,
   container_id) from the adopted discovered agent.
2. **Fixed on the branch: host activity was never used.** `ActivityProjector`
   is never called. The host projector now puts a process object's recent
   observations on the agent as `metadata.activity`, in the drafter's format,
   and attributes the agent to its collector.
3. **Fixed on the branch: no estate on host workloads.** A workload without an
   estate was published to the first active collector by id. It now takes its
   collector's estate.
4. **Fixed in the collector: argv fingerprint.** Host agents are fingerprinted
   by full argv, so a per-session id (Claude Code `--resume=<id>`) made a new
   agent each session. The collector replaces UUIDs and long hex ids in argv
   with `<id>`.
5. **Exec rules lose their program.** The drafter writes one exec rule per
   program (with `path`), but the pinned template matches `exec` on the action
   alone, and the controls artifact drops the path. One review rule for `zsh`
   therefore means "deny every program". The collector follows the signed
   template.
6. **The drafter's review denies include the agent's own model API**
   (`api.anthropic.com` for Claude Code). Enforced as drafted, that cuts the
   agent off.
7. **`IGA_POLICY_SIGNING_KEY_PEM` is a file path**, not PEM text. Unset or
   wrong, publish answers 503 and enrollment returns no policy keys.
8. **No real capability digest is certified** in `linux-managed-v1`, so only
   observe can be published to a real collector.
9. **The credential lasts 24 hours.** A collector that does not rotate fails
   with "credential rejected", which matches the report's host collector
   failure. authsec-cli rotates it.
