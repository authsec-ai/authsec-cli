#!/usr/bin/env bash
# Runs the eBPF daemon as root in a privileged container that shares the
# host's PID and network namespaces, makes an untracked process talk to an
# LLM API, and checks what the log recorded. Prints the daemon's memory and
# CPU use. Needs Docker; does not need sudo.
set -euo pipefail

out="${1:-$(mktemp -d)}"
secs="${SECS:-25}"
mkdir -p "$out"
CGO_ENABLED=0 go build -o "$out/authsec-cli" ./cmd/authsec-cli
docker rm -f askit-smoke >/dev/null 2>&1 || true
docker run -d --name askit-smoke --privileged --pid=host --network host \
  -v /etc/passwd:/etc/passwd:ro -v "$out":/out ubuntu:24.04 \
  sh -c 'mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null; exec /out/authsec-cli daemon run --log /out/events.jsonl' >/dev/null
trap 'docker rm -f askit-smoke >/dev/null 2>&1 || true' EXIT
sleep 3

# An untracked process (in another container) talks to an LLM API.
docker run --rm ubuntu:24.04 bash -c 'exec 3<>/dev/tcp/api.openai.com/443; sleep 3' || true
sleep $((secs - 3))

pid=$(docker inspect -f '{{.State.Pid}}' askit-smoke)
rss=$(awk '/VmRSS/ {print $2}' /proc/"$pid"/status)
ticks=$(awk '{print $14 + $15}' /proc/"$pid"/stat)
age=$(ps -o etimes= -p "$pid" | tr -d ' ')
docker stop -t 5 askit-smoke >/dev/null
docker logs askit-smoke 2>&1 | head -3
docker run --rm -v "$out":/out ubuntu:24.04 chown "$(id -u):$(id -g)" /out/events.jsonl

echo "memory: $((rss / 1024)) MiB RSS; cpu: $ticks ticks in ${age}s ($(awk "BEGIN {printf \"%.2f\", $ticks / $age}")% of one core)"
grep -q '"note":"started (ebpf)"' "$out/events.jsonl" || { echo "FAIL: not in eBPF mode"; exit 1; }
grep -q '"host":"api.openai.com"' "$out/events.jsonl" || { echo "FAIL: LLM connection not recorded"; exit 1; }
grep -q '"id":"unknown"' "$out/events.jsonl" || { echo "FAIL: unknown agent not found"; exit 1; }
echo "ok: $(wc -l < "$out/events.jsonl") records in $out/events.jsonl"
