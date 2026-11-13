#!/usr/bin/env bash
# End-to-end test of threat detections and SIEM forwarding, as root in a
# privileged container (own network namespace, host cgroup namespace):
#   - a renamed ARTEX (ARTEX_* variables, jwt.key/data/skills layout) is
#     detected and followed as an agent;
#   - a recognised agent that runs an attack tool (a fake nmap) raises
#     offensive_tool and, with --quarantine-threats, is frozen;
#   - every record reaches a syslog TCP listener as CEF.
set -euo pipefail
out="${1:-$(mktemp -d)}"
mkdir -p "$out/pol"
CGO_ENABLED=0 go build -o "$out/authsec-cli" ./cmd/authsec-cli
docker build -q -t authsec-cli-enforce-test -f build/enforce-test.Dockerfile build/ >/dev/null
cat > "$out/pol/default.yaml" <<'EOF'
apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: "*"}
mode: monitor
network: {default: allow}
commands: {default: allow}
mcp_servers: {default: allow}
EOF
cat > "$out/inner.sh" <<'EOF'
#!/bin/bash
set -u
fail() { echo "FAIL: $*"; exit 1; }
nc -lk 127.0.0.1 6601 > /out/siem.txt &
# A renamed ARTEX: an innocuous binary, but ARTEX's variables and files.
mkdir -p /opt/x/data /opt/x/skills && touch /opt/x/jwt.key && cp /bin/sleep /opt/x/server
ARTEX_BIND_ADDR=127.0.0.1:8787 ARTEX_NOISE_PROFILE=low /opt/x/server 600 &
ART=$!
# A recognised agent and a fake attack tool.
mkdir -p /opt/goose /opt/tools && printf '#!/bin/sh\nsleep 30\n' > /opt/tools/nmap && chmod +x /opt/tools/nmap
printf '#!/bin/bash\nwhile true; do sleep 1; [ -f /tmp/scan ] && { rm -f /tmp/scan; PATH=/opt/tools:$PATH nmap -sV 10.0.0.0/24; }; echo tick; done\n' > /opt/goose/goose
chmod +x /opt/goose/goose
/opt/goose/goose > /out/goose.log 2>&1 &
GOOSE=$!
sleep 1
/out/authsec-cli daemon --no-ebpf --poll 1s --policies /out/pol --log /out/events.jsonl --quarantine-threats --siem syslog+tcp://127.0.0.1:6601 >/out/daemon.log 2>&1 &
DAEMON=$!
sleep 4
echo "== one-shot detect"; /out/authsec-cli detect; echo "(exit $?)"
grep '"type":"detection"' /out/events.jsonl | grep -q '"rule":"artex_present"' || fail "renamed ARTEX not detected"
grep '"type":"agent_started"' /out/events.jsonl | grep -q '"id":"artex"' || fail "ARTEX not followed as an agent"
echo "== agent runs nmap"; touch /tmp/scan; sleep 4
grep '"type":"detection"' /out/events.jsonl | grep -q '"rule":"offensive_tool"' || fail "offensive tool not detected"
G=$(ls -d /sys/fs/cgroup/authsec/goose-$GOOSE* 2>/dev/null | head -1)
[ -n "$G" ] && grep -q "frozen 1" $G/cgroup.events || fail "the agent was not quarantined after the detection"
echo "quarantined: $G"
n1=$(wc -l < /out/goose.log); sleep 3; n2=$(wc -l < /out/goose.log); [ "$n1" = "$n2" ] || fail "quarantined agent kept running"
echo "== SIEM (CEF over syslog TCP)"; grep -c 'CEF:0|AuthSec|Agent Kit' /out/siem.txt; grep -o 'CEF:0|AuthSec|Agent Kit|[^|]*|detection[^|]*|[^|]*|[0-9]*' /out/siem.txt | sort -u
grep -q 'artex_present' /out/siem.txt || fail "detection not forwarded to the SIEM"
/out/authsec-cli release goose >/dev/null 2>&1 || /out/authsec-cli release $GOOSE >/dev/null
kill -TERM $DAEMON; wait $DAEMON 2>/dev/null
kill $GOOSE $ART 2>/dev/null; sleep 1
rmdir /sys/fs/cgroup/authsec/* /sys/fs/cgroup/authsec 2>/dev/null || true
echo PASS
EOF
chmod +x "$out/inner.sh"
docker run --rm --privileged --cgroupns=host -v "$out":/out authsec-cli-enforce-test /out/inner.sh
