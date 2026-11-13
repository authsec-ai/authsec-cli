#!/usr/bin/env bash
# End-to-end test of the console connection, as root in a privileged
# container (own network namespace; the host firewall is not touched).
#
# The daemon connects to a control plane, reports a fake agent "goose",
# hands over its actuation credential when the console turns enforcement
# on, then freezes goose when the console quarantines it and resumes it on
# release. The console's log must show both decisions.
#
#   AUTHSEC_API        control plane URL, http://HOST:PORT (localhost means the Docker
#                      host); the daemon reaches it through 127.0.0.1:PORT
#   AUTHSEC_WORKSPACE  workspace id
#   ADMIN_JWT_FILE     a console session token file (discovery:admin, discovery:quarantine, governance)
#   INGEST_TOKEN_FILE  an ingest token file of the workspace
#
# Never point it at a production workspace: it registers a machine and
# quarantines an agent there.
set -euo pipefail
: "${AUTHSEC_API:?}" "${AUTHSEC_WORKSPACE:?}" "${ADMIN_JWT_FILE:?}" "${INGEST_TOKEN_FILE:?}"
out="${1:-$(mktemp -d)}"
mkdir -p "$out"
CGO_ENABLED=0 go build -o "$out/authsec-cli" ./cmd/authsec-cli
CGO_ENABLED=0 go build -o "$out/tcpfwd" ./scripts/tcpfwd
docker build -q -t authsec-cli-enforce-test -f build/enforce-test.Dockerfile build/ >/dev/null
install -m 600 "$ADMIN_JWT_FILE" "$out/admin.jwt"
install -m 600 "$INGEST_TOKEN_FILE" "$out/ingest.token"

hostport="${AUTHSEC_API#*://}"; hostport="${hostport%%/*}"
port="${hostport##*:}"; target="${hostport%:*}"
case "$target" in localhost|127.0.0.1) target=host.docker.internal ;; esac
cat > "$out/inner.sh" <<'EOF'
#!/bin/bash
set -u
fail() { echo "FAIL: $*"; echo "== daemon log"; tail -30 /out/daemon.log; exit 1; }
API=http://127.0.0.1:$PORT
/out/tcpfwd 127.0.0.1:$PORT $TARGET:$PORT 2>/out/tcpfwd.log &
sleep 0.5
J=$(cat /out/admin.jwt)
api() { local m=$1 p=$2; shift 2; curl -sS -X "$m" -H "Authorization: Bearer $J" -H 'Content-Type: application/json' "$@" "$API$p"; }

mkdir -p /opt/goose
printf '#!/bin/bash\nwhile true; do date +%%s.%%N; sleep 0.5; done\n' > /opt/goose/goose
chmod +x /opt/goose/goose
/opt/goose/goose >/out/goose.log 2>&1 &

name="console-smoke-$(hostname)"
reg=$(/out/authsec-cli connect --url "$API" --workspace "$WS" --name "$name" --token-file /out/ingest.token) || fail "connect: $reg"
echo "$reg"
SRC=$(echo "$reg" | sed -n 's/.*(source \(.*\))/\1/p')
[ -n "$SRC" ] || fail "no source id"
stat -c '%a %n' /etc/authsec/connect.json

/out/authsec-cli daemon --no-ebpf --poll 1s --policies none --log /var/lib/authsec/events.jsonl >/out/daemon.log 2>&1 &
DAEMON=$!
sleep 6
grep -q "connected to" /out/daemon.log || fail "daemon did not connect"

echo "== console turns enforcement on"
api POST /authsec/governance/connectors/$SRC/actuation -d '{"delivery":"agent"}' | jq -c '{actuation_state}'
for i in $(seq 1 90); do grep -q "console enforcement is on" /out/daemon.log && break; sleep 1; done
grep -q "console enforcement is on" /out/daemon.log || fail "actuation handover did not happen"
stat -c '%a %n' /etc/authsec/actuation.token

AID=$(api GET "/authsec/discovery/agents?discovery_source_id=$SRC&limit=50" | jq -r '(.agents // .items)[] | select(.metadata.machine.agent_id=="goose") | .id' | head -1)
[ -n "$AID" ] || fail "goose not reported to the console"
echo "goose is $AID in the console"

echo "== console quarantines goose"
api POST /authsec/discovery/agents/$AID/quarantine -d '{"reason":"console smoke"}' | jq -c '{status: (.agent.status // .status)}'
for i in $(seq 1 30); do grep -q "console quarantine of goose: 1" /out/daemon.log && break; sleep 1; done
grep "console quarantine" /out/daemon.log | tail -1
G=$(ls -d /sys/fs/cgroup/authsec/goose-* | head -1)
grep -q "frozen 1" $G/cgroup.events || fail "goose not frozen"
n1=$(wc -l < /out/goose.log); sleep 3; n2=$(wc -l < /out/goose.log)
[ "$n1" = "$n2" ] || fail "quarantined goose kept running"
echo "frozen: $(grep frozen $G/cgroup.events)"

echo "== console releases goose"
api POST /authsec/discovery/agents/$AID/unquarantine -d '{}' | jq -c '{status: (.agent.status // .status)}'
for i in $(seq 1 30); do grep -q "console release of goose: 1" /out/daemon.log && break; sleep 1; done
sleep 2
grep -q "frozen 0" $G/cgroup.events || fail "goose still frozen"
n3=$(wc -l < /out/goose.log); [ "$n3" -gt "$n2" ] || fail "released goose did not resume"

echo "== the console's log"
sleep 6
api GET "/authsec/discovery/agentkit/events?agent_id=goose&type=decision" | jq -r '.events[] | "\(.observed_at) \(.action) enforced=\(.enforced) tags=\(.record.tags|join(","))"' | tee /out/console-events.txt
grep -q " quarantine enforced=true" /out/console-events.txt || fail "the console has no quarantine decision"
grep -q " release " /out/console-events.txt || fail "the console has no release decision"

kill -TERM $DAEMON; wait $DAEMON 2>/dev/null
nft list table inet authsec >/dev/null 2>&1 && fail "nft table left behind"
pkill -f /opt/goose/goose; sleep 1
rmdir /sys/fs/cgroup/authsec/goose-* /sys/fs/cgroup/authsec 2>/dev/null || true
echo "PASS"
EOF
chmod +x "$out/inner.sh"
docker run --rm --privileged --cgroupns=host --add-host=host.docker.internal:host-gateway \
  -e PORT="$port" -e TARGET="$target" -e WS="$AUTHSEC_WORKSPACE" -v "$out":/out authsec-cli-enforce-test /out/inner.sh
