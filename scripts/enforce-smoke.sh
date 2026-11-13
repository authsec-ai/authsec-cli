#!/usr/bin/env bash
# End-to-end test of daemon enforcement, as root in a privileged container
# with its own network namespace (the host firewall is not touched) and the
# host cgroup namespace (nftables matches cgroups by their level from the
# real root). A fake agent named "goose" keeps calling an allowed host
# (api.github.com) and a denied one (example.com).
#
# Checks: the agent is moved into its cgroup; the allowed host works and the
# denied one is rejected; a denied command it starts is killed; quarantine
# freezes it and release resumes it; stopping the daemon lifts everything.
set -euo pipefail
out="${1:-$(mktemp -d)}"
mkdir -p "$out/pol"
CGO_ENABLED=0 go build -o "$out/authsec-cli" ./cmd/authsec-cli
docker build -q -t authsec-cli-enforce-test -f build/enforce-test.Dockerfile build/ >/dev/null

cat > "$out/pol/goose.yaml" <<'EOF'
apiVersion: authsec.ai/v1
kind: AgentPolicy
agent: {id: goose, name: Goose}
mode: enforce
network:
  default: deny
  allow:
    - {host: api.github.com, port: 443}
filesystem:
  read_write: ["{project}", /tmp]
commands:
  default: allow
  deny: ["sleep 31*"]
mcp_servers: {default: deny}
EOF

cat > "$out/inner.sh" <<'EOF'
#!/bin/bash
set -u
fail() { echo "FAIL: $*"; exit 1; }
mkdir -p /opt/goose
cat > /opt/goose/goose <<'G'
#!/bin/bash
# Opened before enforcement: a connection and a long-running child. A
# closed socket gives EPIPE (a real agent handles the error; bash would
# otherwise die of SIGPIPE).
trap '' PIPE
exec 3<>/dev/tcp/example.com/80
sleep 1000 &
echo "child $!" > /tmp/goose-child
while true; do
  if printf 'HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n' >&3 2>/dev/null; then echo "old connection OPEN"; else echo "old connection CLOSED"; fi
  curl -s -m 3 -o /dev/null -w "github %{http_code}\n" https://api.github.com/ || echo "github FAILED"
  curl -s -m 3 -o /dev/null -w "example %{http_code}\n" https://example.com/ || echo "example BLOCKED"
  [ -f /tmp/trigger ] && { rm -f /tmp/trigger; sleep 31 && echo "sleep 31 FINISHED" || echo "sleep 31 KILLED"; }
  sleep 1
done
G
chmod +x /opt/goose/goose
/opt/goose/goose >/out/goose.log 2>&1 &
GOOSE=$!
sleep 2
grep -q "old connection OPEN" /out/goose.log || fail "test setup: the early connection did not open"
/out/authsec-cli daemon --no-ebpf --poll 1s --policies /out/pol --log /out/events.jsonl >/out/daemon.log 2>&1 &
DAEMON=$!
sleep 6
echo "== nft table (early)"; nft list table inet authsec 2>&1 | grep -v '^\s*$' | sed -n '1,200p'
echo "== agent output (early)"; tail -6 /out/goose.log
CHILD=$(awk '{print $2}' /tmp/goose-child)
echo "== child started before enforcement: $(cat /proc/$CHILD/cgroup)"
grep -q "authsec/goose-$GOOSE" /proc/$CHILD/cgroup || fail "a child started before enforcement was not moved"
grep -q "old connection CLOSED" /out/goose.log || fail "a connection opened before enforcement was not closed"
grep '"action":"close"' /out/events.jsonl | head -1
echo "== cgroup of the agent: $(cat /proc/$GOOSE/cgroup)"
grep -q "authsec/goose-$GOOSE" /proc/$GOOSE/cgroup || fail "agent not moved into its cgroup"
echo "== nft table"; nft list table inet authsec | sed -n '1,40p'
sleep 5
echo "== agent output (enforced)"; tail -4 /out/goose.log
tail -6 /out/goose.log | grep -q "github 200\|github 403" || fail "allowed host does not work"
tail -6 /out/goose.log | grep -q "example BLOCKED" || fail "denied host not blocked"

echo "== denied command"; touch /tmp/trigger; sleep 4
grep '"type":"decision"' /out/events.jsonl | grep '"kind":"command"' | grep -q '"enforced":true' || fail "denied command not recorded as enforced"
grep '"kind":"command"' /out/events.jsonl | tail -1
grep -q "sleep 31 KILLED" /out/goose.log || fail "denied command was not stopped"
grep '"type":"decision"' /out/events.jsonl | grep '"kind":"network"' | grep -q 'api.github.com' && fail "an allowed destination was logged as denied"
grep '"type":"decision"' /out/events.jsonl | grep '"kind":"network"' | head -2

echo "== quarantine"; /out/authsec-cli quarantine goose; sleep 2
G=$(ls -d /sys/fs/cgroup/authsec/goose-$GOOSE*)
grep frozen $G/cgroup.events
grep -q "frozen 1" $G/cgroup.events || fail "not frozen"
n1=$(wc -l < /out/goose.log); sleep 3; n2=$(wc -l < /out/goose.log)
[ "$n1" = "$n2" ] || fail "quarantined agent kept running"
/out/authsec-cli enforce status | sed -n '1,12p'
echo "== release"; /out/authsec-cli release goose; sleep 4
n3=$(wc -l < /out/goose.log); [ "$n3" -gt "$n2" ] || fail "released agent did not resume"
grep -q "frozen 0" $G/cgroup.events || fail "still frozen"

echo "== a user cannot quarantine"
cp /out/authsec-cli /usr/local/bin/authsec-cli-test && chmod 755 /usr/local/bin/authsec-cli-test
msg=$(setpriv --reuid=65534 --regid=65534 --clear-groups /usr/local/bin/authsec-cli-test quarantine goose 2>&1 || true)
echo "non-root got: $msg"
echo "$msg" | grep -q "needs root" || fail "a non-root user could quarantine"

echo "== stop the daemon: everything lifted"
kill -TERM $DAEMON; wait $DAEMON 2>/dev/null
nft list table inet authsec >/dev/null 2>&1 && fail "nft table left behind"
kill $GOOSE 2>/dev/null; sleep 1
rmdir /sys/fs/cgroup/authsec/goose-* /sys/fs/cgroup/authsec 2>/dev/null || true
[ -d /sys/fs/cgroup/authsec ] && echo "note: /sys/fs/cgroup/authsec left (processes still inside)"
echo "PASS"
EOF
chmod +x "$out/inner.sh"
docker run --rm --privileged --cgroupns=host -v "$out":/out authsec-cli-enforce-test /out/inner.sh
