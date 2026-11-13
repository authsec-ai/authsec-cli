# Image for scripts/enforce-smoke.sh and console-smoke.sh: nftables, curl,
# certificates and jq.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nftables curl ca-certificates procps netcat-openbsd jq && rm -rf /var/lib/apt/lists/*
