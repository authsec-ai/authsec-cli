# Image for scripts/enforce-smoke.sh: nftables, curl and certificates.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nftables curl ca-certificates procps netcat-openbsd && rm -rf /var/lib/apt/lists/*
