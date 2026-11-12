# Builds internal/sensor/bpf/sensor.o. Used by `make bpf`; the object is
# committed so a plain `go build` needs no clang.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev linux-libc-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
