VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X github.com/authsec-ai/authsec-cli/internal/cli.Version=$(VERSION) -X github.com/authsec-ai/authsec-cli/internal/cli.Commit=$(COMMIT)

.PHONY: build test vet lint golden cross clean bpf ebpf-test

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli ./cmd/authsec-cli

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

# Rewrite the golden report after an intended change; review the diff.
golden:
	go test ./internal/scan -run Golden -update

# Rebuild the eBPF object (clang in Docker; the object is committed).
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf
bpf:
	docker build -q -t authsec-cli-bpf -f build/bpf.Dockerfile build/ >/dev/null
	docker run --rm -u $(shell id -u):$(shell id -g) -v $(CURDIR):/src authsec-cli-bpf \
	  sh -c 'clang $(BPF_CFLAGS) -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu -c internal/sensor/bpf/sensor.c -o internal/sensor/bpf/sensor.o && llvm-strip -g internal/sensor/bpf/sensor.o'

# Load the sensor for real (root in a privileged container) and check it.
ebpf-test:
	bash scripts/ebpf-smoke.sh

# The release targets build from any host (no cgo).
cross:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli-linux-amd64 ./cmd/authsec-cli
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli-linux-arm64 ./cmd/authsec-cli
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli-darwin-arm64 ./cmd/authsec-cli
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli-windows-amd64.exe ./cmd/authsec-cli

clean:
	go clean
	rm -f bin/authsec-cli bin/authsec-cli-*
