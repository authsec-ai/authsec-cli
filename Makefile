VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X github.com/authsec-ai/authsec-cli/internal/cli.Version=$(VERSION) -X github.com/authsec-ai/authsec-cli/internal/cli.Commit=$(COMMIT)

.PHONY: build test vet lint golden cross clean

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

# The release targets build from any host (no cgo).
cross:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli-linux-amd64 ./cmd/authsec-cli
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli-darwin-arm64 ./cmd/authsec-cli
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/authsec-cli-windows-amd64.exe ./cmd/authsec-cli

clean:
	go clean
	rm -f bin/authsec-cli bin/authsec-cli-*
