# pagnet client developer Makefile — the open-source module (CLI, host
# daemon, runtime adapters, MCP bridges). The control plane lives in
# pagnet-server; compose/e2e orchestration lives in the monorepo.
# Go is resolved from PATH first, then the local toolchain used on this machine.
GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/go-toolchain/go/bin/go)
export PATH := $(dir $(GO)):$(PATH)

BIN := bin
RELEASE_DIR := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RELEASE_TARGETS := linux/amd64 linux/arm64 darwin/arm64 darwin/amd64

.PHONY: build install test test-race fmt vet tidy demo release clean

## build: compile the Go binaries into bin/
## (pagnet is the single production binary — CLI, daemon and MCP bridges;
## pagnet-fake-runtime is local test infrastructure, never shipped)
build:
	mkdir -p $(BIN)
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BIN)/pagnet ./cmd/pagnet
	$(GO) build -o $(BIN)/pagnet-fake-runtime ./cmd/pagnet-fake-runtime

## install: go-install the pagnet binary into GOPATH/bin
install:
	$(GO) install -ldflags "-X main.version=$(VERSION)" ./cmd/pagnet

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

## demo: seed a demo network with fake agents and sample traffic
## (requires a reachable control plane — see `pagnet login`)
demo: build
	$(BIN)/pagnet demo

## release: cross-compile the unified pagnet binary into dist/ as
## pagnet-<version>-<os>-<arch>.tar.gz, plus pagnet-latest-<os>-<arch>.tar.gz
## copies so `wget .../download/pagnet-latest-linux-amd64.tar.gz` stays
## stable. A control plane serves the tarballs at /download/
## (PAGNET_RELEASE_DIR); pagnet update / install.sh consume them.
##
## Each tarball contains exactly ONE executable — `pagnet` (CLI, daemon and
## MCP bridges in a single binary; the daemon self-spawns its bridges from
## its own executable, so no sibling binaries are shipped) — plus LICENSE
## and README.md. pagnet-fake-runtime is test infrastructure and never
## ships: a daemon reports only the runtime binaries it can actually find
## on PATH, so a host that never receives the fake binary simply never
## offers it.
release:
	@echo "building release tarballs (VERSION=$(VERSION))"
	mkdir -p $(RELEASE_DIR)
	## Prune versioned tarballs from older builds: dist/ keeps the current
	## version + the pagnet-latest-* copies, nothing else.
	@find $(RELEASE_DIR) -maxdepth 1 -name 'pagnet-*.tar.gz' ! -name 'pagnet-latest-*.tar.gz' ! -name "pagnet-$(VERSION)-*.tar.gz" -delete
	@for t in $(RELEASE_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		tmp=$$(mktemp -d); \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $$tmp/pagnet ./cmd/pagnet || rm -rf $$tmp; \
		cp LICENSE README.md $$tmp/; \
		tar -C $$tmp -czf $(RELEASE_DIR)/pagnet-$(VERSION)-$$os-$$arch.tar.gz pagnet LICENSE README.md || rm -rf $$tmp; \
		cp $(RELEASE_DIR)/pagnet-$(VERSION)-$$os-$$arch.tar.gz $(RELEASE_DIR)/pagnet-latest-$$os-$$arch.tar.gz || rm -rf $$tmp; \
		rm -rf $$tmp; \
	done
	@ls -1 $(RELEASE_DIR)/pagnet-*.tar.gz

clean:
	rm -rf $(BIN) $(RELEASE_DIR)
