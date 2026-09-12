# pagnet developer Makefile
# Go is resolved from PATH first, then the local toolchain used on this machine.
GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/go-toolchain/go/bin/go)
export PATH := $(dir $(GO)):$(PATH)
COMPOSE ?= docker compose -f deploy/docker-compose.yml

BIN := bin
SERVER_ADDR ?= :18080
# Optional: pin the web's API base (empty = follow the browser's own hostname).
API_URL ?=

# Local development reuses an existing Postgres; credentials live in
# deploy/.env (see deploy/example.env), which the server also loads as a
# fallback for unset environment variables.
RELEASE_DIR := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
RELEASE_TARGETS := linux/amd64 linux/arm64 darwin/arm64 darwin/amd64

.PHONY: dev dev-server dev-web pg-up build test test-race fmt vet tidy demo release clean

## dev: control plane (18080) + web UI (13000) in foreground (Ctrl+C stops all)
## Expects DATABASE_URL reachable (deploy/.env by default).
dev:
	$(MAKE) -j2 dev-server dev-web

dev-server:
	$(GO) run ./cmd/pagnet-server --addr $(SERVER_ADDR)

## dev-web: Next.js UI on 13000. The API base follows the browser's own
## hostname by default; pass API_URL=http://host:18080 to pin it.
dev-web:
	cd web && NEXT_PUBLIC_PAGNET_API=$(API_URL) npm run dev

## pg-up: optional — start pagnet's own Postgres via compose (only if you
## do NOT already run a local Postgres to point DATABASE_URL at)
pg-up:
	$(COMPOSE) up -d postgres

## build: compile all Go binaries into bin/
## (pagnet is the single production binary — CLI, daemon and MCP bridges;
## pagnet-fake-runtime is local test infrastructure, never shipped)
build:
	mkdir -p $(BIN)
	$(GO) build -o $(BIN)/pagnet-server ./cmd/pagnet-server
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BIN)/pagnet ./cmd/pagnet
	$(GO) build -o $(BIN)/pagnet-fake-runtime ./cmd/pagnet-fake-runtime

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

## demo: seed demo-software network with fake agents and sample traffic
demo: build
	$(BIN)/pagnet demo

## release: cross-compile the unified pagnet binary into dist/ as
## pagnet-<version>-<os>-<arch>.tar.gz, plus pagnet-latest-<os>-<arch>.tar.gz
## copies so `wget .../download/ pagnet-latest-linux-amd64.tar.gz` stays
## stable. Serve dist/ at the server's /download/ (deploy compose mounts it;
## PAGNET_RELEASE_DIR).
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
	## version + the pagnet-latest-* copies, nothing else (no tags yet, so
	## per-commit artifacts would just accumulate).
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
	rm -rf $(BIN)
