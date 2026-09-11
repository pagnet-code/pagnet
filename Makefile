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
# 1 = production tarballs (no pagnet-fake-runtime).
RELEASE_PROD ?= 0

.PHONY: dev dev-server dev-web pg-up build test test-race fmt vet tidy demo release release-prod clean

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
build:
	mkdir -p $(BIN)
	$(GO) build -o $(BIN)/pagnet-server ./cmd/pagnet-server
	$(GO) build -ldflags "-X main.version=$(VERSION)" -o $(BIN)/pagnetd ./cmd/pagnetd
	$(GO) build -o $(BIN)/pagnet-mcp ./cmd/pagnet-mcp
	$(GO) build -o $(BIN)/pagnet-control ./cmd/pagnet-control
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

## release: cross-compile the worker binaries (pagnet, pagnetd, the MCP
## bridges, pagnet-fake-runtime) into dist/ as
## pagnet-<version>-<os>-<arch>.tar.gz, plus pagnet-latest-<os>-<arch>.tar.gz
## copies so `wget .../download/ pagnet-latest-linux-amd64.tar.gz` stays
## stable. Serve dist/ at the server's /download/ (deploy compose mounts it;
## PAGNET_RELEASE_DIR).
##
## The bridges ship in every variant and are not optional: install.sh unpacks
## the tarball into ~/.local/bin, and the daemon hands that directory's
## pagnet-mcp / pagnet-control to every agent it starts as its MCP server. A
## tarball without them yields workers whose agents silently have no network
## tools at all — which is the entire point of a worker.
##
## release-prod: the production variant — tarballs WITHOUT
## pagnet-fake-runtime. The fake runtime is not hardcoded: a daemon
## reports only the runtime binaries it can actually find on PATH, so a
## production host that never receives the fake binary simply never
## offers it. Note: `release` and `release-prod` share dist/ and the
## pagnet-latest-* copies (last build wins), so build the variant you
## intend to serve last.
release:
	@echo "building release tarballs (VERSION=$(VERSION), prod=$(RELEASE_PROD))"
	mkdir -p $(RELEASE_DIR)
	## Prune versioned tarballs from older builds: dist/ keeps the current
	## version + the pagnet-latest-* copies, nothing else (no tags yet, so
	## per-commit artifacts would just accumulate).
	@find $(RELEASE_DIR) -maxdepth 1 -name 'pagnet-*.tar.gz' ! -name 'pagnet-latest-*.tar.gz' ! -name "pagnet-$(VERSION)-*.tar.gz" -delete
	@for t in $(RELEASE_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		tmp=$$(mktemp -d); \
		if [ "$(RELEASE_PROD)" = "1" ]; then tag="-prod"; else tag=""; fi; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $$tmp/pagnet ./cmd/pagnet || rm -rf $$tmp; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $$tmp/pagnetd ./cmd/pagnetd || rm -rf $$tmp; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $$tmp/pagnet-mcp ./cmd/pagnet-mcp || rm -rf $$tmp; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $$tmp/pagnet-control ./cmd/pagnet-control || rm -rf $$tmp; \
		if [ "$(RELEASE_PROD)" != "1" ]; then \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $$tmp/pagnet-fake-runtime ./cmd/pagnet-fake-runtime || rm -rf $$tmp; \
			tar -C $$tmp -czf $(RELEASE_DIR)/pagnet-$(VERSION)$$tag-$$os-$$arch.tar.gz pagnet pagnetd pagnet-mcp pagnet-control pagnet-fake-runtime || rm -rf $$tmp; \
		else \
			tar -C $$tmp -czf $(RELEASE_DIR)/pagnet-$(VERSION)$$tag-$$os-$$arch.tar.gz pagnet pagnetd pagnet-mcp pagnet-control || rm -rf $$tmp; \
		fi; \
		cp $(RELEASE_DIR)/pagnet-$(VERSION)$$tag-$$os-$$arch.tar.gz $(RELEASE_DIR)/pagnet-latest-$$os-$$arch.tar.gz || rm -rf $$tmp; \
		rm -rf $$tmp; \
	done
	@ls -1 $(RELEASE_DIR)/pagnet-*.tar.gz

## release-prod: production tarballs (pagnet, pagnetd and the bridges; no
## fake runtime)
release-prod:
	$(MAKE) release RELEASE_PROD=1

clean:
	rm -rf $(BIN)
