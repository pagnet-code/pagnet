# AgentNet developer Makefile
# Go is resolved from PATH first, then the local toolchain used on this machine.
GO ?= $(shell command -v go 2>/dev/null || echo $(HOME)/go-toolchain/go/bin/go)
export PATH := $(dir $(GO)):$(PATH)
COMPOSE ?= docker compose -f deploy/docker-compose.yml

BIN := bin
SERVER_ADDR ?= :18080
WEB_PORT ?= 13000
API_URL ?= http://localhost:18080

# Local development reuses an existing Postgres; credentials live in
# deploy/.env (see deploy/example.env), which the server also loads as a
# fallback for unset environment variables.
.PHONY: dev dev-server dev-web pg-up build test test-race fmt vet tidy demo clean

## dev: control plane (18080) + web UI (13000) in foreground (Ctrl+C stops all)
## Expects DATABASE_URL reachable (deploy/.env by default).
dev:
	$(MAKE) -j2 dev-server dev-web

dev-server:
	$(GO) run ./cmd/agentnet-server --addr $(SERVER_ADDR)

dev-web:
	cd web && NEXT_PUBLIC_API_URL=$(API_URL) PORT=$(WEB_PORT) npm run dev

## pg-up: optional — start AgentNet's own Postgres via compose (only if you
## do NOT already run a local Postgres to point DATABASE_URL at)
pg-up:
	$(COMPOSE) up -d postgres

## build: compile all Go binaries into bin/
build:
	mkdir -p $(BIN)
	$(GO) build -o $(BIN)/agentnet-server ./cmd/agentnet-server
	$(GO) build -o $(BIN)/agentnetd ./cmd/agentnetd
	$(GO) build -o $(BIN)/agentnet-mcp ./cmd/agentnet-mcp
	$(GO) build -o $(BIN)/agentnet-control ./cmd/agentnet-control
	$(GO) build -o $(BIN)/agentnet ./cmd/agentnet
	$(GO) build -o $(BIN)/agentnet-fake-runtime ./cmd/agentnet-fake-runtime

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
	$(BIN)/agentnet demo

clean:
	rm -rf $(BIN)
