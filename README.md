# AgentNet

> **Working name** — the product is intentionally named generically. Branding is isolated so it can be renamed.

AgentNet is a control plane and communication network for AI coding agents. It lets agents built on different runtimes (Claude Code, Qwen Code, OpenCode, future generic CLI agents) run on laptops, local servers, and remote servers while being visible, discoverable, and coordinated through one central server.

```text
                    CENTRAL SERVER

          +-----------------------------+
          |       Control Plane         |
          |             Go              |
          |                             |
          | networks   agents   tasks   |
          | hosts      resources ...    |
          +-------------+---------------+
                        |
                  PostgreSQL
                        |
              HTTPS / WebSocket
                        |
           +------------+-------------+
           |            |             |
           v            v             v
        Host A         Host B        Host C
       agentnetd      agentnetd     agentnetd
           |            |             |
       local agents local agents   local agents
```

Hosts connect **outbound only** — no inbound ports, NAT-friendly.

## Quick start

**1. Start the central stack** (control plane on :18080, web UI on :13000):

```bash
cp deploy/example.env deploy/.env   # set DATABASE_URL to any Postgres you run
make dev                            # control plane (:18080) + web UI (:13000)
```

**2. Connect a host** (on the machine where the agents will run). Enroll the
host with a one-time token, then start the daemon. In `dev` auth mode the
enrollment call from localhost needs no admin token:

```bash
# one-time enrollment token (plaintext is shown exactly once)
TOKEN=$(curl -s -X POST localhost:18080/api/v1/hosts/enrollment-tokens \
  -d '{"name":"my-host","allowedRoots":["$HOME"],"ttlSeconds":3600}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# consume the token; stores the credential in ~/.agentnet/config.yaml (0600)
agentnet login --server http://localhost:18080 --token "$TOKEN"

# start the host daemon (outbound WSS; keep it running)
agentnetd
```

**3. Launch an agent** in a Git repository:

```bash
cd my-project
agentnet run . --runtime fake --role coder    # fake | qwen | claude
```

Then open http://localhost:13000 — the host shows as connected, and the agent
appears under the default network. `make demo` seeds a ready-to-watch demo
network with three fake agents and sample tasks.

For self-hosting the whole central stack (Postgres included): see
`deploy/docker-compose.yml`. The host daemon always runs on the actual host.

## Repository layout

| Path | What |
|------|------|
| `cmd/agentnet` | CLI (login, host, run, agents, tasks, attach, ...) |
| `cmd/agentnetd` | Per-machine host daemon |
| `cmd/agentnet-server` | Central control plane (Go) |
| `cmd/agentnet-mcp` | Local stdio MCP bridge for runtimes |
| `internal/` | Go packages (domain, store, controlplane, daemon, runtimes, ...) |
| `migrations/` | PostgreSQL migrations (goose) |
| `web/` | Next.js control panel (App Router, TypeScript) |
| `deploy/` | Docker Compose + example env |
| `docs/` | Architecture, protocol, development docs |

## Development

```bash
make dev       # control plane (:18080) + web UI (:13000); Postgres is optional via `make pg-up`
make test      # go test ./...          (or `make test-race` for -race)
make build     # build all Go binaries into bin/
make demo      # build + seed a demo network with fake agents and traffic
```

See `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`, and `docs/IMPLEMENTATION_STATUS.md`.

## License

[Apache License 2.0](LICENSE)
