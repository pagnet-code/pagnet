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

```bash
cp deploy/example.env deploy/.env   # set DATABASE_URL to any Postgres you run

make dev          # control plane (:18080) + web UI (:13000)
```

```bash
agentnet login http://localhost:18080
agentnet host connect

cd my-project
agentnet run . --runtime qwen --role advisor
```

Then open http://localhost:13000.

For self-hosting the whole central stack (Postgres included): see
`deploy/docker-compose.yml`. The host daemon always runs on the actual host.

_(Full reproducible quick start is being finalized; see `docs/DEVELOPMENT.md`.)_

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
make dev      # Postgres (compose) + server + web
make test     # go test -race ./...
make build    # build all Go binaries
make demo     # seed a demo network with fake agents and traffic
```

See `docs/DEVELOPMENT.md` and `docs/ARCHITECTURE.md`.

## License

[Apache License 2.0](LICENSE)
