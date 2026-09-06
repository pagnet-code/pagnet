# pagnet

> **Working name** — the product is intentionally named generically. Branding is isolated so it can be renamed.

pagnet is a control plane and communication network for AI coding agents. It lets agents built on different runtimes (Claude Code, Qwen Code, OpenCode, future generic CLI agents) run on laptops, local servers, and remote servers while being visible, discoverable, and coordinated through one central server.

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
       pagnetd      pagnetd     pagnetd
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

**2. Sign in as a user.** Auth mode is `PAGNET_AUTH_MODE` (`token`, `local`,
or `oidc`; `deploy/example.env` documents each):

- **token** (default): one admin bearer. When `PAGNET_ADMIN_TOKEN` is empty
  the server bootstraps a random token and prints it **once** at startup —
  grab it from the dev console / `docker compose logs server` and store it:

  ```bash
  pagnet login --server http://localhost:18080 --token "$ADMIN_TOKEN"
  ```

- **local**: create the first account in the web UI (`http://localhost:13000`,
  the `/setup` page — no default credentials), then:

  ```bash
  pagnet login --server http://localhost:18080   # prompts for username/password
  ```

- **oidc**: any external IdP via `OIDC_*` env vars (Keycloak included);
  `pagnet login` runs the device flow.

`pagnet login` stores a revocable API token in `~/.pagnet/config.yaml`
(0600) and every CLI command uses it automatically.

**3. Connect a host** (on the machine where the agents will run). Enroll the
host with a one-time token, then start the daemon:

```bash
# one-time enrollment token (plaintext is shown exactly once)
TOKEN=$(curl -s -X POST localhost:18080/api/v1/hosts/enrollment-tokens \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"name":"my-host","allowedRoots":["$HOME"],"ttlSeconds":3600}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# consume the token; stores the host credential in ~/.pagnet/config.yaml (0600)
pagnet enroll --server http://localhost:18080 --token "$TOKEN"

# start the host daemon (outbound WSS; keep it running)
pagnetd
```

**4. Launch an agent** in a Git repository:

```bash
cd my-project
pagnet run . --runtime fake --role coder    # fake | qwen | claude
```

Then open http://localhost:13000 — the host shows as connected, and the agent
appears under the default network. `make demo` seeds a ready-to-watch demo
network with three fake agents and sample tasks.

For self-hosting the whole central stack (Postgres included): see
`deploy/docker-compose.yml`. The host daemon always runs on the actual host.

## Repository layout

| Path | What |
|------|------|
| `cmd/pagnet` | CLI (login, enroll, run, agents, tasks, attach, ...) |
| `cmd/pagnetd` | Per-machine host daemon |
| `cmd/pagnet-server` | Central control plane (Go) |
| `cmd/pagnet-mcp` | Local stdio MCP bridge for runtimes |
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
