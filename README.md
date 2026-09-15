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
        pagnet        pagnet       pagnet
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
pagnet serve           # foreground — or: pagnet -d (detached, logs to ~/.pagnet/pagnetd.log)
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

## Terminal (interactive attach)

Workers have a live terminal: the runtime's **own interactive CLI**
(`qwen` / `claude` / the fake's demo UI) running under a PTY on the host,
proxied through the control plane — the host is never exposed to the
client.

- **Web** — `/agents` → pick an agent → `terminal` tab: it **attaches
  automatically**. The PTY starts on attach (resuming the stored runtime
  session) and **keeps running while you are away**: Detach is
  observational, Stop kills the process (both in the ⋯ menu). Scrollback
  is bounded (256 KiB); re-attaching replays the current screen, and a
  dropped connection shows a "Connection lost — reconnecting…" banner
  until the backoff succeeds.
- **CLI** — `pagnet attach <agent>`: raw terminal (keystrokes, arrow
  keys, Ctrl+C reach the runtime directly; window resizes are forwarded).
  **Ctrl-]** detaches (tmux-style) — the PTY keeps running on the host.

Representatives keep the text proxy (input → turn → turn output).

## Repository layout

This repository is the open-source **client**: everything that runs on your
machines plus the wire/domain contracts they share with the control plane.

| Path | What |
|------|------|
| `cmd/pagnet` | The one production binary: CLI (login, enroll, run, agents, tasks, attach, ...), local service (`pagnet serve` / `pagnet -d`), and the MCP bridges (`pagnet mcp worker\|control`, spawned by the daemon) |
| `cmd/pagnet-fake-runtime` | Deterministic fake runtime (test/dev infrastructure, not shipped) |
| `domain/` | Domain model shared with the control plane |
| `transport/` | Wire protocol (WSS envelopes) shared with the control plane |
| `internal/` | Client packages (daemon, runtime adapters, MCP bridges, config, release updater) |

The rest of the product lives in sibling repositories:

- **pagnet-server** — the control plane (Go + PostgreSQL)
- **pagnet-web** — the Next.js control panel
- **pagnet-monorepo** — Docker Compose deployment + cross-repo E2E suite

## Development

```bash
make test      # go test ./...          (or `make test-race` for -race)
make build     # build the Go binaries into bin/
make install   # go-install pagnet into GOPATH/bin
make demo      # build + seed a demo network with fake agents and traffic
make release   # one-binary tarballs for all targets into dist/
```

Run the CLI against any control plane (hosted or self-hosted) with
`pagnet login` — see the deployment docs in the pagnet-monorepo repository.

## License

[Apache License 2.0](LICENSE)
