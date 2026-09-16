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

**1. Install** (on the machine where the agents will run):

```bash
curl -fsSL https://<your-control-plane>/install.sh | bash
```

On first run this signs you in (your browser opens — the one manual step),
connects this host, and starts the local service. On an already-connected
machine it only upgrades the binary and restarts the service (idempotent).

**2. Connect this host** (manual install / reconnect) — signs you in (opens
your browser on first run) and connects this host:

```bash
pagnet enroll --server https://<your-control-plane>
```

**3. Start the local service** (outbound only — no inbound ports). Restarts
the service if it is already running (idempotent):

```bash
pagnet -d
```

**4. Uninstall** (removes the service and local state):

```bash
curl -fsSL https://<your-control-plane>/uninstall.sh | bash
```

Then open the web UI — the host shows as connected, and you can launch agents
on it (`pagnet run . --runtime <runtime>` inside a Git repository, or from the
console). `pagnet serve` runs the same service in the foreground (containers,
supervisors); `pagnet login` signs in explicitly; `pagnet doctor` diagnoses
the local setup.

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

## Security model

The network trust boundary is the control-plane connection: hosts connect
outbound over HTTPS/WSS, and the client refuses plain HTTP for any
non-loopback control-plane or release URL (loopback `http://` stays allowed
for the dev stack; opt in elsewhere with `PAGNET_INSECURE_REMOTE_HTTP=1` or
`--insecure-remote-http`). Auto-updates install only a release whose
manifest is signed by a pinned key and whose tarball hashes to that
manifest.

The local trust boundary is the OS user, not a local authentication
mechanism. The daemon's Unix socket, state directory, and keyring are
protected by file permissions (0700 / 0600) only: a process running as the
**same UID** can read the keyring (the stored user token) and drive the
daemon socket, and the daemon does not authenticate same-UID peers — that
is the standard Unix-socket trust model. Run pagnet as a dedicated user if
other local users or processes must not be able to read its credentials or
issue commands to it.

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
