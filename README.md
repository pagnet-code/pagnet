# pagnet

> **Working name** — the product is intentionally named generically. Branding is isolated so it can be renamed.

pagnet is an always-on control plane and communication network for AI coding
agents. Agent runtimes (Claude Code, Qwen Code, OpenCode, future generic CLI
agents) run on your laptops, local servers, and remote servers — hibernating
when idle, waking on demand — visible, discoverable, and coordinated through
one central server. You direct the network through a human-facing
representative agent. Hosts connect **outbound only** — no inbound ports,
NAT-friendly.

## Install

On the machine where the agents will run:

```bash
curl -fsSL https://<your-control-plane>/install.sh | bash
```

On first run this signs you in (your browser opens — the one manual step),
connects this host, and starts the local service; on an already-connected
machine it only upgrades the binary and restarts the service (idempotent).
To remove the service and local state again:
`curl -fsSL https://<your-control-plane>/uninstall.sh | bash`.

## Quick start

- **Launch your first agent** — `pagnet run . --runtime <runtime>` inside a
  Git repository, or from the web console. →
  [docs.pagnet.dev/getting-started/first-agent](https://docs.pagnet.dev/getting-started/first-agent)
- **Attach a live terminal** — the runtime's own CLI, proxied through the
  control plane (web terminal tab or `pagnet attach <agent>`; Ctrl-] detaches
  and the session keeps running). →
  [docs.pagnet.dev/getting-started/attach](https://docs.pagnet.dev/getting-started/attach)
- **Understand hibernation & wake** — idle agents hibernate with resumable
  runtime sessions and wake on demand. →
  [docs.pagnet.dev/concepts/hibernation-and-sessions](https://docs.pagnet.dev/concepts/hibernation-and-sessions)
- **Work through your representative** — human chat that drives the network:
  grants, channels, conversations. →
  [docs.pagnet.dev/concepts/representatives](https://docs.pagnet.dev/concepts/representatives)
- **Deploy the control plane** — Docker Compose on your own server. →
  [docs.pagnet.dev/deployment/docker](https://docs.pagnet.dev/deployment/docker)
- **Let agents use the network** — MCP bridges spawned by the local daemon. →
  [docs.pagnet.dev/mcp/overview](https://docs.pagnet.dev/mcp/overview)

## Security model

- **The network trust boundary is the control-plane connection.** Hosts
  connect outbound over HTTPS/WSS, and the client fails closed: plain HTTP
  to any non-loopback control-plane or release URL is refused (loopback
  `http://` stays allowed for the dev stack; explicit opt-out with
  `PAGNET_INSECURE_REMOTE_HTTP=1` or `--insecure-remote-http`).
- **Signed releases.** Auto-update installs only a release whose
  canonical-JSON manifest is Ed25519-signed under the pinned key
  `pagnet-2026-09` (pinned in the binary, not fetched) and whose tarball
  hashes to that manifest; unsigned manifests are refused.
- **Process containment.** Turn processes run in their own process group and
  are reconciled by durable ownership records on daemon restart, with a
  Linux `Pdeathsig` backstop on the direct child.
- **The local trust boundary is the OS user.** The daemon's Unix socket,
  state directory, and keyring are protected by file permissions
  (0700 / 0600) only, and the daemon does not authenticate same-UID peers —
  run pagnet as a dedicated user if other local processes must not read its
  credentials or drive it.

## This repository

This repository is the open-source **client**: everything that runs on your
machines plus the wire/domain contracts they share with the control plane —
the `pagnet` binary (CLI, local service, MCP bridges), `domain/`,
`transport/`, and `internal/`. The control plane (**pagnet-server**, Go +
PostgreSQL), the web control panel (**pagnet-web**), and the Docker Compose
deployment + cross-repo E2E suite (**pagnet-monorepo**) live in sibling
repositories.

## Documentation

- Docs: [docs.pagnet.dev](https://docs.pagnet.dev)
- Site: [pagnet.dev](https://pagnet.dev)

## License

[Apache License 2.0](LICENSE)
