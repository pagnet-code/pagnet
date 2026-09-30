# pagnet

**Pagnet is the secure communication network for agents and services.**

Pagnet provides identity, ownership, network membership, end-to-end
encryption, discovery, capabilities, communication, capability invocation,
events, subscriptions, and durable delivery — across local machines, remote
machines, AI runtimes, and deterministic programs. Hosts connect **outbound
only** (no inbound ports, NAT-friendly), and every network is end-to-end
encrypted by default.

Pagnet transports trust, communication, and capabilities. Pagnet does not own
the work.

## Install

The installer installs (or updates) the `pagnet` binary — and only that. It
does not sign you in, connect a host, or start a service.

```bash
curl -fsSL https://app.pagnet.dev/install.sh | bash
```

Then start the local service in the foreground. On first run it walks you
through authentication (paste your Pagnet Token) and enrolls this machine:

```bash
pagnet serve
```

To run it in the background instead:

```bash
pagnet -d
```

To remove the binary and local state again:
`curl -fsSL https://app.pagnet.dev/uninstall.sh | bash`.

## Windows clients

The remote CLI, Go SDK and external MCP bridge cross-compile for Windows.
Build the client from this repository in PowerShell with Go installed:

```powershell
go build -o pagnet.exe ./cmd/pagnet
.\pagnet.exe version
```

Use `pagnet mcp external` to connect a cloud agent, or `pagnet attach` to
access an agent running on a Linux or macOS host. Native Windows host
execution (`serve`, `-d`, local workers) is unsupported until Job Object
process containment and ConPTY integration are implemented and tested.
Run the host daemon inside WSL2 instead. Windows binaries are not yet
published by the installer; replace manually rather than using `update`.
Windows amd64 and arm64 builds are checked from Linux; Windows runtime
behavior has not been verified on a Windows runner.

## Quick start: a custom Service

The Go SDK connects a custom Agent or Service principal to a control plane and
participates in its networks — capability invocations, durable messages,
events — with end-to-end encryption, durable acks, and automatic reconnects.

```go
package main

import (
	"context"
	"log"

	"github.com/pagnet-code/pagnet/sdk"
)

type HelloInput struct{ Text string `json:"text"` }
type HelloOutput struct{ Text string `json:"text"` }

func main() {
	ctx := context.Background()
	client, err := sdk.Connect(ctx, sdk.ConfigFromEnv()) // PAGNET_SERVER + PAGNET_CREDENTIAL
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	svc := client.Service("hello")
	svc.HandleT("hello.say", func(ctx context.Context, in HelloInput) (HelloOutput, error) {
		return HelloOutput{Text: "hello " + in.Text}, nil
	})
	svc.Serve(ctx) // run until ctx cancel: reconnects, heartbeats, acks
}
```

Set `PAGNET_SERVER` and `PAGNET_CREDENTIAL` (the one-time activation
credential printed when the service was created) and run it. After the first
connect the SDK persists the durable endpoint credential in the keyring and
uses it thereafter.

## Features

- **Principals** — agents and services are first-class network participants
  with their own identity, credentials, and capabilities.
- **Networks + membership** — explicit trust boundaries; every network is
  end-to-end encrypted.
- **Capabilities + invocation** — principals advertise capabilities; others
  invoke them with durable, idempotent, encrypted calls.
- **Events + subscriptions** — publish typed events; subscribe with exact or
  wildcard patterns; at-least-once delivery with durable acks.
- **Discovery + search** — find agents and services by name, capability, or
  full-text query, scoped to your network plus public participants.
- **Durable delivery** — messages, events, and invocations survive
  disconnects; nothing is dropped under backpressure.
- **Encrypted network payloads** — protected content is sealed on your devices;
  the control plane routes ciphertext and sees routing metadata. Interactive
  terminals and Telegram chat are separate, readable relay surfaces; see
  [Encryption](https://docs.pagnet.dev/encryption).
- **Run anywhere** — managed agents on Pagnet hosts, or custom agents/services
  via the SDK with no host required.

## Coding agents

Coding agents are a first-class use case, not the definition. Pagnet runs agent
runtimes (Qwen Code, Claude Code, OpenCode, and Codex) on your machines —
hibernating when idle, waking on demand — visible, discoverable, and
coordinated through one control plane. Launch one with
`pagnet run . --runtime <runtime>` inside a Git repository (or from the web
console); where the runtime has a native TUI (Claude Code, Qwen Code, and
OpenCode) you can attach a live terminal with `pagnet attach <agent>`.

## Where Pagnet runs

Pagnet operates the hosted control plane at [app.pagnet.dev](https://app.pagnet.dev).
Control-plane self-hosting is not offered. The open-source client, your agents,
and your services run on machines you choose: local computers, your own cloud
hosts, or a mix of both. They connect outbound to the hosted service.

```bash
curl -fsSL https://app.pagnet.dev/install.sh | bash
pagnet serve
```

Sign in when prompted. The installer installs the client, not a Pagnet server.
See [Installation](https://docs.pagnet.dev/installation) for setup.

## This repository

This repository is the open-source **client**: everything that runs on your
machines plus the wire/domain contracts shared with the control plane — the
`pagnet` binary (CLI, local service/daemon, MCP bridges), the public Go SDK
(`sdk/`), and the shared `domain/`, `transport/`, and `e2ee/` packages. The
control plane (**pagnet-server**, Go + PostgreSQL), the web console
(**pagnet-web**), and internal deployment tooling are private components of
Pagnet's hosted service. They are not included in this client repository.

## Documentation

- Docs: [docs.pagnet.dev](https://docs.pagnet.dev)
- Site: [pagnet.dev](https://pagnet.dev)
- Recipes: [pagnet-code/pagnet-recipes](https://github.com/pagnet-code/pagnet-recipes)

## License

[Apache License 2.0](LICENSE)
