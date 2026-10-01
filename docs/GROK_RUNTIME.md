# Grok Code

Grok Code is the native `grok` CLI, driven through its documented ACP stdio
endpoint. Pagnet owns one supervised process per managed instance and serializes
prompts through ACP v1. A host must actually have the executable installed;
rescan discovers later installations without restarting its live runtimes.

```sh
pagnet run --name assistant --runtime grok-code --host YOUR_HOST --workspace /absolute/workspace
```

`GROK_HOME` defaults to the instance's private directory under
`<daemon-state>/runtimes/grok-code/<instance>/home`. No global Grok configuration
is overwritten. For a named cached account, configure an immutable local profile:

```sh
pagnet runtime-profile add grok-work --runtime grok-code --env GROK_HOME=~/.pagnet/runtimes/grok-code/accounts/work
GROK_HOME=~/.pagnet/runtimes/grok-code/accounts/work grok login
```

Use the daemon's actual state root when it differs from `~/.pagnet`. Grok native
state must remain inside its dedicated `runtimes/grok-code` subtree. Alternatively,
provide `XAI_API_KEY` through a protected host environment or private profile
file; never put the key in CLI arguments or source control.

ACP `session/new` receives Pagnet's stdio MCP server directly. Native tool
permissions are never auto-approved: only an explicit option from the native
request is accepted. The machine endpoint has no attachable native TUI.
Hibernate requires advertised `loadSession` for materialised sessions; otherwise
the endpoint stays running. Wake resumes the exact native session or visibly
fails, without opening another conversation. Ambiguous prompt delivery or a
mid-turn connection loss is interrupted and never automatically retried.

For an independent native Grok MCP participant, provision its own scoped
activation/endpoint credential and protected environment (`PAGNET_SERVER`,
`PAGNET_CREDENTIAL`, separate `PAGNET_STATE_DIR`), then register the local bridge:

```sh
grok mcp add pagnet -- pagnet mcp external --network NETWORK_UUID --allow-message AGENT_UUID
```

Messaging grants expose encrypted ASK and only that participant's own replies.
Exact service operations separately use `--allow-invoke PRINCIPAL_UUID/CAPABILITY_ID`.
The provider can read MCP inputs/results. No account/host token is sent to Grok.

Grok's browser has a custom MCP setup flow, but Pagnet hosted OAuth is not enabled
until xAI's exact callback/client registration policy is verified. Native stdio
MCP is not browser authorization. No guessed callback, wildcard redirect, or
ChatGPT/Claude credential reuse is supported.

Sources checked 2026-10-01: [native ACP](https://docs.x.ai/build/cli/headless-scripting),
[CLI reference](https://docs.x.ai/build/cli/reference),
[settings](https://docs.x.ai/build/settings/reference),
[stdio MCP](https://docs.x.ai/build/features/mcp-servers),
[browser connectors](https://docs.x.ai/grok/connectors),
[ACP session setup](https://agentclientprotocol.com/protocol/v1/session-setup).
Tests use real supervised mock ACP subprocesses; no paid Grok execution is claimed.
