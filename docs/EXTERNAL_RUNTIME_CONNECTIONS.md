# Connect independently launched runtimes

An independent runtime can use Pagnet's scoped MCP capability and messaging tools without moving its terminal or process into Pagnet. Pagnet never claims ownership of an existing terminal, interrupts its prompt or stops it on disconnect.

## Private bridge profile

Create a dedicated principal with active membership in the intended network and a narrowly scoped activation or endpoint credential. Store the settings on the same host as the external runtime:

```sh
pagnet mcp external-profile add work --principal PRINCIPAL_UUID --network NETWORK_UUID
```

Enter the credential at the hidden prompt. The command verifies its principal and network before saving. Discovery is the default. Add repeated `--allow-invoke PRINCIPAL_UUID/CAPABILITY_ID` or `--allow-message AGENT_UUID` only for intended targets. These grants cannot exceed server permissions. Each profile has a separate local SDK keyring and can restart after activation exchange using its own durable credential.

No credential enters process arguments, runtime configuration, an MCP URL or a vendor home. Private configuration lives at `~/.pagnet/external-profiles/work.json` (owner-owned, regular, mode0600). Linux/macOS ownership is supported; Windows private profiles require verified ACL support and are currently refused. A non-interactive operator may create this same private JSON directly:

```json
{
  "version": 1,
  "principal": "PRINCIPAL_UUID",
  "network": "NETWORK_UUID",
  "server": "https://app.pagnet.dev",
  "credential": "PRINCIPAL_ACTIVATION_OR_ENDPOINT_CREDENTIAL",
  "grants": [],
  "messagingTargets": []
}
```

Never put that JSON in a repository or shared project configuration. `--state-dir` chooses another private local state directory. Run the bridge as a stdio MCP server with:

```sh
pagnet mcp external --profile work
```

Profiles reject policy or HTTP overrides; changing flags cannot silently broaden a saved profile. This is an independent participant, not the managed worker/control surface or a task executor.

## Live Qwen serve connection

This optional integration requires an already-running authenticated Qwen **serve** API that advertises protocol v1, `http-bridge`, `mcp_server_runtime_mutation` and workspace-qualified REST. It does not assume that an ordinary Qwen TUI exposes an API. Current Qwen documentation marks serve experimental. Enable operator authentication using the runtime's supported `--require-auth` setup; keep its operator token in a separate private file on the same host.

Use the existing session ID and registered client ID supplied by your Qwen client. Pagnet verifies the exact live session, trusted workspace and authenticated loopback endpoint before mutation:

```sh
pagnet mcp runtime-connect --profile work \
  --url http://127.0.0.1:4170 --workspace /absolute/workspace \
  --session EXISTING_SESSION_ID --client-id REGISTERED_CLIENT_ID \
  --token-file /absolute/private/qwen-operator-token
```

A literal loopback IP and explicit port are required; remote endpoints, DNS names, redirects and unauthenticated APIs are refused. The integration adds a uniquely named runtime MCP entry with the fixed local `pagnet mcp external --profile` command. It sends no profile credentials or environment values to Qwen's configuration API. Native tools must be confirmed before reporting connection success. The entry is workspace-scoped, so other sessions sharing that Qwen workspace can see its tools; choose an isolated workspace when that access is inappropriate.

The command prints a connection record name before attempting mutation, so even a timeout has an explicit cleanup handle:

```sh
pagnet mcp runtime-disconnect pagnet_external_CONNECTION_ID
```

Disconnect removes only the recorded MCP entry and preserves the external session, terminal, prompts and configuration. If the operator token or registered client changed, supply the current `--token-file` or `--client-id`. An ambiguous failure retains the local record until removal is confirmed. The private bridge profile remains available for another connection. Qwen's ephemeral MCP overlay disappears on its own daemon restart; no global settings are written.

## Other native runtimes

Configure the stdio command above using the native client's session-local MCP mechanism. Pagnet does not automatically edit its global configuration:

- [Claude Code](https://code.claude.com/docs/en/mcp): use a session `--mcp-config` at launch or an SDK-owned query's `setMcpServers()`. This does not give Pagnet access to an unrelated TUI's control channel.
- [Codex App Server](https://learn.chatgpt.com/docs/app-server): configure the fixed executable and args through owned app-server configuration. `config/mcpServer/reload` refreshes loaded configuration, not arbitrary terminals.
- [OpenCode](https://opencode.ai/docs/server/): its exposed server supports dynamic `POST /mcp`, but this release does not automate a connect/disconnect lifecycle for that API. Use native configuration for the local stdio bridge.
- Other MCP clients can run the same fixed command when they support local stdio MCP. A native protocol, account or permissions must still be supplied by that runtime; Pagnet does not infer them from a name.

Primary Qwen contract: [Qwen serve runtime MCP management](https://github.com/QwenLM/qwen-code/blob/main/docs/users/qwen-serve.md), and [workspace MCP control routes](https://github.com/QwenLM/qwen-code/blob/main/packages/cli/src/serve/routes/workspace-mcp-control.ts).
