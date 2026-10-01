# Session-local Pagnet guidance

Managed runtimes receive coordination instructions through native session surfaces: Claude's append-system-prompt file, Qwen's appended system prompt, Codex's developer instructions and OpenCode's instructions configuration. Pagnet adds a concise explicitly referenced skill at:

```
~/.pagnet/sessions/INSTANCE_UUID/.pagnet/skills/pagnet-coordination/SKILL.md
```

A custom daemon state directory changes the prefix. The skill is private, available within that instance's sandbox and removed when the instance is forgotten. Work products are preserved. It is not installed into a global vendor skill directory and does not rely on universal automatic skill discovery. Attaching to an already-managed terminal does not create a synthetic model turn or interrupt native work to reload instructions.

The skill explains Pagnet peer messaging, persistent short references, claiming task offers before execution, encrypted task results and human-channel reply tools. Operator instructions remain separate. Memberships and scoped permissions still govern tool actions.

## An independently launched session

Connecting an external runtime to Pagnet's MCP tools does not transfer ownership of its terminal. Pagnet can manage PTYs it launched or owns; it cannot capture an arbitrary already-running shell session merely from a vendor session identifier.

The existing independent bridge can be configured as a local stdio MCP server:

```sh
pagnet mcp external --network NETWORK_UUID
```

The MCP process needs `PAGNET_SERVER` and `PAGNET_CREDENTIAL` in its local environment. Use a principal activation or endpoint credential with active membership in that exact network; never a user or host credential. Keep secrets in the client's private environment/configuration rather than command arguments or shared project files. Discovery is the default. Add only intended capability grants with repeated `--allow-invoke PRINCIPAL_UUID/CAPABILITY_ID`. This independent surface exposes capability discovery and invocation, not a managed worker identity or its task/channel authority.

Remove the external MCP server or close its bridge to disconnect; this does not stop the externally owned runtime. Managed `pagnet attach` remains for Pagnet-owned instances. This release does not install or modify an external runtime's global configuration.

Native connection APIs have different ownership and version requirements:

- [Codex App Server](https://learn.chatgpt.com/docs/app-server) supports `config/mcpServer/reload` through an owned app-server connection. It reloads configuration; it is not a terminal-adoption API.
- [Claude Code MCP](https://code.claude.com/docs/en/mcp) documents session MCP configuration and the Agent SDK's `setMcpServers()` method. An SDK-owned query is distinct from an unrelated already-running TUI.
- [OpenCode server](https://opencode.ai/docs/server/) supports dynamic `POST /mcp` on an exposed server. Its authenticated server context and scope must be verified before mutation; availability does not prove terminal ownership.
- [Qwen serve](https://github.com/QwenLM/qwen-code/blob/main/docs/users/qwen-serve.md) documents workspace MCP add/remove in an experimental v0.16-alpha daemon. This cannot be assumed for an ordinary Qwen terminal or an older binary.

These APIs make specific native integrations possible. They do not justify automatic scanning, unauthenticated localhost mutation, global configuration changes or stopping an external session on disconnect.
