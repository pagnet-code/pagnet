# Pagnet plugin

This source package provides the Pagnet hosted OAuth MCP connection and one shared skill for Claude Code and OpenAI ChatGPT/Codex. It contains no account credentials and starts no local process.

- `plugin.json` and `mcp.json`: portable Agent Plugins package with a provided public OAuth client for ChatGPT/Codex.
- `.claude-plugin/plugin.json` and `.mcp.json`: Claude Code package and HTTP MCP configuration.
- `skills/pagnet/SKILL.md`: shared setup and network usage instructions.

Install and enable the single Pagnet plugin in ChatGPT and complete its browser OAuth prompt. The package provides the public PKCE client `pagnet-chatgpt-connector`; no client secret or manual CIMD/DCR registration is needed. OAuth endpoints remain discoverable from the hosted service.

For messaging or capabilities, create the connector in Pagnet Integrations, authorize OAuth, and run the one-time `pagnet mcp connect` command shown there on the owner's device. Keep the bridge running, then enable the plugin in the client. Each connector has one network and explicitly approved access. Owner-delegated agent lifecycle actions and network metadata/creation use separate consent in Integrations and do not require the device bridge.

See [plugin integration instructions](../../docs/PLUGIN_INTEGRATIONS.md) for installation, client reload behavior, and validation. This directory can be distributed as source; repository marketplace entries point to it directly. A source package is not a publication in either vendor's public plugin directory.
