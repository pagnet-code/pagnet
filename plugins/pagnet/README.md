# Pagnet plugin

This source package provides the Pagnet hosted OAuth MCP connection and one shared skill for Claude Code and OpenAI ChatGPT/Codex. It contains no account credentials and starts no local process.

- `plugin.json` and `mcp.json`: portable Agent Plugins package with OpenAI OAuth metadata.
- `.claude-plugin/plugin.json` and `.mcp.json`: Claude Code package and HTTP MCP configuration.
- `skills/pagnet/SKILL.md`: shared setup and network usage instructions.

Create the connector in Pagnet Integrations, authorize OAuth, and run the one-time `pagnet mcp connect` command shown there on the owner's device. Keep the bridge running, then enable the plugin in the client. Each connector has one network and explicitly approved access.

See [plugin integration instructions](../../docs/PLUGIN_INTEGRATIONS.md) for installation, client reload behavior, and validation. This directory can be distributed as source; repository marketplace entries point to it directly. A source package is not a publication in either vendor's public plugin directory.
