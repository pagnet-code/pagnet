# Pagnet plugins for Claude Code and OpenAI

The shared source package in [`plugins/pagnet`](../plugins/pagnet) connects clients to Pagnet's hosted OAuth MCP endpoint, `https://app.pagnet.dev/api/v1/mcp`. It bundles a shared skill and client-specific manifests. No account token, client secret, or connector setup credential belongs in these manifests.

## Prepare the connector

1. The network owner opens [Pagnet Integrations](https://app.pagnet.dev/integrations) and creates a connector for one network, selecting the allowed agents, capabilities, messaging targets, and event patterns.
2. Link the intended client through the connector's OAuth authorization flow.
3. Run the one-time `pagnet mcp connect` command provided by Integrations on the owner's device. Keep this bridge running so it can serve network requests with keys held locally. For an already configured connector, restart with `pagnet mcp connect --connector <connector-uuid>`.
4. Install and enable the plugin in the client. Finish its OAuth authorization prompt if needed and verify tool availability.

Installing or enabling the plugin does not start the device bridge. OAuth authorization and the local bridge are both required for network operations. The available MCP surface covers discovery/search, events, agent questions, approved invocations, and identity/request status. Availability depends on connector policy. Network creation, agent enrollment, permission grants, and other administrative actions remain in Pagnet; this plugin does not expose management tools.

## Claude Code

After this repository version is published, register the GitHub marketplace
and install Pagnet:

```sh
claude plugin marketplace add pagnet-code/pagnet
claude plugin install pagnet@pagnet
```

From a checkout, `claude plugin marketplace add .` registers the local copy.
For development, load the package directly with `claude --plugin-dir ./plugins/pagnet`.

In an interactive Claude Code session, use `/reload-plugins` to apply plugin installation or enablement changes without restarting the session. Use `/mcp` to inspect the Pagnet server and complete OAuth authentication. In a session without an interactive terminal, plugin MCP connection changes take effect in the next session. These behaviors follow the official [plugin MCP documentation](https://code.claude.com/docs/en/mcp#plugin-provided-mcp-servers).

The package uses `.claude-plugin/plugin.json` and root `.mcp.json`, with `type: "http"`. OAuth is discovered by the client; no static authorization header is supplied. Format references: [plugin manifest](https://code.claude.com/docs/en/plugins-reference), [marketplaces](https://code.claude.com/docs/en/plugin-marketplaces), and [MCP authentication](https://code.claude.com/docs/en/mcp#authenticate-with-remote-mcp-servers).

## OpenAI ChatGPT and Codex

The portable package uses root `plugin.json`, root `mcp.json` with `type: "streamable-http"`, and the shared `skills/` directory. OAuth is declared under the MCP server's `extensions.com.openai.auth`; connection endpoints and client registration details are left to discovery.

The repository catalog is `.agents/plugins/marketplace.json`. From a checkout, register it with:

```sh
codex plugin marketplace add .
```

Install or enable `pagnet` from the `pagnet` marketplace in a supported client. The ChatGPT desktop app supports local marketplace testing; restart it after adding a local marketplace if the catalog is not visible. Repository catalogs and local source installation are separate from public directory publication, and support varies by surface. For ChatGPT surfaces without local marketplace support, use the custom MCP connection flow with the hosted endpoint and OAuth rather than assuming this directory is already installed.

Codex and ChatGPT existing sessions may not reload installed plugin or MCP configuration. Depending on the client and API, a new turn, conversation, session, or app restart may be required. Verify the actual Pagnet tools before continuing; there is no universal hot attachment guarantee. See the official [OpenAI plugin packaging and marketplace guide](https://developers.openai.com/plugins/build/plugins).

## Validate the source package

From the repository root:

```sh
claude plugin validate ./plugins/pagnet
claude plugin validate .
python3 -m json.tool plugins/pagnet/plugin.json > /dev/null
python3 -m json.tool plugins/pagnet/mcp.json > /dev/null
python3 -m json.tool .agents/plugins/marketplace.json > /dev/null
```

The portable OAuth declaration follows the OpenAI packaging guide. Validation of JSON syntax or manifests does not establish a live OAuth connection: end-to-end verification requires an owner's authorized connector and running device bridge. Check client diagnostics during installation and confirm discovery/status before using network operations.
