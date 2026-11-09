# Pagnet plugins for Claude Code and OpenAI

The shared source package in [`plugins/pagnet`](../plugins/pagnet) connects clients to Pagnet's hosted OAuth MCP endpoint, `https://app.pagnet.dev/api/v1/mcp`. It bundles a shared skill and client-specific manifests. No account token, client secret, or connector setup credential belongs in these manifests.

## Current local bridge requirement for messaging and capabilities

1. The network owner opens [Pagnet Integrations](https://app.pagnet.dev/integrations) and creates a connector for one network, selecting the allowed agents, capabilities, messaging targets, and event patterns.
2. Link the intended client through the connector's OAuth authorization flow.
3. Run the one-time `pagnet mcp connect` command provided by Integrations on the owner's device. Keep this bridge running so it can serve network requests with keys held locally. For an already configured connector, restart with `pagnet mcp connect --connector <connector-uuid>`.
4. Install and enable the plugin in the client. Finish its OAuth authorization prompt if needed and verify tool availability.

Installing or enabling the plugin does not start the device bridge. OAuth authorization and the local bridge are both required for messaging, capability, and event operations. These connectors remain limited to one network. Their MCP surface covers discovery/search, events, agent questions, approved invocations, and identity/request status, subject to connector policy.

## Authorize owner-delegated management

Management has separate consent in [Pagnet Integrations](https://app.pagnet.dev/integrations). The owner selects exact network/host/managed-agent tuples across one or more networks, chooses the allowed `read`, `launch`, and/or `stop` actions, and sets an expiry. The owner can revoke the grant there. The grant belongs to the provider, not an exact OAuth client; it must not be presented as isolation between clients of that provider. Messaging connector permissions do not authorize management.

The management tools use the same hosted OAuth MCP endpoint and existing `discover` and `invoke` scopes. They do not require the local device bridge. Authorization happens in the browser; the assistant never needs the owner's account credentials.

| Tool | Purpose |
| --- | --- |
| `pagnet_management_targets` | Discover the exact targets authorized by management consent. |
| `pagnet_management_status` | Inspect an authorized target's state. |
| `pagnet_management_launch` | Request launch of an authorized managed agent. |
| `pagnet_management_stop` | Request stop of an authorized managed agent. |

Launch and stop accept a `requestId`. Reuse the same request ID with the same target, action, and input when retrying. Their response means the request was accepted; it does not establish that the agent is running or stopped. Check `pagnet_management_status` before reporting the resulting state. Expired or revoked grants no longer authorize actions.

Network access is a second, independent consent in Integrations. The owner can select exact existing networks whose metadata the provider may read, and can separately authorize creation through one eligible owner host. The grant expires and can be revoked. It does not include future networks, agents, or lifecycle actions automatically. The provider can read only the selected metadata, and creating a network does not add it to the read grant.

| Tool | Purpose |
| --- | --- |
| `pagnet_networks_list` | List metadata for networks explicitly selected in network consent. |
| `pagnet_network_get` | Read metadata for one selected network. |
| `pagnet_network_create` | Request a new network through the exact owner host selected in consent. |
| `pagnet_network_create_status` | Check the state of that creation request. |

Network creation accepts a `requestId`; retry with the same ID and arguments. A created row can be `provisioning` or `activating` before it becomes `active`. Check status before claiming the network is usable. Creating agents with protected instructions, enrolling agents, permission grants, and broad administrative operations remain in Pagnet.

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

The portable package uses root `plugin.json`, root `mcp.json` with `type: "streamable-http"`, and the shared `skills/` directory. OAuth is declared under the MCP server's `extensions.com.openai.auth`; the package selects the provided public PKCE client `pagnet-chatgpt-connector` with `client.mode: "provided"` and `tokenEndpointAuthMethod: "none"`. OAuth endpoints remain available through discovery. No client secret or manual CIMD/DCR registration is required.

The repository catalog is `.agents/plugins/marketplace.json`. From a checkout, register it with:

```sh
codex plugin marketplace add .
```

Install or enable the single `pagnet` plugin from the `pagnet` marketplace in a supported client, then complete its browser OAuth prompt. The same plugin exposes the tools covered by the owner's separate connector, management, and network consents; additional plugins are not required. Messaging, capability, and event operations still require the local bridge described above. The ChatGPT desktop app supports local marketplace testing; restart it after adding a local marketplace if the catalog is not visible. Repository catalogs and local source installation are separate from public directory publication, and support varies by surface. For ChatGPT surfaces without local marketplace support, use the custom MCP connection flow with the hosted endpoint and OAuth rather than assuming this directory is already installed.

Codex and ChatGPT existing sessions may not reload installed plugin or MCP configuration. Depending on the client and API, a new turn, conversation, session, or app restart may be required. Verify the actual Pagnet tools before continuing; there is no universal hot attachment guarantee. See the official [OpenAI plugin packaging and marketplace guide](https://developers.openai.com/plugins/build/plugins).

## Validate the source package

From the repository root:

```sh
claude plugin validate ./plugins/pagnet
claude plugin validate .
python3 -m json.tool plugins/pagnet/plugin.json > /dev/null
python3 -m json.tool plugins/pagnet/.claude-plugin/plugin.json > /dev/null
python3 -m json.tool plugins/pagnet/.mcp.json > /dev/null
python3 -m json.tool plugins/pagnet/mcp.json > /dev/null
python3 -m json.tool .agents/plugins/marketplace.json > /dev/null
```

The portable OAuth declaration follows the OpenAI packaging guide. Validation of JSON syntax or manifests does not establish a live OAuth connection: end-to-end verification of messaging and capabilities requires an owner's authorized connector and running device bridge. Management verification requires separate, unexpired management consent for the selected targets and actions, with no device bridge required. Check client diagnostics during installation and confirm the applicable discovery/status tools before acting.
