# Runtime integration surfaces

Engineering snapshot: 2026-11-26, Pagnet main `4dc7e6b`. Runtime documentation
describes upstream capabilities, not a promise that every installed version
implements them. Recommendations below are integration choices, not implemented
changes.

## Ownership boundary

A **managed session** has a Pagnet-owned native process, transport and session
identity. Pagnet can submit work through that transport and correlate native
events. An **independent MCP-connected session** belongs to the user or another
host application. MCP exposes Pagnet tools to that participant; connecting it
does not grant Pagnet control of its native conversation, an inbound prompt
channel, or permission to restart it. See [external runtime connections](EXTERNAL_RUNTIME_CONNECTIONS.md).

Integrations must preserve that distinction. Do not force a restart, adopt a
different conversation, or edit global runtime settings to retrofit an existing
session. Use its already-supported control surface, an explicitly enabled local
extension, or leave inbound delivery pending with the limitation visible.

## Current Pagnet adapters

These are the managed paths in the cited code, not all upstream possibilities.

| Runtime | Current adapter surface | Consequence |
| --- | --- | --- |
| Qwen Code | [QwenPersistent](../internal/runtime/qwen_persistent.go): one native TUI under a PTY; `--input-file` JSONL submissions/confirmation responses and `--json-file` structured events. | Human attachment and machine input share the same native session. Unacknowledged input is surfaced rather than blindly retried. This adapter does not use the daemon REST API. |
| Codex | [CodexPersistent](../internal/runtime/codex_persistent.go): supervised `codex app-server --stdio`, JSON-RPC thread/turn control, notifications and native interaction requests. | Structured persistent endpoint; managed submissions are serialized. Its machine process has no attachable native TUI. |
| Claude Code | [ClaudePersistent](../internal/runtime/claude_persistent.go): persistent `claude -p` with stream-json input/output, initialize/control messages and stdio permission requests. | Existing native conversation receives machine submissions and structured results; no hook is needed for managed input. |
| OpenCode | [NewOpenCodePersistent](../internal/runtime/opencode_persistent.go): `opencode acp`, private configuration and native state, using the shared ACP driver. | A private machine endpoint, not attachment to a shared OpenCode server or a replacement TUI. |
| Grok Build (Pagnet `grok-code`) | [NewGrok](../internal/runtime/grok.go): `grok --no-auto-update … agent stdio`, using the shared ACP driver. | Pagnet owns the ACP process and private native home; no second native TUI attachment. |

The [ACP driver](../internal/runtime/acp_driver.go) initializes the endpoint,
passes MCP servers at session creation, and resumes materialized sessions only
when the runtime advertises `loadSession`; [turn handling](../internal/runtime/acp_turn.go)
uses native prompt/update/cancel messages. These adapters are not a general
mechanism for attaching to independently launched sessions.

## Official surfaces and integration choice

“Live” below means the documented operation can reach a compatible running
session. It does not mean Pagnet already implements it or can retrofit a new
transport into an arbitrary process.

| Runtime | Official extension/event surface | Can it apply live? | Best Pagnet choice |
| --- | --- | --- | --- |
| Qwen Code | [Daemon REST/SSE](https://qwenlm.github.io/qwen-code-docs/en/developers/daemon-rest-api-reference/): capabilities, session lifecycle, prompt/cancel, events and transcript. [Hooks](https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/) cover session, prompt, tool and completion events. | REST addresses live daemon-owned sessions; prompt `202` means queued, with completion correlated by `promptId`. Hook definitions reload through the interactive `/hooks` menu; file edits alone do not reload them. Hook controls/security changes still require restart. | Retain dual-output for managed TUI sessions. Prefer capability-negotiated REST/SSE for a future daemon-owned integration; hooks can report lifecycle or add context, while delivery stays in Pagnet's queue. |
| Codex | [App-server](https://developers.openai.com/codex/app-server): bidirectional JSON-RPC, thread resume, turn start/interrupt, active-turn steering and structured item/turn events. | A connected client can start a turn on a loaded thread or use `turn/steer` with the expected active turn ID. This is control through an available app-server endpoint, not arbitrary CLI attachment. | Keep app-server as the managed control and observation surface. Gate newer methods against the installed schema/version; do not substitute hooks for native turn correlation. |
| Claude Code | [Hooks](https://code.claude.com/docs/en/hooks) observe session/prompt/tool/completion events and can return event-specific decisions/context. [Settings](https://code.claude.com/docs/en/settings#when-edits-take-effect) define configuration scope and reload behavior. | Most settings edits, including hooks, reload in the running session; some settings remain startup-only. Hook execution still depends on its lifecycle event. | Keep stream-json for managed submissions/results. Optional scoped hooks can improve independent-session observation or context at supported boundaries; live hook installation alone does not establish durable inbound delivery. |
| OpenCode | [Plugin parts](https://opencode.ai/docs/build/plugins) include server/TUI/GUI/RPC. The [server API](https://opencode.ai/docs/build/plugins/server) provides event subscriptions, session prompting and prompt/context/tool hooks. | [Watched configuration directories reload automatically](https://opencode.ai/docs/plugins#reload); unwatched local dependencies may require restart. V1/V2 plugin APIs differ. | Keep ACP for the managed private endpoint. For an explicitly enabled independent-session bridge, prefer a version-compatible server plugin using session APIs and events, backed by Pagnet's queue. A UI-only plugin is insufficient for delivery ownership. |
| Grok Build | [Plugins](https://docs.x.ai/build/features/skills-plugins-marketplaces) package skills, agents, hooks, MCP and LSP servers. [Hooks](https://docs.x.ai/build/features/hooks) provide lifecycle callbacks; [ACP](https://docs.x.ai/build/cli/headless-scripting#acp) provides JSON-RPC prompts and streamed session updates. | ACP controls its running endpoint. The cited plugin/hook pages describe discovery and the extensions modal but do not establish a general hot-install guarantee; verify the installed version before claiming live adoption. | Keep ACP for managed execution. Use scoped plugins/MCP and observational hooks for independent participants where enabled; do not infer inbound prompt injection from plugin availability. |

## Why hooks do not replace the inbound queue

Hooks execute at runtime-defined boundaries. An idle or disconnected process may
not reach the required boundary, and hook completion is not proof that a Pagnet
message was durably admitted to the intended native turn. A hook may notify a
bridge or consume queued context, but Pagnet still needs persisted delivery IDs,
authorization, ordering/backpressure, duplicate handling, admission ACKs and
recovery across process or connection loss.

Native queues can help implement the final handoff, but do not establish
end-to-end Pagnet delivery by themselves. OpenCode explicitly documents that
[prompt hooks are not an exactly-once side-effect boundary](https://opencode.ai/docs/build/plugins/server#prompt-admission).
Grok's [passive hooks ignore stdout](https://docs.x.ai/build/features/hooks#the-script-contract),
so their output is not a general inbound-message channel. Pagnet's
[durable delivery contract](DURABLE_DELIVERY.md) separately distinguishes
at-least-once events, admitted work, uncertain invocation outcomes and result
receipts. Preserve those distinctions: after ambiguous native submission,
reconcile or expose uncertainty instead of automatically executing it again.
