# Native checklist observations

Pagnet can show a runtime's structured checklist as read-only progress on the
exact task turn that produced it. These observations never claim a task or
change its durable status. No emitted checklist means **not reported**, rather
than empty or complete. The latest published snapshot remains **last observed**
after the turn ends or its execution binding changes.

- **Codex:** managed app-server `turn/plan/updated`, bound to its current native
  turn and thread.
- **Grok:** managed ACP v1 `session/update` plan, bound to the owned session and
  serialized prompt. Plan emission is optional; ACP v1 provides no native turn
  ID in this event.
- **Claude Code:** successful, paired `TaskList` results (`tasks`) or `TodoWrite`
  results (`newTodos`) provide full snapshots. Partial `TaskCreate` and
  `TaskUpdate` calls do not establish a complete list, especially after resume,
  and are not projected. Availability of native tools depends on the installed
  model/version and session configuration. Pagnet does not enable them globally.
- **OpenCode:** completed, owned-session `todowrite` tool parts provide full
  `state.metadata.todos` snapshots. Proposed inputs, running and failed tools
  do not count as checklist state.
- **Qwen:** currently not supported. Its installed dual-output protocol exposes
  tool-result text but drops the structured `resultDisplay.todo_list` field.
  Pagnet does not parse vendor prose or inspect global native todo history to
  pretend that a deterministic checklist was emitted.

All supported snapshots are bounded and encrypted locally before upload. The
server validates the current delivery command, runner connection, native
session, assignment, membership and encryption epoch. Offered-turn snapshots
stay invisible until the actual task claim; stale unpublished snapshots are
removed. Browser reads and key unwrap require current task-read permission.

Native contracts: [Codex app-server](https://learn.chatgpt.com/docs/app-server),
[ACP v1 plans](https://agentclientprotocol.com/protocol/v1/agent-plan),
[Claude todo tracking](https://code.claude.com/docs/en/agent-sdk/todo-tracking)
and [tool output types](https://code.claude.com/docs/en/agent-sdk/typescript#tool-output-types),
[OpenCode tool implementation](https://github.com/anomalyco/opencode/blob/dev/packages/opencode/src/tool/todo.ts).
