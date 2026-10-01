# Host-local runtime profiles

Profiles select a native executable, arguments and environment on one Pagnet host. They let accounts such as `claude-work` and `claude-shared` share the Claude adapter while keeping native state separate. Supported bases are Claude Code, Qwen Code, Codex and OpenCode on Linux and macOS.

```sh
pagnet runtime-profile add claude-work --runtime claude-code --env CLAUDE_CONFIG_DIR=~/.claude-work
pagnet runtime-profile add claude-shared --runtime claude-code --env CLAUDE_CONFIG_DIR=~/.claude-shared
pagnet runtime-profile list
```

Use your normal daemon reload procedure after configuration changes. Profiles are immutable for a running daemon. Once the target host reports the selected profile as available:

```sh
pagnet run --name reviewer --host YOUR_HOST --profile claude-work --workspace /absolute/project/path
```

Launch APIs accept `profile` alongside the canonical `runtime`. Only a runner reporting that exact profile can receive its launch. Default runtime availability cannot substitute a different account. Existing host launch permissions apply: use a personal host for personal provider accounts. Availability confirms executable discovery, not provider authentication or readiness.

## Private configuration

The default file is `~/.pagnet/runtime-profiles.json`; `--state-dir` selects another daemon state directory. It must be an owner-owned regular file with mode `0600` in a private directory. Symlinks are rejected. Windows private profiles are currently unsupported because their ACL privacy has not been verified; default runtimes remain available.

```json
{
  "version": 1,
  "profiles": [{
    "name": "claude-work",
    "runtime": "claude-code",
    "executable": "/absolute/path/to/claude",
    "args": [],
    "env": {"CLAUDE_CONFIG_DIR": "~/.claude-work"},
    "nativeDirs": []
  }]
}
```

Omit `executable` to resolve the native CLI from the daemon's PATH. Arguments are separate strings passed before managed-mode arguments. Pagnet does not evaluate shell aliases or commands. A wrapper must preserve the native CLI protocol, process ownership and local transport. Optional sandbox wrappers, including OpenShell configurations, must satisfy the same requirements; Pagnet does not install them or claim arbitrary executable compatibility.

Use `--env` only for non-secret values. Edit the private file for secrets without putting them in shell history or process arguments. The control plane receives only names, canonical runtime and availability, never environment values, arguments or executable paths. Home overrides, shell startup overrides, loader injection and `PAGNET_*` overrides are prohibited.

`CLAUDE_CONFIG_DIR` and `CODEX_HOME` select native sandbox directories automatically. `nativeDirs` can explicitly select absolute native directories for other compatible configurations. Profiles cannot grant access to daemon state. Only leading `~/` expands; shell substitutions and variable interpolation are not evaluated.

## Resume and activity

Each instance pins a digest of its private configuration. Changing it cannot silently resume with another executable or provider account: create a fresh instance after reloading. Stop an active instance before selecting another profile. Canonical runtime and native session identity remain intact.

For persistent Qwen and Codex sessions, positive structured native activity drives working status, including human terminal turns. Exact completion restores idle without inventing a Pagnet task transition. A live endpoint alone is not work. Claude and OpenCode direct human activity currently lacks the equivalent structured reporter; this feature does not claim universal scheduler detection.
