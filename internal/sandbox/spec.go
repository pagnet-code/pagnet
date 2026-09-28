// Package sandbox implements the per-instance filesystem sandbox (security
// wave S2) applied at the process-launch layer.
//
// A managed runtime is an LLM with shell access, spawned as a SAME-UID child
// of the daemon. Without isolation it can read the daemon's state dir
// (~/.pagnet: accounts/<name>/config.yaml host+client credentials,
// e2ee/host.json the host X25519 private key, e2ee/<net>/keyring.json network
// E2EE keys, daemon.sqlite) and every other instance's state. chmod and
// relocation are NOT a fix — same UID can read either.
//
// On Linux the sandbox is a real kernel boundary (Landlock) plus
// no_new_privs + a capability bounding-set drop, applied by a wrapper that
// EXECs the target IN PLACE (the child's PID stays the runtime's PID, so the
// supervisor's root-PID tracking and the S1 bridge process-tree binding keep
// working). It FAILS CLOSED on Linux when the sandbox cannot be applied. On
// platforms without Landlock (darwin) the launch is NOT sandboxed and the
// platform is reported as non-isolated (owner-scoped dev machines).
//
// The allowlist is per-instance and built by the daemon/driver layer from
// what it already knows (NewSpec). Coarse system read + tight per-instance
// write; the daemon's state dir is reached only via READ_DIR traversal on
// the bridge socket's path, so its secret FILE CONTENTS stay denied.
package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Subcommand is the hidden pagnet subcommand that runs the wrapper
// (`pagnet sandbox-exec ...`). It is intercepted in main BEFORE the CLI's
// command tree so the wrapper's pre-sandbox path stays minimal and it never
// touches the CLI's flag/credential plumbing. No new binary is built or
// distributed — it is a subcommand of the existing pagnet binary.
const Subcommand = "sandbox-exec"

// Spec is the per-instance filesystem allowlist. RW/RO are absolute
// directory subtrees; Sockets are absolute unix socket file paths.
// Execute is implied by both RW and RO (a runtime must be able to run its own
// binary and its dependencies inside the allowed subtrees).
type Spec struct {
	// RW: read-write subtrees — the instance's workspace, its pagnet
	// session/state dirs, its scratch, and the runtime's OWN native state
	// dir (which holds the runtime's LLM auth + sessions: legitimately the
	// runtime's own, allowed by the owner's allowlist).
	RW []string
	// RO: read-only subtrees — the coarse system paths a runtime needs to run
	// at all (SystemRO) plus its interpreter/module support paths
	// (RuntimeSupportRO) and any extras.
	RO []string
	// Sockets: unix socket paths the runtime must be able to reach (the
	// daemon bridge socket). The sandbox grants READ_DIR (traversal) on the
	// socket's parent + ancestors so any file access toward that path walks
	// a granted chain — no read/write on the surrounding dir contents.
	//
	// KNOWN KERNEL LIMITATION (documented, not a sandbox bug): on the
	// supported kernels (Landlock ABI v1–v4, Linux 5.13–6.8) unix-socket
	// CONNECT is NOT gateable by Landlock at all — there is no
	// connect-unix access bit before ABI v5 (Linux 6.10), and 6.8 registers
	// no path-lookup hook, so even the path walk of a connect is unchecked.
	// Connect reachability is therefore bounded by DAC (same-UID sockets
	// only), and authorization ON the daemon bridge is enforced by the S1
	// layer (SO_PEERCRED process-tree binding + per-activation nonce), not
	// by the sandbox. The Sockets field is the spec-level statement of that
	// intent; on a future ABI v5+ kernel the CONNECT_UNIX bit could gate it
	// precisely.
	Sockets []string
	// Dev: device subtrees granted read+write+truncate (DAC-gated) — /dev.
	// Runtimes and their shell commands must WRITE /dev/null (the universal
	// output sink: `> /dev/null`, `2>/dev/null` — bash opens it
	// O_WRONLY|O_CREAT|O_TRUNC, so the grant carries the TRUNCATE bit) and
	// READ /dev/urandom, /dev/zero, /dev/tty. A Landlock path_beneath rule
	// can only target a DIRECTORY, so a single device file cannot be
	// granted — the grant is necessarily on the /dev subtree. That is safe
	// because Landlock sits ON TOP of DAC: a device is writable only if the
	// user's DAC already allows writing it (a normal user: /dev/null and
	// their own ttys); privileged devices (/dev/mem, /dev/sda, /dev/kmsg,
	// ...) stay DAC-denied.
	Dev []string
}

// Normalize makes the spec canonical: absolute + cleaned + de-duplicated,
// empty entries dropped. It is deterministic and fails closed on a
// non-absolute path (the daemon/driver always pass absolute paths; a relative
// one is a caller bug we refuse, not silently resolve against an unknown CWD).
func (s *Spec) Normalize() error {
	norm := func(in []string, label string) ([]string, error) {
		seen := map[string]bool{}
		var out []string
		for _, p := range in {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !filepath.IsAbs(p) {
				return nil, fmt.Errorf("sandbox: %s path %q must be absolute", label, p)
			}
			p = filepath.Clean(p)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		return out, nil
	}
	rw, err := norm(s.RW, "rw")
	if err != nil {
		return err
	}
	ro, err := norm(s.RO, "ro")
	if err != nil {
		return err
	}
	sock, err := norm(s.Sockets, "socket")
	if err != nil {
		return err
	}
	dev, err := norm(s.Dev, "dev")
	if err != nil {
		return err
	}
	s.RW, s.RO, s.Sockets, s.Dev = rw, ro, sock, dev
	return nil
}

// WrapperArgs returns the argv (following the `sandbox-exec` token) that
// encodes spec and the target launch:
//
//	[--rw p]* [--ro p]* [--dev p]* [--sock p]* -- target arg1 arg2 ...
//
// target is the absolute target binary; targetArgs are the runtime's own
// arguments (NOT including the target itself). Paths are not secret — the
// allowlist is deliberately argv-testable (the owner's design). The target's
// ENVIRONMENT (which may carry provider auth) is passed via the child's env
// (the wrapper forwards os.Environ() across the exec), NEVER argv.
func WrapperArgs(spec *Spec, target string, targetArgs []string) []string {
	out := make([]string, 0, 16+len(targetArgs))
	for _, p := range spec.RW {
		out = append(out, "--rw", p)
	}
	for _, p := range spec.RO {
		out = append(out, "--ro", p)
	}
	for _, p := range spec.Dev {
		out = append(out, "--dev", p)
	}
	for _, p := range spec.Sockets {
		out = append(out, "--sock", p)
	}
	out = append(out, "--", target)
	out = append(out, targetArgs...)
	return out
}

// ParseWrapperArgs parses the argv following the `sandbox-exec` token (the
// shape WrapperArgs produces). It returns the spec, the target (absolute
// binary), and targetArgs (the runtime's own args, excluding the target).
func ParseWrapperArgs(argv []string) (Spec, string, []string, error) {
	var spec Spec
	dashdash := -1
	for i := 0; i < len(argv); {
		switch a := argv[i]; a {
		case "--rw", "--ro", "--dev", "--sock":
			if i+1 >= len(argv) {
				return Spec{}, "", nil, fmt.Errorf("sandbox-exec: %s requires a path", a)
			}
			p := argv[i+1]
			if strings.TrimSpace(p) == "" {
				return Spec{}, "", nil, fmt.Errorf("sandbox-exec: %s given an empty path", a)
			}
			switch a {
			case "--rw":
				spec.RW = append(spec.RW, p)
			case "--ro":
				spec.RO = append(spec.RO, p)
			case "--dev":
				spec.Dev = append(spec.Dev, p)
			case "--sock":
				spec.Sockets = append(spec.Sockets, p)
			}
			i += 2
		case "--":
			dashdash = i
			i = len(argv) // stop: the rest is target + args
		default:
			return Spec{}, "", nil, fmt.Errorf("sandbox-exec: unexpected argument %q before --", a)
		}
	}
	if dashdash < 0 {
		return Spec{}, "", nil, fmt.Errorf("sandbox-exec: missing -- separator (expected: -- target args...)")
	}
	rest := argv[dashdash+1:]
	if len(rest) == 0 || strings.TrimSpace(rest[0]) == "" {
		return Spec{}, "", nil, fmt.Errorf("sandbox-exec: missing target binary after --")
	}
	return spec, rest[0], rest[1:], nil
}

// Home returns the user's home directory ("" when it cannot be resolved).
func Home() string {
	h, _ := os.UserHomeDir()
	return h
}

// SystemRO returns the coarse read-only system subtrees a runtime needs to
// run at all (standard practice: coarse system read + tight per-instance
// write). Landlock sits ON TOP of DAC, so these grants only permit files the
// user already has permission to read — they never grant access to
// root-only files (/etc/shadow, /dev/mem, ...). None of these is the daemon's
// state dir or the user's home root.
//
// /proc/self (not /proc): the runtime may read its OWN /proc entries (needed
// by some runtimes) but not other processes' /proc/<pid> — so one same-UID
// runtime cannot read another's /proc/<pid>/environ (provider auth).
//
// /dev is NOT here: it is a Spec.Dev grant (read+write+truncate, DAC-gated)
// because runtimes and their shell commands must WRITE /dev/null — see
// SystemDev.
func SystemRO() []string {
	return []string{
		"/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc", "/opt",
		"/proc/self",
	}
}

// SystemDev returns the device subtrees every sandboxed launch gets
// read+write+truncate on (Spec.Dev). See the Spec.Dev doc for the rationale
// (Landlock cannot grant a single device file; the subtree grant is safe
// because Landlock sits on top of DAC, so only devices the user's DAC
// already allows writing — /dev/null, own ttys — are actually writable).
func SystemDev() []string {
	return []string{"/dev"}
}

// ResolvRO returns the EXTRA read-only subtree that holds the system
// resolver's config when it lives outside /etc: on systemd-resolved
// systems /etc/resolv.conf is a symlink into /run
// (/run/systemd/resolve/stub-resolv.conf). The /etc grant sees the LINK
// but Landlock resolves it — the target's directory must be granted or
// glibc cannot read the resolver config, DNS resolution fails, and every
// network call the runtime makes dies (observed: codex model requests
// fail with "workspace routing discovery failed"). A regular
// /etc/resolv.conf (non-systemd resolvers) is already covered by /etc:
// no extra grant. Best-effort: an unreadable /etc/resolv.conf yields no
// grant (the regular-file case is already covered; a machine whose
// resolver config is unreadable by the user cannot do DNS at all).
// Safe: the grant sits ON TOP of DAC — the resolved target dir
// (/run/systemd/resolve) holds the world-readable stub config plus
// root-only state (private/) the user's DAC never reaches.
func ResolvRO() []string {
	target, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	if strings.HasPrefix(target, "/etc/") {
		return nil // the /etc grant already covers the resolved target
	}
	dir := filepath.Dir(target)
	if dir == "" || dir == "/" {
		return nil // never grant the filesystem root
	}
	return []string{dir}
}

// RuntimeSupportRO returns the read-only subtrees that hold a runtime CLI and
// its dependencies (the node interpreter, global node_modules, home-local
// installs) so a node-based runtime can be EXECUTED. `binary` is the resolved
// runtime binary path; `home` is the user's home. It never returns the
// filesystem root or a path that would expose the daemon's state dir.
//
// Node-based CLIs (qwen, claude, opencode) are JS entrypoints with a
// `#!/usr/bin/env node` shebang: executing them requires reading the
// interpreter, the entry script, and their module tree. The binary's dir +
// immediate parent cover a typical `.../bin/<cli>` layout and the sibling
// module tree; the explicit list covers the standard global-install
// locations (system and home-local, incl. nvm/volta/deno/bun).
func RuntimeSupportRO(binary, home string) []string {
	var out []string
	if binary != "" {
		dir := filepath.Dir(binary)
		for _, p := range []string{dir, filepath.Dir(dir)} {
			if p == "" || p == "/" {
				continue // never grant the filesystem root
			}
			out = append(out, p)
		}
	}
	out = append(out,
		"/usr/lib/node_modules",
		"/usr/local/lib/node_modules",
		"/opt/homebrew/lib/node_modules",
		"/opt/homebrew/bin",
	)
	if home != "" {
		out = append(out,
			filepath.Join(home, ".local"),
			filepath.Join(home, ".npm-global"),
			filepath.Join(home, ".nvm"),
			filepath.Join(home, ".volta"),
			filepath.Join(home, ".deno"),
			filepath.Join(home, ".bun"),
		)
	}
	return out
}

// mcpBridgeTargets parses a rendered PAGNET_MCP_CONFIG once and returns the
// two daemon-bridge targets a sandboxed runtime must be able to reach:
// the bridge socket path (the `--socket` argument of the bridge command)
// and the directory containing the bridge worker binary (the `command`
// the runtime EXECs as its MCP server). The daemon renders both together
// (`<selfExe> mcp worker|control --socket <StateDir>/pagnetd.sock`); the
// runtime inherits the config, not the paths as dedicated env, so the
// driver recovers them here for the allowlist. Each is "" when absent,
// invalid, or not derivable.
func mcpBridgeTargets(mcpJSON string) (socket, bridgeDir string) {
	if strings.TrimSpace(mcpJSON) == "" {
		return "", ""
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(mcpJSON), &cfg); err != nil {
		return "", ""
	}
	for _, srv := range cfg.MCPServers {
		if bridgeDir == "" && srv.Command != "" {
			dir := filepath.Dir(srv.Command)
			if dir != "" && dir != "." && dir != "/" {
				bridgeDir = dir
			}
		}
		for i, a := range srv.Args {
			if a == "--socket" && i+1 < len(srv.Args) {
				socket = srv.Args[i+1]
			}
		}
	}
	return socket, bridgeDir
}

// SocketFromMCPConfig extracts the daemon bridge socket path from a rendered
// PAGNET_MCP_CONFIG JSON (the `--socket` argument of the bridge command). ""
// when absent or invalid. The daemon renders the socket as
// `<StateDir>/pagnetd.sock`; the runtime inherits the config (not the socket
// path as a dedicated env), so the driver recovers it here for the allowlist.
func SocketFromMCPConfig(mcpJSON string) string {
	socket, _ := mcpBridgeTargets(mcpJSON)
	return socket
}

// BridgeDirFromMCPConfig returns the directory containing the daemon bridge
// worker binary that the runtime EXECs as its MCP server (the `command` of
// the rendered PAGNET_MCP_CONFIG). The sandbox must grant it read+execute:
// a sandboxed runtime that cannot exec its MCP server loses its network
// tools silently (the daemon always renders an absolute selfExe). "" when
// absent, invalid, or a relative command — a relative command yields no
// derivable grant, and the runtime's MCP spawn then fails visibly rather
// than the allowlist guessing.
func BridgeDirFromMCPConfig(mcpJSON string) string {
	_, bridgeDir := mcpBridgeTargets(mcpJSON)
	return bridgeDir
}

// Options describes the per-instance inputs a driver knows when building a
// sandbox spec (H4: built by the daemon/driver layer from what it already
// knows).
type Options struct {
	// Workspace: the instance's working dir (RW).
	Workspace string
	// StateDirs: the instance's pagnet session/state dirs (RW).
	StateDirs []string
	// Scratch: per-instance scratch dirs (RW).
	Scratch []string
	// NativeDirs: the runtime's OWN native state dirs (RW) — e.g. qwen
	// ~/.qwen, claude ~/.claude, codex ~/.codex, opencode ~/.config/opencode.
	// These hold the runtime's LLM auth + sessions (legitimately the
	// runtime's own, allowed by the owner's allowlist).
	NativeDirs []string
	// Binary: the resolved runtime CLI binary (RO support paths derived).
	Binary string
	// Home: the user's home ("" = os.UserHomeDir()).
	Home string
	// Socket: the daemon bridge socket (CONNECT_UNIX).
	Socket string
	// BridgeDir: the directory containing the daemon bridge worker binary
	// (the pagnet MCP server the runtime spawns as its child). RO grant
	// (read+execute) — the sandboxed runtime must be able to EXEC its MCP
	// server; the ancestors get READ_DIR traversal from the rule
	// expansion, so the one directory grant is sufficient.
	BridgeDir string
	// ExtraRO / ExtraRW: driver-specific additions.
	ExtraRO []string
	ExtraRW []string
}

// NewSpec assembles the per-instance allowlist from Options (H4). It is the
// single spec-construction point: coarse system read (SystemRO +
// RuntimeSupportRO + the resolver-config target, ResolvRO) + the device
// grant (SystemDev) + the bridge worker's binary dir (the runtime must EXEC
// its MCP server) + tight per-instance write (workspace/state/scratch/native)
// + the bridge socket. The daemon's
// state dir is NEVER placed in RW or RO — it is reached only through READ_DIR
// traversal on the socket's path, so the secret FILE CONTENTS (accounts/,
// e2ee/, daemon.sqlite) stay denied (Landlock grants READ_DIR on the state
// dir for traversal but never READ_FILE, so only entry NAMES are visible,
// not contents).
func NewSpec(o Options) *Spec {
	if o.Home == "" {
		o.Home = Home()
	}
	s := &Spec{}
	if o.Workspace != "" {
		s.RW = append(s.RW, o.Workspace)
	}
	s.RW = append(s.RW, o.StateDirs...)
	s.RW = append(s.RW, o.Scratch...)
	s.RW = append(s.RW, o.NativeDirs...)
	s.RW = append(s.RW, o.ExtraRW...)
	s.RO = append(s.RO, SystemRO()...)
	s.RO = append(s.RO, ResolvRO()...)
	s.RO = append(s.RO, RuntimeSupportRO(o.Binary, o.Home)...)
	if o.BridgeDir != "" {
		s.RO = append(s.RO, o.BridgeDir)
	}
	s.RO = append(s.RO, o.ExtraRO...)
	s.Dev = append(s.Dev, SystemDev()...)
	if o.Socket != "" {
		s.Sockets = append(s.Sockets, o.Socket)
	}
	return s
}
