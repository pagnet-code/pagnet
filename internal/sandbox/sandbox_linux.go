//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MustSandbox reports whether a sandbox spec MUST be applied for a launch to
// proceed on this platform. Linux: true (the launch FAILS CLOSED without it,
// H3 — there is no fallback to an unsandboxed launch).
func MustSandbox() bool { return true }

// Available reports whether the filesystem sandbox can be applied right now
// (Landlock ABI3 or newer, including truncation protection). Callers check
// MustSandbox() first: on
// non-Linux, Available() is false by design ("non-isolated", H5), while here
// false is a FAILURE that must stop the launch.
func Available() bool { return requireKernelABI(getABI()) == nil }

// requireKernelABI enforces the filesystem-content protection minimum:
// older ABIs cannot prevent truncating protected files.
func requireKernelABI(a landlockABI) error {
	if a.version < 3 {
		return fmt.Errorf("unsupported Linux sandbox: Landlock ABI3 or newer is required for truncation protection (detected ABI%d, kernel %s; Linux 6.2+ with Landlock enabled)", a.version, kernelRelease())
	}
	return nil
}

// LandlockAvailable probes whether the running kernel supports Landlock by
// issuing a side-effect-free ABI version query. A kernel without Landlock
// (ENOSYS), Landlock disabled at boot (EOPNOTSUPP), a seccomp filter that
// blocks the syscall, or any other error all report false.
func LandlockAvailable() bool { return getABI().version > 0 }

// ---------------------------------------------------------------------------
// Kernel ABI detection
//
// landlock_create_ruleset has used (attr, size, flags) since Linux 5.13
// (ABI v1). The version query is (NULL, 0, VERSION). The supplied size
// provides forwards/backwards-compatible struct extension.
//
// x/sys v0.47.0 provides the Landlock types/constants/sysnums but NO
// wrapper functions, so the syscalls are issued with unix.Syscall/Syscall6.

// landlockABI describes the Landlock interface of the running kernel.
type landlockABI struct {
	version int    // ABI version reported by the version query (0 = none)
	fsMask  uint64 // the kernel's filesystem access mask for this ABI
}

var (
	abiOnce sync.Once
	abi     landlockABI
)

// getABI returns the cached ABI probe result.
func getABI() landlockABI {
	abiOnce.Do(func() { abi = probeABI() })
	return abi
}

// probeABI queries the running kernel for its Landlock ABI (no side effects).
func probeABI() landlockABI {
	if v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0,
		unix.LANDLOCK_CREATE_RULESET_VERSION); errno == 0 && v > 0 {
		return landlockABI{version: int(v), fsMask: landlockFSMask(int(v))}
	}
	return landlockABI{}
}

// landlockFSMask returns the supported filesystem subset used by this policy.
// ABI v1 already includes all execute/read/write/remove/make bits (0x1FFF).
// ABI v2 adds REFER; ABI v3 adds TRUNCATE. Later filesystem rights are not
// claimed as handled until the policy implements their grants.
func landlockFSMask(v int) uint64 {
	switch {
	case v < 1:
		return 0
	case v == 1:
		return 0x1FFF
	case v == 2:
		return 0x3FFF
	default:
		return 0x7FFF
	}
}

// Landlock access bits (the filesystem subset this sandbox uses). Cast to
// uint64 at use (the x/sys constants are C ints).
const (
	bReadFile   = unix.LANDLOCK_ACCESS_FS_READ_FILE
	bReadDir    = unix.LANDLOCK_ACCESS_FS_READ_DIR
	bWriteFile  = unix.LANDLOCK_ACCESS_FS_WRITE_FILE
	bExecute    = unix.LANDLOCK_ACCESS_FS_EXECUTE
	bTruncate   = unix.LANDLOCK_ACCESS_FS_TRUNCATE
	bRemoveDir  = unix.LANDLOCK_ACCESS_FS_REMOVE_DIR
	bRemoveFile = unix.LANDLOCK_ACCESS_FS_REMOVE_FILE
	bMakeChar   = unix.LANDLOCK_ACCESS_FS_MAKE_CHAR
	bMakeDir    = unix.LANDLOCK_ACCESS_FS_MAKE_DIR
	bMakeReg    = unix.LANDLOCK_ACCESS_FS_MAKE_REG
	bMakeSock   = unix.LANDLOCK_ACCESS_FS_MAKE_SOCK
	bMakeFIFO   = unix.LANDLOCK_ACCESS_FS_MAKE_FIFO
	bMakeBlock  = unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK
	bMakeSym    = unix.LANDLOCK_ACCESS_FS_MAKE_SYM
)

// Access sets (uint64).
var (
	// rwAccess: full write access for per-instance RW subtrees (workspace,
	// state, scratch, the runtime's native state): read, modify, execute,
	// the remove bits (delete), TRUNCATE, and the seven MAKE_* bits
	// (creation: open(O_CREAT), mkdir, symlink, mknod, mkfifo, mksocket,
	// mkblock). The MAKE bits are what gate node/pipe/socket/symlink
	// CREATION: Landlock gates an access only when its bit is in the
	// ruleset's handled set, so without them a sandboxed process could
	// mkdir/symlink/mknod ANYWHERE DAC allows (plant ~/.ssh/authorized_keys,
	// plant entries at daemon-state locations). With them granted on the
	// RW subtrees, creation inside them is unchanged (it succeeded while
	// unhandled too — it is now an explicit grant) and creation OUTSIDE
	// them is denied (EACCES), including on ABI v1 kernels (5.13–5.18),
	// which already support every REMOVE/MAKE right used here.
	// Making a file executable (chmod +x) is not gated by a Landlock bit,
	// so no extra bit is needed for it.
	rwAccess = uint64(bReadFile | bReadDir | bWriteFile | bExecute | bTruncate |
		bRemoveDir | bRemoveFile |
		bMakeChar | bMakeDir | bMakeReg | bMakeSock | bMakeFIFO | bMakeBlock | bMakeSym)
	// roAccess: read + execute, for system / runtime-support subtrees.
	roAccess = uint64(bReadFile | bReadDir | bExecute)
	// devAccess: the device subtree (Spec.Dev, /dev): read + write +
	// read-dir + execute + truncate. Write + truncate are what `> /dev/null`
	// needs (bash opens O_WRONLY|O_CREAT|O_TRUNC); read covers /dev/urandom,
	// /dev/zero, /dev/tty, /dev/null. No remove bits — creating or removing
	// device nodes is DAC-gated anyway (/dev is root-owned; a normal user
	// cannot write the directory). Device access also depends on the user's
	// existing OS permissions, including supplementary groups. This policy
	// does not restrict device IOCTLs or grant only selected device nodes.
	// See the Spec.Dev doc.
	devAccess = uint64(bReadFile | bReadDir | bWriteFile | bExecute | bTruncate)
	// directoryNamesAccess grants directory entry names, never file contents.
	// The policy grants it only on explicitly listed socket parents.
	directoryNamesAccess = uint64(bReadDir)
)

// Apply installs the sandbox on the CURRENT process (the wrapper, immediately
// before it execs the target): no_new_privs (fail closed on error), a
// best-effort capability bounding-set drop, then the Landlock ruleset
// (fail closed on any failure). Landlock rules persist across exec and are
// inherited by children, so the exec'd target — and its whole tree (shells,
// the MCP bridge the runtime spawns) — runs sandboxed.
//
// After validation, Apply permanently pins the calling goroutine to its
// current OS thread, including on partial failure. The caller must exec or
// return from that goroutine; it must never call runtime.UnlockOSThread or
// continue unrelated work on this irreversibly restricted thread.
func Apply(spec *Spec) error {
	if err := spec.Normalize(); err != nil {
		return err
	}
	if err := requireKernelABI(getABI()); err != nil {
		return err
	}
	// no_new_privs, capability bounds and Landlock are per-thread. Keep
	// this goroutine on the same thread through all restrictions and the
	// caller's subsequent exec. Never unlock: even partial failure may
	// leave irreversible restrictions, and that thread must not rejoin
	// Go's pool. A returning goroutine retires its locked OS thread.
	runtime.LockOSThread()
	// 1. no_new_privs — the privilege boundary: the process (and its
	// descendants) can never gain new privileges via exec (setuid/setgid
	// binaries, file capabilities). MUST succeed — fail closed.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w (kernel %s)", errno, kernelRelease())
	}
	// 2. Capability bounding-set drop (best-effort, defense-in-depth): a
	// normal user holds no capabilities, but a daemon run setuid-root or via
	// a file-capability binary would. Dropping the bounding set means even a
	// capability-holding binary exec'd later starts with none. Individual
	// drops of absent capabilities fail (EINVAL/ENOSPC) — expected, ignored.
	// The no_new_privs set above is the real boundary; this shrinks the set
	// further.
	dropCapabilitiesBestEffort()
	// 3. Landlock — the filesystem boundary. MUST succeed — fail closed
	// (H3): the child never runs without the full policy applied.
	if err := applyLandlockFunc(spec); err != nil {
		return err
	}
	return nil
}

// applyLandlockFunc is the Landlock step of Apply. It is a variable (not an
// inline call) so tests can force its failure and verify the fail-closed
// contract end to end (refused launch, non-zero exit, child never runs).
var applyLandlockFunc = applyLandlock

// dropCapabilitiesBestEffort drops every capability (0..capLastCap) from the
// bounding set via prctl(PR_CAPBSET_DROP). Best-effort by design: a
// capability not present fails and is ignored.
func dropCapabilitiesBestEffort() {
	const capLastCap = 41 // CAP_CHECKPOINT_RESTORE (last defined capability)
	for cap := 0; cap <= capLastCap; cap++ {
		_, _, _ = unix.Syscall6(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0, 0)
	}
}

func applyLandlock(spec *Spec) error {
	a := getABI()
	if err := requireKernelABI(a); err != nil {
		return err
	}
	rules, accessFs, mandatory, err := computeRules(spec, a)
	if err != nil {
		return err
	}
	var attr unix.LandlockRulesetAttr
	attr.Access_fs = accessFs
	// Only handled_access_fs is configured; the kernel zero-fills newer
	// fields. Eight bytes is the original supported ABI v1 struct size.
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), 8, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w (kernel %s, ABI v%d)", errno, kernelRelease(), a.version)
	}
	rulesetFd := int(fd)
	defer unix.Close(rulesetFd)

	for path, access := range rules {
		if _, isMandatory := mandatory[path]; !isMandatory {
			// A best-effort support path (coarse system read /
			// interpreter + module locations) that is ABSENT on this
			// machine: the grant would be a no-op, so it is skipped
			// deterministically — granting a missing path can never
			// BROADEN access, and refusing the whole launch over a
			// cosmetic gap (e.g. a machine without ~/.nvm) would make
			// the sandbox unusable where it is most needed. Mandatory
			// paths (RW grants — the daemon guarantees them — and
			// anything beneath them) are never skipped: a missing one
			// is a deterministic launch failure below (H3).
			if _, err := os.Stat(path); err != nil {
				continue
			}
		}
		if err := addPathRule(rulesetFd, path, access); err != nil {
			return err
		}
	}
	// RestrictSelf applies the ruleset to THIS process (and, across the
	// upcoming exec, to the target and its whole tree). MUST succeed — fail
	// closed (H3). It requires no_new_privs (or CAP_SYS_ADMIN), which Apply
	// set in step 1.
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFd), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w (kernel %s)", errno, kernelRelease())
	}
	return nil
}

// computeRules expands the semantic spec into (a) a map of subtree path →
// access bits, (b) the ruleset's handled_access_fs (the union of every bit
// any rule grants — a Landlock ABI requirement), and (c) the MANDATORY
// set: the rule paths whose existence is a launch precondition (the RW
// grants — the daemon guarantees them; a missing one refuses the launch)
// as opposed to the best-effort coarse RO support paths (a missing one is
// a deterministic no-op skip — see applyLandlock). For each granted
// subtree (RW/RO/Dev) it records the grant on the subtree root; for each
// socket it records READ_DIR (directory listing) on its parent subtree.
//
// Only explicit subtree roots receive grants; path traversal needs no
// ancestor READ_DIR grant. READ_DIR permits opening/listing directories.
// stat/lstat metadata is not restricted by Landlock on any ABI.
// Grants are intersected with the rights supported by the detected ABI;
// Apply rejects ABI1/2 because they cannot restrict truncation.
//
// Pathname Unix socket connections are not currently handled by this policy.
// Linux added LANDLOCK_ACCESS_FS_RESOLVE_UNIX in ABI v9, not ABI v5 (which
// added IOCTL_DEV). ABI v6 separately scopes abstract Unix sockets/signals.
// Until explicit socket rules and scoped attributes are installed, connects
// remain possible wherever DAC permits; bridge/control authentication must
// enforce authority independently of filesystem containment.
func computeRules(spec *Spec, abi landlockABI) (map[string]uint64, uint64, map[string]bool, error) {
	rules := map[string]uint64{}
	var accessFs uint64
	// mandatory: the rule paths whose EXISTENCE is a launch precondition
	// (H3): the RW grants — the daemon (the driver's launch path) creates
	// every directory it puts in RW before the launch, so a missing one
	// is a deterministic failure, never a skip. The coarse RO support
	// paths are best-effort (a missing one is a no-op grant, skipped).
	mandatory := map[string]bool{}
	abiMask := abi.fsMask
	add := func(p string, selfAccess uint64, isMandatory bool) error {
		p = filepath.Clean(p)
		if p == "" {
			return fmt.Errorf("empty allowlist path")
		}
		grant := selfAccess & abiMask
		if grant == 0 {
			return fmt.Errorf("sandbox: no access bit for %s is supported by this kernel's Landlock ABI — refusing a partially-restrictive policy", p)
		}
		rules[p] |= grant
		if isMandatory {
			mandatory[p] = true
		}
		accessFs |= grant
		return nil
	}
	for _, p := range spec.RW {
		if err := add(p, rwAccess, true); err != nil {
			return nil, 0, nil, err
		}
	}
	for _, p := range spec.RO {
		if err := add(p, roAccess, false); err != nil {
			return nil, 0, nil, err
		}
	}
	// Device subtrees: best-effort like RO (on Linux /dev always exists;
	// the skip is there for symmetry with the other coarse support paths).
	for _, p := range spec.Dev {
		if err := add(p, devAccess, false); err != nil {
			return nil, 0, nil, err
		}
	}
	for _, s := range spec.Sockets {
		parent := filepath.Dir(s)
		if parent == s {
			return nil, 0, nil, fmt.Errorf("socket path %q has no parent directory", s)
		}
		// Permit listing the explicit socket parent, never reading its files.
		// This is not a connection gate; see the function doc for IPC limits.
		if err := add(parent, directoryNamesAccess, false); err != nil {
			return nil, 0, nil, err
		}
	}
	return rules, accessFs, mandatory, nil
}

// addPathRule adds one path_beneath rule granting access to the subtree
// rooted at path. Read-only regular files receive only file-compatible
// read/execute bits; writable and device grants remain directory-only. A missing path is a deterministic LAUNCH FAILURE (H3): the
// daemon created the paths it believes exist, so a missing one is never
// silently skipped.
func addPathRule(rulesetFd int, path string, access uint64) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("allowlist path %s: %w (refusing to launch — the path the daemon expects is missing)", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("allowlist path %s: %w", path, err)
	}
	if !st.IsDir() {
		if !st.Mode().IsRegular() || access & ^roAccess != 0 {
			return fmt.Errorf("allowlist path %s is not a directory or an exact read-only regular file", path)
		}
		access &= bReadFile | bExecute
	}
	var rule unix.LandlockPathBeneathAttr
	rule.Allowed_access = access
	rule.Parent_fd = int32(f.Fd())
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFd), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&rule)), 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock_add_rule %s: %w", path, errno)
	}
	return nil
}

// RunWrapper is the wrapper's entrypoint (`pagnet sandbox-exec ...`). It
// parses the allowlist from argv, applies the sandbox to this process (fail
// closed), and EXECs the target IN PLACE (H1: the child's PID stays the
// runtime's PID — the supervisor's root-PID tracking, S1's process-tree
// binding, and Pdeathsig all keep working). It returns only on failure.
func RunWrapper(argv []string) error {
	spec, target, targetArgs, err := ParseWrapperArgs(argv)
	if err != nil {
		return err
	}
	// H3: a missing EXEC target is a deterministic launch failure, checked
	// BEFORE the sandbox is applied (the refusal names the binary; the
	// launch is never partially prepared).
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("refusing to launch: the runtime binary the daemon expects is missing — %s: %v (fail closed)", target, err)
	}
	if err := Apply(&spec); err != nil {
		// H3: fail closed with an explicit security error; the child never
		// runs without the full policy.
		return fmt.Errorf("refusing to launch: sandbox could not be applied — %v (fail closed)", err)
	}
	// In-place exec. The env is the child's env (set by the supervisor on the
	// wrapper) forwarded unchanged — it carries the runtime's provider auth
	// and is never placed on argv.
	argv0 := append([]string{target}, targetArgs...)
	if err := syscall.Exec(target, argv0, os.Environ()); err != nil {
		return fmt.Errorf("refusing to launch: exec %s after sandbox applied: %v (fail closed)", target, err)
	}
	return nil // unreachable on a successful exec
}

// RunWrapperMain runs the wrapper and returns the process exit code (for
// cmd/pagnet's main). On success it never returns (exec replaces the
// process); a non-zero return means the launch was refused.
func RunWrapperMain(argv []string) int {
	if err := RunWrapper(argv); err != nil {
		fmt.Fprintln(os.Stderr, "pagnet sandbox-exec:", err)
		return 1
	}
	return 0
}

// KernelRelease returns the running kernel release (for diagnostics and
// heartbeats), "" when it cannot be read.
func KernelRelease() string {
	return kernelRelease()
}

// kernelRelease returns the running kernel release (for diagnostics in the
// fail-closed error), "" when it cannot be read.
func kernelRelease() string {
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return ""
	}
	n := 0
	for n < len(u.Release) && u.Release[n] != 0 {
		n++
	}
	return string(u.Release[:n])
}
