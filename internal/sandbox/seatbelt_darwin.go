//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// DarwinPolicy is a Seatbelt profile and its sandbox-exec -D
// parameters. Paths are parameters, never Scheme source: quotes, backslashes,
// whitespace and Unicode in a filename cannot inject profile expressions.
// Neither generation nor wrapping reads credentials or the environment.
type DarwinPolicy struct {
	Profile    string
	Parameters []string
}

// GenerateDarwinPolicy builds a default-deny filesystem policy without applying
// it. Only the explicit Darwin wrapper applies it; supervisor launches remain
// unchanged until production runtime probes pass.
// RW directories get read/write/execute; RO directories or regular files get
// read/execute; Dev directories get read, data-write and execute, without node
// creation/removal. Ordinary outbound IP networking and process creation are
// allowed; Unix connections are limited to the exact listed sockets. No Mach,
// inbound network or general IPC permissions are implied. Read-only sysctls
// cover Go page-size initialization and the exact OS-information names denied
// during the isolated Qwen Node startup probe. The sole
// implicit filesystem data grant is read-data on the literal root directory: dyld
// needs to open it during bootstrap. This exposes root entry names, never
// contents of files or subdirectories outside the explicit grants. Exact
// path and ancestor metadata is allowed for grant traversal, including symlink
// aliases (macOS checks /etc itself before resolving /etc/resolv.conf).
//
// Like Linux, absent optional RO/Dev support paths are skipped; RW directories
// and socket endpoints must exist. All existing paths are resolved before
// containment checks, including Denied (whose missing suffix is resolved through
// its closest existing ancestor). Filesystem mutation during preparation is not
// synchronized: callers must control the grant roots and their ancestors.
func GenerateDarwinPolicy(spec *Spec) (DarwinPolicy, error) {
	if spec == nil {
		return DarwinPolicy{}, fmt.Errorf("sandbox: nil spec")
	}
	// Work on a copy; Normalize replaces slices rather than editing their entries.
	s := *spec
	for _, paths := range [][]string{s.RW, s.RO, s.Dev, s.Sockets, s.Denied} {
		for _, p := range paths {
			if strings.IndexByte(p, 0) >= 0 || strings.TrimSpace(p) != p {
				return DarwinPolicy{}, fmt.Errorf("sandbox: invalid path %q", p)
			}
		}
	}
	if err := s.Normalize(); err != nil {
		return DarwinPolicy{}, err
	}
	var denied []string
	for _, p := range s.Denied {
		resolved, err := darwinCanonicalPath(p)
		if err != nil {
			return DarwinPolicy{}, err
		}
		denied = append(denied, resolved)
	}
	policy := DarwinPolicy{Profile: `(version 1)
(deny default)
(allow file-read-data (literal "/"))
(allow process-fork)
(allow sysctl-read (sysctl-name "hw.pagesize") (sysctl-name "hw.pagesize_compat"))
; Node's os initialization queries these exact read-only OS properties.
(allow sysctl-read
  (sysctl-name "hw.memsize")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.version")
  (sysctl-name "hw.machine"))
(allow network-outbound (remote ip "*:*"))
`}
	add := func(operations, filter, p string) {
		key := "PATH_" + strconv.Itoa(len(policy.Parameters))
		policy.Parameters = append(policy.Parameters, key+"="+p)
		policy.Profile += fmt.Sprintf("(allow %s (%s (param %q)))\n", operations, filter, key)
	}
	metadata := map[string]bool{}
	addTraversalMetadata := func(p string) {
		for ; ; p = filepath.Dir(p) {
			if !metadata[p] {
				add("file-read-metadata", "literal", p)
				metadata[p] = true
			}
			if p == filepath.Dir(p) {
				break
			}
		}
	}
	for _, group := range []struct {
		paths      []string
		label      string
		operations string
		mandatory  bool
	}{{s.RW, "RW", "file-read* file-write* file-link process-exec", true},
		{s.RO, "RO", "file-read* process-exec", false},
		{s.Dev, "Dev", "file-read* file-write-data process-exec", false}} {
		for _, p := range group.paths {
			st, err := os.Stat(p)
			if err != nil {
				if !group.mandatory {
					continue // Same best-effort support-path rule as Linux.
				}
				return DarwinPolicy{}, fmt.Errorf("sandbox: mandatory %s path %q: %w", group.label, p, err)
			}
			if !st.IsDir() && (group.label != "RO" || !st.Mode().IsRegular()) {
				return DarwinPolicy{}, fmt.Errorf("sandbox: %s path %q has unsupported file type", group.label, p)
			}
			resolved, err := filepath.EvalSymlinks(p)
			if err != nil {
				return DarwinPolicy{}, fmt.Errorf("sandbox: canonical path %q: %w", p, err)
			}
			// Check lexical and canonical forms, including '/' (Normalize's
			// existing lexical check does not cover that ancestor).
			for _, dn := range append(append([]string{}, s.Denied...), denied...) {
				if darwinPathWithin(dn, p) || darwinPathWithin(dn, resolved) {
					return DarwinPolicy{}, fmt.Errorf("sandbox: denied path %q is equal to or beneath %s grant %q", dn, group.label, p)
				}
			}
			filter := "subpath"
			if !st.IsDir() {
				filter = "literal"
			}
			add(group.operations, filter, resolved)
			addTraversalMetadata(p)
			addTraversalMetadata(resolved)
		}
	}
	if len(s.Sockets) != 0 {
		policy.Profile += "(allow system-socket (socket-domain AF_UNIX))\n"
	}
	for _, p := range s.Sockets {
		st, err := os.Stat(p)
		if err != nil {
			return DarwinPolicy{}, fmt.Errorf("sandbox: mandatory socket %q: %w", p, err)
		}
		if st.Mode()&os.ModeSocket == 0 {
			return DarwinPolicy{}, fmt.Errorf("sandbox: socket path %q is not a Unix socket", p)
		}
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return DarwinPolicy{}, fmt.Errorf("sandbox: canonical socket %q: %w", p, err)
		}
		addTraversalMetadata(p)
		addTraversalMetadata(resolved)
		key := "PATH_" + strconv.Itoa(len(policy.Parameters))
		policy.Parameters = append(policy.Parameters, key+"="+resolved)
		policy.Profile += fmt.Sprintf("(allow network-outbound (remote unix-socket (literal (param %q))))\n", key)
	}
	return policy, nil
}

func darwinPathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func darwinCanonicalPath(p string) (string, error) {
	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) || p == filepath.Dir(p) {
		return "", fmt.Errorf("sandbox: canonical path %q: %w", p, err)
	}
	// EvalSymlinks cannot resolve a dangling link, but its target still
	// determines containment if a granted process creates it later.
	if st, statErr := os.Lstat(p); statErr == nil && st.Mode()&os.ModeSymlink != 0 {
		target, readErr := os.Readlink(p)
		if readErr != nil {
			return "", fmt.Errorf("sandbox: read symlink %q: %w", p, readErr)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(p), target)
		}
		return darwinCanonicalPath(target)
	}
	parent, err := darwinCanonicalPath(filepath.Dir(p))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(p)), nil
}

// DarwinWrapperArgs prepares arguments for the fixed /usr/bin/sandbox-exec
// executable. It never invokes a shell and does not put environment credentials
// on argv. Target arguments are forwarded verbatim, just like WrapperArgs.
func DarwinWrapperArgs(spec *Spec, target string, targetArgs []string) ([]string, error) {
	if !filepath.IsAbs(target) || strings.IndexByte(target, 0) >= 0 {
		return nil, fmt.Errorf("sandbox: target must be an absolute path")
	}
	st, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("sandbox: target %q: %w", target, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("sandbox: target %q is not a regular file", target)
	}
	policy, err := GenerateDarwinPolicy(spec)
	if err != nil {
		return nil, err
	}
	args := []string{"-p", policy.Profile}
	for _, param := range policy.Parameters {
		args = append(args, "-D", param)
	}
	args = append(args, "--", target)
	return append(args, targetArgs...), nil
}

// RunDarwinWrapper implements the explicit Darwin wrapper. It
// replaces the current process with sandbox-exec, which applies the policy
// before executing the target; failure never falls back to an unsandboxed exec.
// The supervisor does not yet invoke this wrapper on Darwin.
func RunDarwinWrapper(argv []string) error {
	spec, target, targetArgs, err := ParseWrapperArgs(argv)
	if err != nil {
		return err
	}
	args, err := DarwinWrapperArgs(&spec, target, targetArgs)
	if err != nil {
		return err
	}
	return syscall.Exec("/usr/bin/sandbox-exec", append([]string{"/usr/bin/sandbox-exec"}, args...), os.Environ())
}
