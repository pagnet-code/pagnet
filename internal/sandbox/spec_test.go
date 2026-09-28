package sandbox

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNormalize_AbsoluteCleanDedup(t *testing.T) {
	s := &Spec{
		RW:      []string{"/a/b/", "//a/b", "/a/b/c", ""},
		RO:      []string{"/x/y", "/x/y", "/"},
		Sockets: []string{"/s/pagnetd.sock"},
	}
	if err := s.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !reflect.DeepEqual(s.RW, []string{"/a/b", "/a/b/c"}) {
		t.Errorf("RW = %v, want [/a/b /a/b/c]", s.RW)
	}
	if !reflect.DeepEqual(s.RO, []string{"/x/y", "/"}) {
		t.Errorf("RO = %v, want [/x/y /]", s.RO)
	}
	if !reflect.DeepEqual(s.Sockets, []string{"/s/pagnetd.sock"}) {
		t.Errorf("Sockets = %v", s.Sockets)
	}
}

func TestNormalize_FailsClosedOnRelative(t *testing.T) {
	for name, s := range map[string]*Spec{
		"rw":    {RW: []string{"relative/path"}},
		"ro":    {RO: []string{"~/.pagnet"}},
		"sock":  {Sockets: []string{"s/pagnetd.sock"}},
		"clean": {RW: []string{"/ok"}, RO: []string{"./bad"}},
	} {
		if err := s.Normalize(); err == nil {
			t.Errorf("%s: Normalize accepted a relative path — must fail closed", name)
		}
	}
}

func TestWrapperArgs_ParseRoundTrip(t *testing.T) {
	spec := &Spec{
		RW:      []string{"/ws", "/state/inst1"},
		RO:      []string{"/usr", "/bin"},
		Sockets: []string{"/state/pagnetd.sock"},
	}
	target := "/usr/local/bin/qwen"
	targetArgs := []string{"--model", "x", "run"}

	argv := WrapperArgs(spec, target, targetArgs)
	gotSpec, gotTarget, gotArgs, err := ParseWrapperArgs(argv)
	if err != nil {
		t.Fatalf("ParseWrapperArgs: %v", err)
	}
	if gotTarget != target {
		t.Errorf("target = %q, want %q", gotTarget, target)
	}
	if !reflect.DeepEqual(gotArgs, targetArgs) {
		t.Errorf("targetArgs = %v, want %v", gotArgs, targetArgs)
	}
	if !reflect.DeepEqual(gotSpec.RW, spec.RW) || !reflect.DeepEqual(gotSpec.RO, spec.RO) || !reflect.DeepEqual(gotSpec.Sockets, spec.Sockets) {
		t.Errorf("spec round-trip mismatch: %+v", gotSpec)
	}
}

func TestParseWrapperArgs_Errors(t *testing.T) {
	cases := [][]string{
		nil,
		{"--rw"},
		{"--rw", ""},
		{"--rw", "/a"},
		{"--"},
		{"--", ""},
		{"bogus", "--", "/bin/true"},
	}
	for _, argv := range cases {
		if _, _, _, err := ParseWrapperArgs(argv); err == nil {
			t.Errorf("ParseWrapperArgs(%v): accepted, want a refusal", argv)
		}
	}
}

func TestSocketFromMCPConfig(t *testing.T) {
	valid := `{"mcpServers":{"pagnet":{"command":"/usr/local/bin/pagnet","args":["mcp","worker","--socket","/home/u/.pagnet/pagnetd.sock"]}}}`
	if got := SocketFromMCPConfig(valid); got != "/home/u/.pagnet/pagnetd.sock" {
		t.Errorf("SocketFromMCPConfig = %q, want the --socket argument", got)
	}
	if got := SocketFromMCPConfig(`{"mcpServers":{"pagnet":{"args":["mcp","worker"]}}}`); got != "" {
		t.Errorf("no --socket: got %q, want empty", got)
	}
	if got := SocketFromMCPConfig("not json"); got != "" {
		t.Errorf("invalid json: got %q, want empty", got)
	}
	if got := SocketFromMCPConfig(""); got != "" {
		t.Errorf("empty: got %q, want empty", got)
	}
}

func TestBridgeDirFromMCPConfig(t *testing.T) {
	valid := `{"mcpServers":{"pagnet":{"command":"/usr/local/bin/pagnet","args":["mcp","worker","--socket","/home/u/.pagnet/pagnetd.sock"]}}}`
	if got := BridgeDirFromMCPConfig(valid); got != "/usr/local/bin" {
		t.Errorf("BridgeDirFromMCPConfig = %q, want the command's directory", got)
	}
	// No command: nothing derivable (the socket is still recoverable).
	if got := BridgeDirFromMCPConfig(`{"mcpServers":{"pagnet":{"args":["mcp","worker"]}}}`); got != "" {
		t.Errorf("no command: got %q, want empty", got)
	}
	// A relative command yields NO derivable grant (the daemon always
	// renders an absolute selfExe; guessing would be worse than failing
	// visibly at the runtime's MCP spawn).
	if got := BridgeDirFromMCPConfig(`{"mcpServers":{"pagnet":{"command":"pagnet"}}}`); got != "" {
		t.Errorf("relative command: got %q, want empty", got)
	}
	// The filesystem root must never become a grant.
	if got := BridgeDirFromMCPConfig(`{"mcpServers":{"pagnet":{"command":"/pagnet"}}}`); got != "" {
		t.Errorf("root-dir command: got %q, want empty", got)
	}
	if got := BridgeDirFromMCPConfig("not json"); got != "" {
		t.Errorf("invalid json: got %q, want empty", got)
	}
	if got := BridgeDirFromMCPConfig(""); got != "" {
		t.Errorf("empty: got %q, want empty", got)
	}
}

func TestSystemRO_NoHomeNoStateDir(t *testing.T) {
	for _, p := range SystemRO() {
		if p == "~" || p == "/root" || p == "/home" || (len(p) >= 7 && strings.HasSuffix(p, ".pagnet")) {
			t.Errorf("SystemRO contains a home/state path: %q", p)
		}
	}
}

func TestRuntimeSupportRO_NeverRoot(t *testing.T) {
	out := RuntimeSupportRO("/usr/local/bin/qwen", "/home/u")
	for _, p := range out {
		if p == "" || p == "/" {
			t.Errorf("RuntimeSupportRO returned %q — the filesystem root must never be granted", p)
		}
	}
	// The binary's dir + its parent are covered.
	found := map[string]bool{}
	for _, p := range out {
		found[p] = true
	}
	if !found["/usr/local/bin"] || !found["/usr/local"] {
		t.Errorf("RuntimeSupportRO missing the binary dir chain: %v", out)
	}
}

func TestResolvRO(t *testing.T) {
	target, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		t.Skipf("/etc/resolv.conf not resolvable: %v", err)
	}
	got := ResolvRO()
	if strings.HasPrefix(target, "/etc/") {
		// The /etc grant already covers the resolved target: no extra grant.
		if len(got) != 0 {
			t.Errorf("ResolvRO = %v, want empty (the /etc grant already covers %q)", got, target)
		}
		return
	}
	// The resolver config lives outside /etc (systemd-resolved): the
	// target's directory is the single extra RO grant.
	want := []string{filepath.Dir(target)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ResolvRO = %v, want %v", got, want)
	}
	for _, p := range got {
		if p == "" || p == "/" {
			t.Errorf("ResolvRO returned %q — the filesystem root must never be granted", p)
		}
	}
}

func TestNewSpec_AssemblesExpectedShape(t *testing.T) {
	s := NewSpec(Options{
		Workspace:  "/ws/inst1",
		StateDirs:  []string{"/state/inst1/sessions"},
		Scratch:    []string{"/state/inst1/scratch"},
		NativeDirs: []string{"/home/u/.qwen"},
		Binary:     "/usr/local/bin/qwen",
		Home:       "/home/u",
		Socket:     "/state/pagnetd.sock",
		BridgeDir:  "/opt/pagnet/bin",
	})
	if err := s.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// The daemon state dir must be NEITHER RW nor RO — it is reached only
	// via the socket's traversal path.
	for _, p := range append(append([]string{}, s.RW...), s.RO...) {
		if p == "/state" || p == "/state/inst1" {
			t.Errorf("state dir placed in the allowlist subtrees: %q (it must be traversal-only)", p)
		}
	}
	// /state/inst1/sessions is RW; /state is NOT granted at all (the socket
	// path /state/pagnetd.sock grants traversal on /state via the socket
	// rule, not a subtree grant).
	hasRW := map[string]bool{}
	for _, p := range s.RW {
		hasRW[p] = true
	}
	for _, want := range []string{"/ws/inst1", "/state/inst1/sessions", "/state/inst1/scratch", "/home/u/.qwen"} {
		if !hasRW[want] {
			t.Errorf("RW missing %q (got %v)", want, s.RW)
		}
	}
	if len(s.Sockets) != 1 || s.Sockets[0] != "/state/pagnetd.sock" {
		t.Errorf("Sockets = %v, want [/state/pagnetd.sock]", s.Sockets)
	}
	// The bridge worker's binary dir is an RO grant (the sandboxed
	// runtime must EXEC its MCP server) — never RW.
	hasRO := map[string]bool{}
	for _, p := range s.RO {
		hasRO[p] = true
	}
	if !hasRO["/opt/pagnet/bin"] {
		t.Errorf("RO missing the bridge worker dir %q (got %v)", "/opt/pagnet/bin", s.RO)
	}
	for _, p := range s.RW {
		if p == "/opt/pagnet/bin" {
			t.Errorf("the bridge worker dir must be RO, never RW")
		}
	}
	// The resolver-config target (ResolvRO) is part of the coarse system
	// read — present in RO whenever the machine keeps it outside /etc.
	for _, p := range ResolvRO() {
		if !hasRO[p] {
			t.Errorf("RO missing the resolver-config target %q (got %v)", p, s.RO)
		}
	}
}
