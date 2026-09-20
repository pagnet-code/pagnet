package main

import (
	"bytes"
	"testing"
)

// TestVersionCommand pins the `pagnet version` output format: one line,
// "pagnet <version>". The version var is stamped at release-build time
// (-X main.version=$(VERSION)); in tests it is the "dev" default.
func TestVersionCommand(t *testing.T) {
	if version == "" {
		t.Fatal("version must be non-empty (stamped or the dev default)")
	}
	cmd := versionCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if want := "pagnet " + version + "\n"; buf.String() != want {
		t.Fatalf("version output = %q, want %q", buf.String(), want)
	}
}

// TestVersionFlagMatchesVersionCommand pins the parity (plan §7):
// `pagnet --version` and `pagnet version` are the same command in two
// spellings and must print identical bytes. Both route through printVersion,
// and --version is deliberately NOT cobra's built-in version flag (whose
// template would add a "version" word and make the two disagree).
func TestVersionFlagMatchesVersionCommand(t *testing.T) {
	// The root command binds its flags to package globals, so restore them:
	// a leaked versionFlag would make every later bare-root invocation print
	// a version instead of running.
	prevFlag := versionFlag
	t.Cleanup(func() { versionFlag = prevFlag })

	var flagBuf, cmdBuf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&flagBuf)
	root.SetErr(&flagBuf)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--version: %v", err)
	}
	sub := versionCmd()
	sub.SetOut(&cmdBuf)
	sub.SetErr(&cmdBuf)
	if err := sub.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
	if flagBuf.String() != cmdBuf.String() {
		t.Fatalf("--version printed %q, version printed %q — the two spellings must agree",
			flagBuf.String(), cmdBuf.String())
	}
	if want := "pagnet " + version + "\n"; flagBuf.String() != want {
		t.Fatalf("--version output = %q, want %q", flagBuf.String(), want)
	}
}

// TestVersionFlagWinsOverDetach: the version path is answered before the
// detached launcher or the bare status view, so `pagnet --version` never
// re-execs a daemon or reads daemon state — it works on a machine that has
// never been enrolled.
func TestVersionFlagWinsOverDetach(t *testing.T) {
	prevFlag, prevDetach := versionFlag, detach
	t.Cleanup(func() { versionFlag, detach = prevFlag, prevDetach })

	var buf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"--version", "-d"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--version -d: %v", err)
	}
	if got := buf.String(); got != "pagnet "+version+"\n" {
		t.Fatalf("output = %q, want only the version line (no detach, no status view)", got)
	}
}
