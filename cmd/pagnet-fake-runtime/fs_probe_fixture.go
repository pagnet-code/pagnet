package main

// The filesystem-probe fixture (security wave S2 e2e). A scripted
// endpoint attempts to READ a set of planted secret files and records
// the outcome per path, so a test can assert the sandbox DENIED each
// one (EACCES) while the endpoint itself completed its work.
//
//	PAGNET_FAKE_FS_PROBE=<path1>[,<path2>,...]
//	  Comma-separated ABSOLUTE paths to attempt to read at endpoint start.
//	PAGNET_FAKE_FS_PROBE_FILE=<path>
//	  Where to write the observed outcomes (a JSON array, one object per
//	  path: {"fs_probe": <path>, "ok": <bool>, "err": "<errno or error>"}).
//
// OFF unless both are set. The probe runs BEFORE the bridge fixtures so
// a test can pair "the sandboxed runtime cannot read the daemon state"
// with "the same runtime's bridge still authenticates" (S1 invariants
// under S2). A successful read is recorded as ok:true — in a sandboxed
// endpoint a true for a daemon-state path means the sandbox is broken,
// and the test fails on it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// fsProbe runs the scripted secret-read probes and writes the observed
// outcomes. It never fails the endpoint: the outcomes are DATA for the
// test, not a fatal condition (an unsandboxed run records ok:true, a
// sandboxed run records the denial — the test asserts which).
func fsProbe() {
	paths := os.Getenv("PAGNET_FAKE_FS_PROBE")
	out := os.Getenv("PAGNET_FAKE_FS_PROBE_FILE")
	if paths == "" || out == "" {
		return
	}
	var lines []string
	for _, p := range strings.Split(paths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, err := os.ReadFile(p)
		rec := map[string]any{"fs_probe": p}
		if err == nil {
			rec["ok"] = true
		} else {
			rec["ok"] = false
			rec["err"] = fsProbeErrName(err)
		}
		b, _ := json.Marshal(rec)
		lines = append(lines, string(b))
	}
	body := bytes.NewBufferString("[")
	for i, l := range lines {
		if i > 0 {
			body.WriteString(",")
		}
		body.WriteString(l)
	}
	body.WriteString("]\n")
	if err := os.WriteFile(out, body.Bytes(), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "fs probe fixture: write result file:", err)
	}
}

// fsProbeErrName renders the errno of a read failure (EACCES / EPERM /
// ENOENT / ...) — or the full error text when it carries no errno — so
// a test can assert the DENIAL CLASS (Landlock denials are EACCES).
func fsProbeErrName(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	return err.Error()
}
