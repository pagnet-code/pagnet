package daemon

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeRecoveryFenceLogging(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		level    string
		category string
	}{
		{"fenced", errNativeWorkerRecoveryFenced, "DEBUG", errNativeWorkerRecoveryFenced.Error()},
		{"wrapped fence", fmt.Errorf("private worker path: %w", errNativeWorkerRecoveryFenced), "DEBUG", errNativeWorkerRecoveryFenced.Error()},
		{"untyped fence text", errors.New(errNativeWorkerRecoveryFenced.Error()), "WARN", "*errors.errorString"},
		{"connection refused", &net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED}, "WARN", "native worker socket unavailable; explicit lost-worker recovery required"},
		{"wrapped unix connection refused", fmt.Errorf("private worker path: %w", &net.OpError{Op: "dial", Net: "unix", Addr: &net.UnixAddr{Name: "/private worker path/worker.sock", Net: "unix"}, Err: fmt.Errorf("connect: %w", syscall.ECONNREFUSED)}), "WARN", "native worker socket unavailable; explicit lost-worker recovery required"},
		{"wrapped tcp connection refused", fmt.Errorf("private worker path: %w", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}), "WARN", "*fmt.wrapError"},
		{"wrapped non-dial connection refused", fmt.Errorf("private worker path: %w", &net.OpError{Op: "read", Net: "unix", Addr: &net.UnixAddr{Name: "/private worker path/worker.sock", Net: "unix"}, Err: syscall.ECONNREFUSED}), "WARN", "*fmt.wrapError"},
		{"registry failure", sql.ErrConnDone, "WARN", "*errors.errorString"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			log := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			now := time.Unix(100, 0)
			report := nativeRecoveryFailureReporter(log, func() time.Time { return now })
			for _, elapsed := range []time.Duration{0, 5 * time.Second, time.Minute, 2 * time.Minute} {
				now = time.Unix(100, 0).Add(elapsed)
				report("worker", test.err)
			}
			if got := strings.Count(output.String(), "level="+test.level); got != 3 {
				t.Fatalf("%s entries = %d, want 3: %s", test.level, got, output.String())
			}
			if got := strings.Count(output.String(), "level="); got != 3 {
				t.Fatalf("total entries = %d, want 3: %s", got, output.String())
			}
			if !strings.Contains(output.String(), test.category) {
				t.Fatalf("missing error category %q: %s", test.category, output.String())
			}
			if strings.Contains(output.String(), "private worker path") {
				t.Fatal("wrapped error text leaked into recovery log")
			}
		})
	}
}

func TestNativeRecoveryAdmissionDeferredLogging(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprintf("persistent=%t", persistent), func(t *testing.T) {
			var output bytes.Buffer
			log := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			now := time.Unix(100, 0)
			report := nativeRecoveryFailureReporter(log, func() time.Time { return now })
			deferred := fmt.Errorf("ownership bootstrap: %w", ErrNativeOriginAdmissionDeferred)
			report("worker", deferred)
			now = now.Add(2 * time.Second)
			report("worker", deferred)
			if persistent {
				now = now.Add(3 * time.Second)
				report("worker", deferred)
				now = now.Add(2 * time.Second)
				report("worker", deferred)
			} else {
				report("worker", nil)
			}
			if got := strings.Count(output.String(), "level=DEBUG"); got != 1 {
				t.Fatalf("debug entries = %d, want 1: %s", got, output.String())
			}
			wantWarnings := 0
			if persistent {
				wantWarnings = 1
			}
			if got := strings.Count(output.String(), "level=WARN"); got != wantWarnings {
				t.Fatalf("warning entries = %d, want %d: %s", got, wantWarnings, output.String())
			}
			if !strings.Contains(output.String(), ErrNativeOriginAdmissionDeferred.Error()) {
				t.Fatal("missing admission-deferred error category")
			}
		})
	}
}

func TestNativeRecoveryFailureLoggingIsolationAndReset(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	now := time.Unix(100, 0)
	report := nativeRecoveryFailureReporter(log, func() time.Time { return now })
	report("worker", ErrNativeOriginAdmissionDeferred)
	now = now.Add(5 * time.Second)
	report("worker", ErrNativeOriginAdmissionDeferred)
	report("other-worker", ErrNativeOriginAdmissionDeferred)
	report("worker", nil)
	report("worker", ErrNativeOriginAdmissionDeferred)
	for _, err := range []error{ErrNativeOriginAdmissionRejected, errors.New("private worker configuration")} {
		report("failing-worker", err)
		report("failing-worker", err)
	}
	if got := strings.Count(output.String(), "level=DEBUG"); got != 3 {
		t.Fatalf("debug entries = %d, want 3: %s", got, output.String())
	}
	if got := strings.Count(output.String(), "level=WARN"); got != 3 {
		t.Fatalf("warning entries = %d, want 3: %s", got, output.String())
	}
	if strings.Contains(output.String(), "private worker configuration") {
		t.Fatal("arbitrary error text leaked into recovery log")
	}
}
