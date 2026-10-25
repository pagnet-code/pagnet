package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

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
