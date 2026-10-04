package daemon

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

func TestNativeTerminalActivationFailureIsNotUnsupported(t *testing.T) {
	for _, test := range []struct {
		name, state, code, want string
		pid                     int
		runtime                 domain.RuntimeName
	}{
		{"pending", "admitted", "", "", 0, domain.RuntimeQwenCode},
		{"lost_resume", "failed", "native_session_lost", "could not resume", 0, domain.RuntimeQwenCode},
		{"unmaterialised", "failed", "native_session_not_materialised", "no confirmed saved conversation", 0, domain.RuntimeQwenCode},
		{"startup_failed", "failed", "native_activation_failed", "could not be started", 0, domain.RuntimeQwenCode},
		{"uncertain", "uncertain", "", "could not be started", 0, domain.RuntimeQwenCode},
		{"exited_after_success", "completed", "", "stopped before", 0, domain.RuntimeQwenCode},
		{"missing_original_pty", "completed", "", "terminal is unavailable", 123, domain.RuntimeQwenCode},
		{"genuine_headless", "completed", "", "does not expose", 123, domain.RuntimeClaudeCode},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, _ := json.Marshal(sessionworker.NativeOperationFailure{Error: "private vendor diagnostic must not escape", Code: test.code})
			snapshot := sessionworker.NativeSnapshot{PID: test.pid, ActualRuntime: test.runtime, NativeSessionID: "original-session"}
			err := nativeTerminalActivationError(snapshot, sessionworker.Outcome{State: test.state, Result: raw})
			if test.state == "admitted" {
				if !errors.Is(err, ErrDeferred) {
					t.Fatal("in-flight activation became final error", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "private vendor diagnostic") {
				t.Fatal("incorrect terminal activation diagnostic", err)
			}
			if test.name != "genuine_headless" && strings.Contains(err.Error(), "does not expose") {
				t.Fatal("failed original activation became unsupported runtime", err)
			}
		})
	}
}
