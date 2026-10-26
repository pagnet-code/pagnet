package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInstanceWorkerAvailabilityStatus(t *testing.T) {
	for _, tc := range []struct{ wire, want string }{
		{`{"ID":"ordinary","Status":"idle"}`, "idle"},
		{`{"Status":"idle","workerAvailability":{"state":"connected"}}`, "idle"},
		{`{"Status":"idle","workerAvailability":{"state":"unavailable","observedAt":"2026-10-26T12:00:00Z","expiresAt":"2026-10-26T12:00:10Z"}}`, "worker unavailable (last state: idle)"},
		{`{"Status":"idle","workerAvailability":{"state":"unknown"}}`, "worker unknown (last state: idle)"},
		{`{"Status":"working","workerAvailability":{"state":"unknown"}}`, "worker unknown (last state: working)"},
		{`{"Status":"stopped","workerAvailability":{"state":"unavailable"}}`, "stopped"},
		{`{"Status":"failed","workerAvailability":{"state":"unknown"}}`, "failed"},
		{`{"Status":"blocked","workerAvailability":{"state":"unavailable"}}`, "blocked"},
		{`{"Status":"auth_required","workerAvailability":{"state":"unknown"}}`, "auth_required"},
		{`{"Status":"rate_limited","workerAvailability":{"state":"unavailable"}}`, "rate_limited"},
	} {
		var instance agentInstanceView
		if err := json.Unmarshal([]byte(tc.wire), &instance); err != nil {
			t.Fatal(err)
		}
		if got := instance.displayStatus(); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.wire, got, tc.want)
		}
		var representative v2Participant
		if err := json.Unmarshal([]byte(tc.wire), &representative); err != nil {
			t.Fatal(err)
		}
		if got := representative.endpointStatus(); got != tc.want {
			t.Fatalf("representative got %q, want %q", got, tc.want)
		}
	}
}

func TestStopPendingAndConfirmedReceipt(t *testing.T) {
	for _, tc := range []struct {
		name, admission, detail, wantError, wantStatus string
		timeout                                        time.Duration
		wantGets                                       int
	}{
		{"unavailable admission", `{"commandId":"command","status":"pending","workerAvailability":{"state":"unavailable"}}`, ``, "stop pending: worker unavailable; stopping is not confirmed", "", time.Second, 0},
		{"unavailable detail", `{"commandId":"command","status":"pending"}`, `{"instance":{"Status":"idle","workerAvailability":{"state":"unavailable"}}}`, "stop pending: worker unavailable; stopping is not confirmed", "", time.Second, 1},
		{"deadline", `{"commandId":"command","status":"pending"}`, ``, "stop pending: stopping is not confirmed", "", 0, 0},
		{"receipt", `{"commandId":"command","status":"pending"}`, `{"instance":{"Status":"stopped","workerAvailability":{"state":"unavailable"}}}`, "", "stopped", time.Second, 1},
		{"legacy receipt", `{}`, `{"instance":{"Status":"stopped"}}`, "", "stopped", time.Second, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posts, gets := 0, 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost {
					posts++
					w.WriteHeader(http.StatusAccepted)
					fmt.Fprint(w, tc.admission)
					return
				}
				gets++
				fmt.Fprint(w, tc.detail)
			}))
			defer ts.Close()
			c := &cliCtx{base: ts.URL}
			status, err := c.performInstanceAction("/instance", "stop", tc.timeout, time.Millisecond)
			if tc.wantError != "" {
				var pending *stopPendingError
				if !errors.As(err, &pending) || !errors.Is(err, errStopPending) || err.Error() != tc.wantError {
					t.Fatalf("expected typed pending %q, got %v", tc.wantError, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if status != tc.wantStatus || strings.Contains(status, "dispatched") {
				t.Fatalf("status %q", status)
			}
			if posts != 1 || gets != tc.wantGets {
				t.Fatalf("unexpected request counts: post=%d get=%d", posts, gets)
			}
		})
	}
}

func TestInstanceRowsWorkerAvailability(t *testing.T) {
	s := newRecordServer(t, map[string]string{
		"GET /api/v1/networks/net/agents":                 `[{"ID":"agent","Name":"Agent"}]`,
		"GET /api/v1/hosts":                               `[{"ID":"host","Name":"Host"}]`,
		"GET /api/v1/networks/net/agents/agent/instances": `[{"ID":"native","Status":"idle","HostID":"host","workerAvailability":{"state":"unavailable"}},{"ID":"ordinary","Status":"idle","HostID":"host"}]`,
	})
	c := &cliCtx{base: s.ts.URL}
	rows, err := c.instanceRows("net")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0][2] != "worker unavailable (last state: idle)" || rows[1][2] != "idle" {
		t.Fatal(rows)
	}
	instances, err := c.definitionInstances("net", "agent")
	if err != nil {
		t.Fatal(err)
	}
	_, err = selectSendInstance("Agent", "", instances)
	if err == nil || !strings.Contains(err.Error(), "worker unavailable (last state: idle)") {
		t.Fatal(err)
	}
	output, err := captureStdoutErr(t, func() error {
		_, _, err := c.findInstance("net", "Agent", "")
		return err
	})
	if err == nil || !strings.Contains(output, "worker unavailable (last state: idle)") {
		t.Fatal(output, err)
	}
}

func TestStopCommandPendingIsNonzero(t *testing.T) {
	for _, unavailable := range []bool{true, false} {
		t.Run(fmt.Sprint(unavailable), func(t *testing.T) {
			admission := `{"commandId":"command","status":"pending"}`
			if unavailable {
				admission = `{"commandId":"command","status":"pending","workerAvailability":{"state":"unavailable"}}`
			}
			s := newRecordServer(t, map[string]string{
				"GET /api/v1/networks":                                           `[{"ID":"net","Name":"Network"}]`,
				"GET /api/v1/networks/net/agents":                                `[{"ID":"agent","Name":"Agent"}]`,
				"GET /api/v1/networks/net/agents/agent/instances":                `[{"ID":"instance","Status":"idle"}]`,
				"POST /api/v1/networks/net/agents/agent/instances/instance/stop": admission,
				"GET /api/v1/networks/net/agents/agent/instances/instance":       `{"instance":{"ID":"instance","Status":"stopped"}}`,
			})
			cliEnv(t, s.ts)
			cmd := stopCmd()
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"Agent"})
			out, err := captureStdoutErr(t, cmd.Execute)
			if unavailable {
				if !errors.Is(err, errStopPending) || strings.Contains(out, "->") {
					t.Fatalf("pending printed success: %q, %v", out, err)
				}
				if !s.noCall(http.MethodGet, "/api/v1/networks/net/agents/agent/instances/instance") {
					t.Fatal("unavailable admission started polling")
				}
			} else if err != nil || !strings.Contains(out, "-> stopped") {
				t.Fatal(out, err)
			}
			if strings.Contains(out, "(dispatched)") {
				t.Fatal("stop printed dispatch as completion", out)
			}
		})
	}
}
