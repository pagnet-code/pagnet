package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInstanceRowsRecoveryDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name, response, want string
		code                 int
	}{
		{"prepared", `[{"id":"recovery","instanceId":"instance","definitionId":"agent","hostId":"host","state":"prepared"}]`, preparedRecoveryStatus, 200},
		{"committed", `[{"id":"recovery","instanceId":"instance","definitionId":"agent","hostId":"host","state":"committed"}]`, committedRecoveryStatus, 200},
		{"instance mismatch", `[{"id":"recovery","instanceId":"Instance","definitionId":"agent","hostId":"host","state":"prepared"}]`, "", 200},
		{"definition mismatch", `[{"id":"recovery","instanceId":"instance","definitionId":"Agent","hostId":"host","state":"prepared"}]`, "", 200},
		{"host mismatch", `[{"id":"recovery","instanceId":"instance","definitionId":"agent","hostId":"Host","state":"prepared"}]`, "", 200},
		{"missing recovery id", `[{"instanceId":"instance","definitionId":"agent","hostId":"host","state":"prepared"}]`, "", 200},
		{"unknown state", `[{"id":"recovery","instanceId":"instance","definitionId":"agent","hostId":"host","state":"verified"}]`, "", 200},
		{"malformed", `[{"id":"recovery","instanceId":"instance","definitionId":"agent","hostId":"host","state":"prepared"},`, "", 200},
		{"wrong shape", `{}`, "", 200},
		{"missing endpoint", `[]`, "", 404},
		{"server failure", `[]`, "", 500},
		{"unauthorized without reauth", `[]`, "", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/networks/net/agents":
					fmt.Fprint(w, `[{"ID":"agent","Name":"Agent"}]`)
				case "/api/v1/hosts":
					fmt.Fprint(w, `[{"ID":"host","Name":"Host"}]`)
				case "/api/v1/networks/net/agents/agent/instances":
					fmt.Fprint(w, `[{"ID":"instance","Status":"blocked","HostID":"host","AvailabilityRetryAt":"later","workerAvailability":{"state":"unavailable"}},{"ID":"other","Status":"idle","HostID":"host"}]`)
				case "/api/v1/agents/agent/worker-recoveries":
					lookups++
					if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer diagnostic-token" {
						t.Errorf("unexpected diagnostic request: %s, authorization present=%v", r.Method, r.Header.Get("Authorization") != "")
					}
					w.WriteHeader(tc.code)
					fmt.Fprint(w, tc.response)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer ts.Close()
			c := &cliCtx{base: ts.URL, token: "diagnostic-token", reauth: true}
			rows, err := c.instanceRows("net")
			if err != nil {
				t.Fatal(err)
			}
			want := "blocked (worker unavailable) (retry later)"
			if tc.want != "" {
				want += " (" + tc.want + ")"
			}
			if len(rows) != 2 || rows[0][2] != want || rows[1][2] != "idle" || lookups != 1 || c.retried {
				t.Fatalf("rows=%v lookups=%d retried=%v", rows, lookups, c.retried)
			}
		})
	}
}

func TestStatusRecoveryRebootGuidance(t *testing.T) {
	for _, state := range []string{"prepared", "committed", "unknown"} {
		t.Run(state, func(t *testing.T) {
			recovery, err := json.Marshal([]workerRecoverySummary{{ID: "recovery", InstanceID: "instance", DefinitionID: "agent", HostID: "host", State: state}})
			if err != nil {
				t.Fatal(err)
			}
			s := newRecordServer(t, map[string]string{
				"GET /api/v1/stats/overview":                      `{}`,
				"GET /api/v1/networks":                            `[{"ID":"net","Name":"Network"}]`,
				"GET /api/v1/networks/net/agents":                 `[{"ID":"agent","Name":"Agent"}]`,
				"GET /api/v1/hosts":                               `[{"ID":"host","Name":"Host"}]`,
				"GET /api/v1/networks/net/agents/agent/instances": `[{"ID":"instance","Status":"blocked","HostID":"host"}]`,
				"GET /api/v1/agents/agent/worker-recoveries":      string(recovery),
				"GET /api/v1/networks/net/services":               `[]`,
			})
			cliEnv(t, s.ts)
			out, err := captureStdoutErr(t, statusCmd().Execute)
			if err != nil {
				t.Fatal(err)
			}
			guidance := "Recovery requires a host OS reboot after preparation; restarting pagnet is insufficient."
			if strings.Contains(out, guidance) != (state == "prepared") {
				t.Fatal(out)
			}
		})
	}
}

func TestInstanceRowsSkipsRecoveryLookupWithoutBlockedInstances(t *testing.T) {
	s := newRecordServer(t, map[string]string{
		"GET /api/v1/networks/net/agents":                 `[{"ID":"agent","Name":"Agent"}]`,
		"GET /api/v1/hosts":                               `[]`,
		"GET /api/v1/networks/net/agents/agent/instances": `[{"ID":"instance","Status":"idle"}]`,
	})
	c := &cliCtx{base: s.ts.URL}
	rows, err := c.instanceRows("net")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0][2] != "idle" || !s.noCall(http.MethodGet, "/api/v1/agents/agent/worker-recoveries") {
		t.Fatal(rows)
	}
}
