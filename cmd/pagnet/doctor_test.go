package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoctorServerReachability(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			withFileFallback(t)
			t.Setenv("PAGNET_SERVER", "")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Hosted ingress exposes the API but sends /healthz to the web app.
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/auth/setup/status" {
					http.NotFound(w, r)
					return
				}
				if r.Header.Get("Authorization") != "" {
					t.Error("reachability probe must work without authentication")
				}
				w.WriteHeader(status)
				fmt.Fprint(w, `{"setupRequired":false}`)
			}))
			defer server.Close()

			previousServer, previousToken, previousAccount := serverURL, userToken, accountFlag
			serverURL, userToken, accountFlag = server.URL, "", ""
			t.Cleanup(func() { serverURL, userToken, accountFlag = previousServer, previousToken, previousAccount })
			cmd := doctorCmd()
			cmd.SetArgs([]string{"--state-dir", t.TempDir()})
			output, err := captureStdoutErr(t, cmd.Execute)
			if status == http.StatusOK {
				if !strings.Contains(output, "ok   server reachable") || !strings.Contains(output, "host login stored") {
					t.Fatalf("doctor did not continue past the public reachability check: %s (error: %v)", output, err)
				}
			} else if err == nil || err.Error() != "server unhealthy" || !strings.Contains(output, "http 503") {
				t.Fatalf("doctor did not reject an unhealthy server: %s (error: %v)", output, err)
			}
		})
	}
}
