package sdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRESTPermissionDeniedDoesNotKillCredential(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer ts.Close()
			c := newRestClient(ts.URL, "test", func() string { return "credential" })
			err := c.do(context.Background(), http.MethodGet, "/networks", nil, nil)
			if errors.Is(err, ErrCredentialDead) != (status == 401) {
				t.Fatalf("status %d classified as dead: %v", status, err)
			}
			if err == nil {
				t.Fatal("permission failure swallowed")
			}
		})
	}
}

func TestRESTLargeResponseAndBounds(t *testing.T) {
	for _, size := range []int{128 << 10, 17 << 20} {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"value":"` + strings.Repeat("a", size) + `"}`))
		}))
		c := newRestClient(ts.URL, "test", func() string { return "credential" })
		var out struct{ Value string }
		err := c.do(context.Background(), http.MethodGet, "/networks", nil, &out)
		ts.Close()
		if size < 16<<20 {
			if err != nil || len(out.Value) != size {
				t.Fatalf("large valid response truncated: %v, size %d", err, len(out.Value))
			}
		} else if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("oversize response: %v", err)
		}
	}
}
