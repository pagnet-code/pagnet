package main

import (
	"errors"
	"github.com/pagnet-code/pagnet/sdk"
	"testing"
	"time"
)

func TestBrowserBridgeReconnectDelay(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want time.Duration
	}{
		{"healthy session", &sdk.BrowserBridgeError{Healthy: true}, time.Second},
		{"short session", &sdk.BrowserBridgeError{}, 15 * time.Second},
		{"service unavailable", &sdk.BrowserBridgeError{HTTPStatus: 503}, 15 * time.Second},
		{"transport failure", errors.New("connection failed"), 15 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := browserBridgeReconnectDelay(15*time.Second, tc.err); got != tc.want {
				t.Fatalf("delay = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBrowserBridgeDiagnosticDoesNotExposeOtherErrors(t *testing.T) {
	if got := browserBridgeDiagnostic(errors.New("private-token at https://private-server")); got != "browser bridge unavailable" {
		t.Fatalf("unsafe diagnostic: %s", got)
	}
}
