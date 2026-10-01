package sdk

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceServeStopsAfterCredentialRevocation(t *testing.T) {
	fs := newFakeServer(t)
	_, credential := fs.createPrincipal("service", "Jev")
	c := mustConnect(t, fs, credential, t.TempDir())
	svc := c.Service("Jev")
	result := make(chan error, 1)
	go func() { result <- svc.Serve(context.Background()) }()
	durable := c.credential.Load().(string)
	fs.mu.Lock()
	delete(fs.endpointCreds, durable)
	fs.mu.Unlock()
	fs.dropEndpoint(c.EndpointID())
	select {
	case err := <-result:
		if !errors.Is(err, ErrCredentialDead) || !errors.Is(c.Err(), ErrCredentialDead) {
			t.Fatalf("credential failure hidden: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service silently stayed alive after its credential died")
	}
}

func TestServiceServeSurvivesTransientDisconnectAndStopsOnClose(t *testing.T) {
	fs := newFakeServer(t)
	_, credential := fs.createPrincipal("service", "Jev")
	c := mustConnect(t, fs, credential, t.TempDir())
	result := make(chan error, 1)
	go func() { result <- c.Service("Jev").Serve(context.Background()) }()
	first := c.EndpointID()
	fs.dropEndpoint(first)
	waitFor(t, 5*time.Second, "reconnect", func() bool { return c.EndpointID() != first && c.connected.Load() })
	select {
	case err := <-result:
		t.Fatalf("transient disconnect stopped service: %v", err)
	default:
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("close error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("service kept running after Close")
	}
}
