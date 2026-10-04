package extension

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
)

type handlerFunc func(context.Context, InterceptRequest) (Decision, error)

func (f handlerFunc) Intercept(ctx context.Context, r InterceptRequest) (Decision, error) {
	return f(ctx, r)
}

type credentialFunc func(context.Context, string) (string, error)

func (f credentialFunc) Authorization(ctx context.Context, b string) (string, error) {
	return f(ctx, b)
}
func interceptRequest() InterceptRequest {
	return InterceptRequest{ProtocolVersion: "1.0", InterceptorID: "acme.security.a", Operation: fabric.OperationInvoke, Stage: "invoke.dispatch", Phase: PhaseRequest, Envelope: patchEnvelope()}
}
func compiledRegistration() CompiledRegistration {
	m := manifestWith("a")
	r := m.Interceptors[0]
	r.TimeoutMillis = 50
	return CompiledRegistration{ExtensionID: m.ID, Registration: r}
}

func TestRemoteCredentialBoundaryAndNoRedirect(t *testing.T) {
	var calls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`{"action":"CONTINUE"}`)) }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer private-adapter-key" {
			t.Error("missing private authorization")
		}
		if strings.Contains(string(body), "private-adapter-key") {
			t.Error("credential entered envelope")
		}
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	handler, err := NewHTTPHandler(server.URL, "binding", credentialFunc(func(_ context.Context, b string) (string, error) {
		if b != "binding" {
			t.Error(b)
		}
		return "Bearer private-adapter-key", nil
	}), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	if _, err = handler.Intercept(context.Background(), interceptRequest()); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("credential and payload followed redirect")
	}
}
func TestRemoteMalformedDecisionsAreBounded(t *testing.T) {
	for _, body := range []string{`{"action":"CONTINUE","action":"RESPOND"}`, `{"Action":"CONTINUE"}`, strings.Repeat("x", MaxInterceptBytes+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		handler, err := NewHTTPHandler(server.URL, "binding", nil, 1)
		if err != nil {
			t.Fatal(err)
		}
		_, err = handler.Intercept(context.Background(), interceptRequest())
		handler.Close()
		server.Close()
		if err == nil {
			t.Fatal("malformed response accepted")
		}
	}
}
func TestExecutorTimeoutRetainsBoundedCapacityAndCopiesRequest(t *testing.T) {
	executor, _ := NewExecutor(1)
	registration := compiledRegistration()
	request := interceptRequest()
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	handler := handlerFunc(func(ctx context.Context, r InterceptRequest) (Decision, error) {
		close(entered)
		r.Envelope.Payload[0] = 'X'
		<-release
		close(finished)
		return Decision{Action: Continue}, nil
	})
	done := make(chan error, 1)
	go func() { _, err := executor.Call(context.Background(), registration, handler, request); done <- err }()
	<-entered
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if request.Envelope.Payload[0] != '{' {
		t.Fatal("handler modified engine request")
	}
	var extra atomic.Int32
	_, err := executor.Call(context.Background(), registration, handlerFunc(func(context.Context, InterceptRequest) (Decision, error) {
		extra.Add(1)
		return Decision{Action: Continue}, nil
	}), request)
	if !errors.Is(err, context.DeadlineExceeded) || extra.Load() != 0 {
		t.Fatal("timeout released running handler capacity")
	}
	close(release)
	<-finished
	// The first timed-out handler eventually releases its reserved slot.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = executor.Call(ctx, registration, handlerFunc(func(context.Context, InterceptRequest) (Decision, error) { return Decision{Action: Continue}, nil }), request)
	if err != nil {
		t.Fatal(err)
	}
}
func TestExecutorPanicAndRelayCannotCrashOrLeak(t *testing.T) {
	executor, _ := NewExecutor(1)
	registration := compiledRegistration()
	if _, err := executor.Call(context.Background(), registration, handlerFunc(func(context.Context, InterceptRequest) (Decision, error) { panic("private-key-in-panic") }), interceptRequest()); err == nil || strings.Contains(err.Error(), "private-key") {
		t.Fatal(err)
	}
	registration.Registration.Placement = PlacementRelay
	var calls atomic.Int32
	_, err := executor.Call(context.Background(), registration, handlerFunc(func(context.Context, InterceptRequest) (Decision, error) {
		calls.Add(1)
		return Decision{Action: Continue}, nil
	}), interceptRequest())
	if err == nil || calls.Load() != 0 {
		t.Fatal("relay received plaintext envelope")
	}
}
