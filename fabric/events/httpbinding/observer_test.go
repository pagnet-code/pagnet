package httpbinding

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

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/pagnet-code/pagnet/fabric/events"
)

type credential func(context.Context, string) (string, error)

func (f credential) Authorization(c context.Context, b string) (string, error) { return f(c, b) }

func sample(t *testing.T) event.Event {
	t.Helper()
	e := event.New("1.0")
	e.SetID("original-observation")
	e.SetSource("pagnet://example/node")
	e.SetType("dev.pagnet.invoke.completed")
	if err := e.SetData("application/json", []byte(`{"large":9007199254740993}`)); err != nil {
		t.Fatal(err)
	}
	return e
}
func config(endpoint string) Config {
	return Config{Endpoint: endpoint, Binding: "observer.audit", AllowPlainHTTP: true, Concurrency: 1, MaxEventBytes: 1 << 20, Timeout: time.Second}
}

func TestOfficialStructuredDeliveryPrivateCredentialAndNoRedirectReplay(t *testing.T) {
	var calls, leaks atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaks.Add(1); w.WriteHeader(204) }))
	defer target.Close()
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Content-Type") != "application/cloudevents+json" || r.Header.Get("Authorization") != "Bearer private-observer-key" {
			t.Error("wrong official binding or credential")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		e, err := events.Decode(raw, 1<<20)
		if err != nil || e.ID() != "original-observation" || !strings.Contains(string(e.Data()), "9007199254740993") || strings.Contains(string(raw), "private-observer-key") {
			t.Error("event identity/data/secret boundary", err)
		}
		if calls.Load() == 1 {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Location", target.URL)
		w.WriteHeader(307)
	}))
	defer sink.Close()
	c := config(sink.URL)
	c.Credentials = credential(func(ctx context.Context, b string) (string, error) {
		if b != "observer.audit" {
			t.Error("wrong credential selector")
		}
		return "Bearer private-observer-key", nil
	})
	o, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer o.CloseContext(context.Background())
	if err = o.Deliver(context.Background(), sample(t)); err != nil {
		t.Fatal(err)
	}
	if err = o.Deliver(context.Background(), sample(t)); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls.Load() != 2 || leaks.Load() != 0 {
		t.Fatal("redirect followed or HTTP retried")
	}
}

func TestNoImplicitProxyPlaintextQueryCredentialsOrErrorLeak(t *testing.T) {
	var proxyCalls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls.Add(1); w.WriteHeader(502) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	for _, endpoint := range []string{"http://example.test/sink", "https://user:secret@example.test/sink", "https://example.test/sink?token=secret", "https://example.test/sink?", "https://example.test/sink#secret"} {
		c := config(endpoint)
		c.AllowPlainHTTP = false
		if _, err := New(c); err == nil {
			t.Fatalf("unsafe binding accepted: %s", endpoint)
		}
	}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer sink.Close()
	c := config(sink.URL)
	c.Credentials = credential(func(context.Context, string) (string, error) { return "", errors.New("secret-credential-error") })
	o, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer o.CloseContext(context.Background())
	if err = o.Deliver(context.Background(), sample(t)); err == nil || strings.Contains(err.Error(), "secret-credential-error") {
		t.Fatal("private credential failure leaked", err)
	}
	if tr := o.client.Transport.(*http.Transport); tr.Proxy != nil {
		t.Fatal("environment proxy inherited")
	}
	if proxyCalls.Load() != 0 {
		t.Fatal("implicit proxy received request")
	}
}

func TestCloseJoinsRealCallbackAndBoundedQueuedDelivery(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c := config("http://127.0.0.1:1/sink")
	c.Timeout = time.Minute
	c.Credentials = credential(func(context.Context, string) (string, error) { close(entered); <-release; return "", nil })
	o, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- o.Deliver(context.Background(), sample(t)) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err = o.Deliver(ctx, sample(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("capacity not bounded", err)
	}
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err = o.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close falsely joined callback", err)
	}
	cancel()
	close(release)
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("closed callback continued HTTP", err)
	}
	if err = o.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = o.Deliver(context.Background(), sample(t)); err == nil {
		t.Fatal("closed observer admitted work")
	}
}
