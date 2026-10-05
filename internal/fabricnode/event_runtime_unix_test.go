//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricclient"
	"github.com/pagnet-code/pagnet/internal/fabrichost"
)

func TestInstalledEventsActualKernelDiscoveryIndependentObserverAndRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			return
		}
		event, e := events.Decode(raw, 1<<20)
		if e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		if event.Type() != "dev.pagnet.discover.started" && event.Type() != "dev.pagnet.discover.completed" {
			t.Error("unexpected event type", event.Type())
		}
		if strings.Contains(string(raw), "private-query-never-in-events") {
			t.Error("private query leaked")
		}
		once.Do(func() { close(entered) })
		select {
		case <-release:
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer sink.Close()
	defer close(release)
	// t.TempDir's immediate child follows the process umask, which need not be
	// 0700. Own a genuinely private directory for the real socket boundary; the
	// short prefix also keeps the selected path within the native sun_path bound.
	parent, e := os.MkdirTemp("", "pgn-events-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(parent)
	dir := filepath.Join(parent, "authority")
	socket := filepath.Join(parent, "node.sock")
	i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	settings := DefaultEventSettings([]ObserverSettings{{ID: "audit.local", Types: []string{"dev.pagnet.discover.started", "dev.pagnet.discover.completed"}, Endpoint: sink.URL, CredentialSelector: "credentials.none", AllowPlainHTTP: true}})
	settings.Queue.RetryDelay = time.Millisecond
	settings.PollInterval = time.Millisecond
	if e = InitializeConfiguredEvents(ctx, i, settings); e != nil {
		t.Fatal(e)
	}
	root := i.Store.AuthorityIdentity()
	if e = InitializeConfiguredEvents(ctx, i, settings); e != nil {
		t.Fatal("exact explicit setup retry", e)
	}
	check, e := OpenInstalledEvents(ctx, i, nil)
	if e != nil {
		t.Fatal("event configuration/open before node", e)
	}
	if e = check.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	changed := DefaultEventSettings(settings.Observers)
	changed.DeliveryTimeout = time.Second
	if e = InitializeConfiguredEvents(ctx, i, changed); e == nil {
		t.Fatal("changed configuration silently accepted")
	}
	if e = i.Close(); e != nil {
		t.Fatal(e)
	}
	binary, _ := os.Executable()
	n, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal(e)
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		result, e := client.Call(ctx, fabric.OperationDiscover, json.RawMessage(`{"query":"private-query-never-in-events","limit":1}`))
		if e == nil && result.IsError {
			e = localDenied()
		}
		done <- e
	}()
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("real discovery waited on observer")
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual lifecycle event not delivered")
	}
	if e = client.Close(); e != nil {
		t.Fatal(e)
	}
	// Sink remains blocked: joining closes actual HTTP delivery, preserves queue
	// state and original keys without misreporting observer acceptance.
	if e = n.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	i, e = localinstallation.Load(ctx, dir, registry.DefaultOptions())
	if e != nil {
		t.Fatal(e)
	}
	if i.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("event restart substituted root")
	}
	r, e := OpenInstalledEvents(ctx, i, nil)
	if e != nil {
		t.Fatal(e)
	}
	state, e := r.Store.State(ctx)
	if e != nil || state.Rows < 1 || state.Acknowledged != 0 {
		t.Fatal("blocked observation falsely acknowledged/lost", state, e)
	}
	if e = r.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	if e = i.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestInstalledEventsMissingAndPartialStateNeverBootstrapOnOpen(t *testing.T) {
	ctx := t.Context()
	parent := t.TempDir()
	dir := filepath.Join(parent, "authority")
	i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(parent, "node.sock"))})
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	if r, e := OpenInstalledEvents(ctx, i, nil); e != nil || r != nil {
		t.Fatal("all-missing observation not disabled", e)
	}
	if e = os.Mkdir(filepath.Join(dir, "events"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenInstalledEvents(ctx, i, nil); e == nil {
		t.Fatal("orphan state implicitly attested")
	}
	if e = os.Remove(filepath.Join(dir, "events")); e != nil {
		t.Fatal(e)
	}
	s := DefaultEventSettings([]ObserverSettings{{ID: "audit.local", Types: []string{"dev.pagnet.invoke.completed"}, Endpoint: "http://127.0.0.1:1/sink", CredentialSelector: "credentials.none", AllowPlainHTTP: true}})
	if e = InitializeConfiguredEvents(ctx, i, s); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(dir, "events"), filepath.Join(dir, "events-preserved")); e != nil {
		t.Fatal(e)
	}
	if _, e = OpenInstalledEvents(ctx, i, nil); e == nil {
		t.Fatal("missing signed store regenerated")
	}
	if _, e = os.Lstat(filepath.Join(dir, "events")); !os.IsNotExist(e) {
		t.Fatal("startup created missing store", e)
	}
}

func TestInvalidEventSettingsLeaveNoPreparingPinOrPrivateStore(t *testing.T) {
	cases := map[string]func(*EventSettings){
		"duplicate subscriptions": func(s *EventSettings) {
			s.Queue.Subscriptions = append(s.Queue.Subscriptions, s.Queue.Subscriptions[0])
			s.Observers = append(s.Observers, s.Observers[0])
		},
		"duplicate observers": func(s *EventSettings) {
			s.Observers = append(s.Observers, s.Observers[0])
			s.Queue.Subscriptions = append(s.Queue.Subscriptions, s.Queue.Subscriptions[0])
			s.Queue.Subscriptions[1].ID = "audit.other"
		},
		"duplicate types":      func(s *EventSettings) { s.Observers[0].Types = append(s.Observers[0].Types, s.Observers[0].Types[0]) },
		"unknown subscription": func(s *EventSettings) { s.Observers[0].ID = "audit.unselected" },
		"invalid queue":        func(s *EventSettings) { s.Queue.LeaseTTL = 0 },
		"invalid ingress":      func(s *EventSettings) { s.Ingress.QueueDepth = 0 },
		"invalid delivery":     func(s *EventSettings) { s.DeliveryTimeout = 0 },
		"invalid selector":     func(s *EventSettings) { s.Observers[0].CredentialSelector = "unqualified" },
		"embedded credential": func(s *EventSettings) {
			s.Observers[0].Endpoint = "https://sink.example/events?token=must-not-be-pinned"
		},
		"unselected http": func(s *EventSettings) { s.Observers[0].AllowPlainHTTP = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			parent := t.TempDir()
			dir := filepath.Join(parent, "authority")
			i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(parent, "node.sock"))})
			if e != nil {
				t.Fatal(e)
			}
			defer i.Close()
			s := DefaultEventSettings([]ObserverSettings{{ID: "audit.local", Types: []string{"dev.pagnet.discover.completed"}, Endpoint: "http://127.0.0.1:1/events", AllowPlainHTTP: true, CredentialSelector: "credentials.none"}})
			mutate(&s)
			if e = InitializeConfiguredEvents(ctx, i, s); e == nil {
				t.Fatal("invalid settings accepted")
			}
			if _, e = eventRecord(ctx, i); !authorityMissing(e) {
				t.Fatal("invalid setup published preparing pin", e)
			}
			if _, e = os.Lstat(filepath.Join(dir, "events")); !os.IsNotExist(e) {
				t.Fatal("invalid setup created private event state", e)
			}
		})
	}
}

func TestMissingEventCredentialProviderRetainsQueueWithoutBlockingActualNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var sinkCalls atomic.Int64
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sinkCalls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer sink.Close()
	private, e := os.MkdirTemp("", "pgn-events-missing-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(private)
	dir, socket := filepath.Join(private, "authority"), filepath.Join(private, "node.sock")
	i, e := localinstallation.Bootstrap(ctx, dir, localinstallation.Options{Settings: localinstallation.DefaultSettings(socket)})
	if e != nil {
		t.Fatal(e)
	}
	s := DefaultEventSettings([]ObserverSettings{{ID: "audit.private", Types: []string{"dev.pagnet.discover.started", "dev.pagnet.discover.completed"}, Endpoint: sink.URL, AllowPlainHTTP: true, CredentialSelector: "credentials.audit"}})
	if e = InitializeConfiguredEvents(ctx, i, s); e != nil {
		t.Fatal(e)
	}
	root, key := i.Store.AuthorityIdentity(), i.Keys.Reference()
	if e = i.Close(); e != nil {
		t.Fatal(e)
	}
	binary, _ := os.Executable()
	n, e := OpenInstalled(ctx, InstalledConfig{Directory: dir, Binary: binary})
	if e != nil {
		t.Fatal("missing observer provider disabled actual node", e)
	}
	defer n.CloseContext(ctx)
	status := n.Events.ObserverStatus()
	if len(status) != 1 || status[0].ID != "audit.private" || !status[0].MissingCredentialProvider || status[0].ErrorCode != fabric.CodeUnsupported {
		t.Fatal("missing observer diagnostics lost", status)
	}
	client, e := fabricclient.Dial(ctx, socket, fabrichost.Authentication{Type: "fabric.auth", Mode: "owner"})
	if e != nil {
		t.Fatal(e)
	}
	result, e := client.Call(ctx, fabric.OperationDiscover, json.RawMessage(`{"query":"private query","limit":1}`))
	if e != nil || result.IsError {
		t.Fatal("unavailable observation blocked discovery", e)
	}
	if e = client.Close(); e != nil {
		t.Fatal(e)
	}
	// Returning discovery proves only volatile ingress acceptance. Synchronize
	// on an actual FULL delivery retry before closing: volatile shutdown may
	// truthfully discard uncommitted ingress, never call that durable acceptance.
	ticker := time.NewTicker(5 * time.Millisecond)
	for n.Events.workers.Stats().Retried == 0 {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			ticker.Stop()
			t.Fatal("unavailable provider never settled original durable delivery", ctx.Err())
		}
	}
	ticker.Stop()
	if e = n.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
	i, e = localinstallation.Load(ctx, dir, registry.DefaultOptions())
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	if i.Keys.Reference() != key || i.Store.AuthorityIdentity().StoreID != root.StoreID {
		t.Fatal("missing provider replaced original authority/key")
	}
	r, e := OpenInstalledEvents(ctx, i, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer r.CloseContext(ctx)
	state, e := r.Store.State(ctx)
	if e != nil || state.Rows < 1 || state.Acknowledged != 0 {
		t.Fatal("unavailable observer lost or acknowledged events", state, e)
	}
	if sinkCalls.Load() != 0 {
		t.Fatal("named provider silently became credentials.none", sinkCalls.Load())
	}
}
