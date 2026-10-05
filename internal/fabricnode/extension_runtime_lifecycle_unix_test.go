//go:build linux || darwin

package fabricnode

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension/continuation"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/node/dispatch"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// This resource fixture deliberately cannot execute an endpoint. Actual
// effects/action acceptance use the kernel+official SDK tests separately.
type extensionNoEffectResolver struct{}

func (extensionNoEffectResolver) Select(context.Context, fabric.ExecutionContext, fabric.EndpointDescriptor, *fabric.OfferDescriptor) (dispatch.Selection, error) {
	return dispatch.Selection{}, fabric.NewError(fabric.CodeUnsupported, "No endpoint in lifecycle fixture")
}

type extensionCloseBarrier struct {
	unblock   chan struct{}
	calls     atomic.Int32
	failFirst bool
}

func (*extensionCloseBarrier) Next(context.Context) (fabric.InvocationFrame, error) {
	return fabric.InvocationFrame{}, errors.New("resource fixture has no effect")
}
func (s *extensionCloseBarrier) Close() error {
	n := s.calls.Add(1)
	if s.failFirst && n == 1 {
		return errors.New("genuine incomplete resource join fixture")
	}
	<-s.unblock
	return nil
}

func extensionLifecycleRuntime(t *testing.T) (*ExtensionRuntime, *localinstallation.Installation) {
	t.Helper()
	private := t.TempDir()
	if e := os.Chmod(private, 0700); e != nil {
		t.Fatal(e)
	}
	i, e := localinstallation.Bootstrap(t.Context(), filepath.Join(private, "root"), localinstallation.Options{Settings: localinstallation.DefaultSettings(filepath.Join(private, "fabric.sock"))})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { i.Close() })
	owner, e := i.Operator(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	b, e := newLocalBoundary(t.Context(), i.Store, owner, i, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	s := DefaultExtensionSettings()
	s.MaxActiveInvocations = 2
	if e = InitializeExtensionInfrastructure(t.Context(), i, s); e != nil {
		t.Fatal(e)
	}
	r, e := NewExtensionRuntime(t.Context(), i, b, ExtensionRuntimeConfig{Lifetime: t.Context(), Bindings: extensionNoEffectResolver{}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()
		r.Close(ctx)
	})
	return r, i
}

func TestExtensionRuntimeCapacityRetiredBundlesAndCloseDeadlineKeepsWriter(t *testing.T) {
	r, i := extensionLifecycleRuntime(t)
	_, one, _, e := r.begin(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	_, two, _, e := r.begin(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = r.begin(t.Context()); e == nil {
		t.Fatal("unbounded active invocation admission")
	}
	one()
	two()
	one()
	for range 20 {
		if e = r.reload(t.Context()); e != nil {
			t.Fatal(e)
		}
	}
	r.mu.Lock()
	count := len(r.bundles)
	active := r.active
	r.mu.Unlock()
	if count != 1 || active != 0 {
		t.Fatal("retired generation retention grew", count, active)
	}
	_, release, _, e := r.begin(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	barrier := &extensionCloseBarrier{unblock: make(chan struct{})}
	var unblock sync.Once
	defer unblock.Do(func() { close(barrier.unblock) })
	stream := &extensionRuntimeStream{runtime: r, upstream: barrier, release: release}
	r.mu.Lock()
	r.streams[stream] = struct{}{}
	r.mu.Unlock()
	short, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	if e = r.Close(short); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("close fabricated join", e)
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		t.Fatal("unfinished runtime marked closed")
	}
	rootDir, e := i.Store.CurrentAuthorityDirectory(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	if store, e := continuation.Open(t.Context(), filepath.Join(rootDir, "continuations"), continuation.Scope{Audience: r.boundary.root.Namespace}, r.infrastructure.Settings.Continuations, i.Keys); e == nil {
		store.Close()
		t.Fatal("writer released before original stream joined")
	}
	unblock.Do(func() { close(barrier.unblock) })
	finish, cancelFinish := context.WithTimeout(t.Context(), time.Second)
	defer cancelFinish()
	if e = r.Close(finish); e != nil {
		t.Fatal(e)
	}
	if barrier.calls.Load() != 1 {
		t.Fatal("close retry duplicated original stop", barrier.calls.Load())
	}
	store, e := continuation.Open(t.Context(), filepath.Join(rootDir, "continuations"), continuation.Scope{Audience: r.boundary.root.Namespace}, r.infrastructure.Settings.Continuations, i.Keys)
	if e != nil {
		t.Fatal("true join did not release private writer", e)
	}
	store.Close()
}

func TestExtensionRuntimeFailedOriginalJoinCanRetryWithoutSettlement(t *testing.T) {
	r, _ := extensionLifecycleRuntime(t)
	_, release, _, e := r.begin(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	barrier := &extensionCloseBarrier{unblock: make(chan struct{}), failFirst: true}
	var unblock sync.Once
	defer unblock.Do(func() { close(barrier.unblock) })
	stream := &extensionRuntimeStream{runtime: r, upstream: barrier, release: release}
	r.mu.Lock()
	r.streams[stream] = struct{}{}
	r.mu.Unlock()
	if e = r.Close(t.Context()); e == nil {
		t.Fatal("failed stop reported complete")
	}
	r.mu.Lock()
	closed, active := r.closed, r.active
	r.mu.Unlock()
	if closed || active != 1 {
		t.Fatal("failed original join lost resource ownership")
	}
	unblock.Do(func() { close(barrier.unblock) })
	if e = r.Close(t.Context()); e != nil {
		t.Fatal(e)
	}
	if barrier.calls.Load() != 2 {
		t.Fatal("actual join was not retried", barrier.calls.Load())
	}
}

func TestExtensionRuntimeCloseJoinsSourceRegisteredAfterShutdownBegins(t *testing.T) {
	r, _ := extensionLifecycleRuntime(t)
	_, release, _, err := r.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	if err = r.Close(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	barrier := &extensionCloseBarrier{unblock: make(chan struct{})}
	var unblock sync.Once
	defer unblock.Do(func() { close(barrier.unblock) })
	stream := &extensionRuntimeStream{runtime: r, upstream: barrier, release: release}
	r.mu.Lock()
	r.streams[stream] = struct{}{}
	r.pulseLocked()
	r.mu.Unlock()
	unblock.Do(func() { close(barrier.unblock) })
	finish, done := context.WithTimeout(t.Context(), time.Second)
	defer done()
	if err = r.Close(finish); err != nil {
		t.Fatal("late original source was stranded", err)
	}
	if barrier.calls.Load() != 1 {
		t.Fatal("late source stop count", barrier.calls.Load())
	}
}

func TestExtensionRuntimePrivatePlanCaptureExactGenerationAndNoSerialization(t *testing.T) {
	r, i := extensionLifecycleRuntime(t)
	ctx, release, _, err := r.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	selected, ok := SelectedExtensionPlan(ctx)
	if !ok || selected.Revision() == "" || len(selected.PrivateCheckpoint()) == 0 {
		t.Fatal("missing actual selected plan")
	}
	if _, ok := SelectedExtensionPlan(t.Context()); ok {
		t.Fatal("unscoped context gained plan proof")
	}
	if _, err = json.Marshal(selected); err == nil {
		t.Fatal("private plan became wire evidence")
	}
	checkpoint := selected.PrivateCheckpoint()
	checkpoint[0] ^= 1
	if selected.PrivateCheckpoint()[0] == checkpoint[0] {
		t.Fatal("private checkpoint aliased immutable plan")
	}
	owner, err := i.Operator(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	verify := func() error {
		return i.Store.WithNativeAuthority(t.Context(), owner, registry.AuthorityScope{HistoryOnly: true, MaxOperations: 2}, selected.VerifyTx)
	}
	if err = verify(); err != nil {
		t.Fatal(err)
	}
	_, err = r.infrastructure.Profiles.Put(t.Context(), ExtensionProfile{Protocol: extensionHTTPProtocol, URL: "http://127.0.0.1:12345/intercept", CredentialSelector: "operator.test", MaxConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err = verify(); err == nil {
		t.Fatal("changed actual Root purpose generation accepted old selected plan")
	}
}
