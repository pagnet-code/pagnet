//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeCancellationActualBackendLostReplyAndOriginalWorkerFence(t *testing.T) {
	t.Setenv("PAGNET_NATIVE_SOURCE_HELPER_RUNTIME", string(domain.RuntimeFakePersistent))
	helper, fixture := startNativeBackendHelper(t)
	a := connectNativeBackend(t, fixture, false)
	scope := sessionworker.Scope{ServerURL: a.connection.serverURL, TenantID: a.session.TenantID, AccountID: a.session.AccountID, HostID: fixture.HostID, InstanceID: fixture.InstanceID, Generation: domain.NewID().String()}
	spec := sessionworker.NativeSpec{Runtime: domain.RuntimeName(fixture.Runtime), Binary: "/bin/true", MCPExecutable: "/bin/true", Workspace: t.TempDir(), Kind: "worker", TenantID: scope.TenantID, NetworkID: fixture.NetworkID, NetworkTenantID: fixture.TenantID}
	original, err := a.connection.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", "")
	if err != nil {
		t.Fatal("actual original ownership registration failed", err)
	}
	dir := filepath.Join(t.TempDir(), "worker")
	key := bytes.Repeat([]byte{23}, 32)
	if err = sessionworker.PrepareBootstrap(dir, sessionworker.Bootstrap{Protocol: sessionworker.Protocol, Scope: scope, Native: spec}, key); err != nil {
		t.Fatal(err)
	}
	journal, err := sessionworker.OpenJournal(dir, scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	owner, err := sessionworker.NewSessionOwner(t.Context(), journal, spec, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	ownerCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = sessionworker.ServeOwner(ownerCtx, owner, key, "original-worker") }()
	var proxy *NativeWorkerProxy
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		proxy, err = AttachNativeWorker(t.Context(), a.connection, dir, scope, "controller-A")
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal("actual original worker attachment failed", err)
	}
	defer proxy.Close()
	if err = proxy.BindOwnership(t.Context(), *original); err != nil {
		t.Fatal(err)
	}
	var seeded struct {
		NativeDispatch *transport.NativeDispatchProof `json:"nativeDispatch"`
	}
	helper.call(t, map[string]any{"action": "seed_pending_cancel", "runnerId": a.session.RunnerID, "runnerEpoch": a.session.RunnerEpoch, "bootId": a.session.BootID, "nativeAdmissionId": a.session.NativeAdmissionID}, &seeded)
	if seeded.NativeDispatch == nil {
		t.Fatal("actual server supplied no cancelled original ordinal")
	}
	page, err := a.connection.DispatchCancellationProposals(t.Context(), *original, 0)
	if err != nil || len(page.Proposals) != 1 || !reflect.DeepEqual(page.Proposals[0].Proof, *seeded.NativeDispatch) {
		t.Fatal("actual cancellation proposal mismatch", err)
	}
	prepared, err := proxy.call(t.Context(), sessionworker.Request{Type: "cancel_prepare", CancelProposal: &page.Proposals[0]})
	if err != nil || prepared.Cancellation == nil {
		t.Fatal("original worker failed durable preparation", err)
	}
	request := prepared.Cancellation.Request
	a.dropCancellationID.Store(&request.RequestID)
	shortCtx, shortCancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	_, err = a.connection.CommitDispatchCancellation(shortCtx, request)
	shortCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lost actual commit reply was treated as acknowledged", err)
	}
	// The server COMMIT is real, but its lost response must leave the worker
	// ordinal prepared rather than finalized or eligible for a native operation.
	rows, err := proxy.call(t.Context(), sessionworker.Request{Type: "dispatches"})
	if err != nil || len(rows.Dispatches) != 0 {
		t.Fatal("lost cancellation reply advanced local history", err)
	}
	payload, _ := json.Marshal(sessionworker.Operation{Input: "must never execute", InputKind: "task"})
	response, err := proxy.call(t.Context(), sessionworker.Request{Type: "dispatch", CommandID: seeded.NativeDispatch.SourceCommandID, Kind: "prompt", Payload: payload, NativeDispatch: seeded.NativeDispatch})
	if err == nil || response.Outcome != nil {
		t.Fatal("prepared cancellation allowed native submission")
	}
	_ = proxy.Close()
	a.connection.Close()
	_ = a.socket.Close()
	<-a.done
	b := connectNativeBackend(t, fixture, false)
	replacement, err := b.connection.RegisterNativeWorkerOwnership(t.Context(), scope, spec, "", original.ID)
	if err != nil || replacement.ID != original.ID {
		t.Fatal("fresh controller replaced original ownership", err)
	}
	proxy, err = AttachNativeWorker(t.Context(), b.connection, dir, scope, "controller-B")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if err = proxy.BindOwnership(t.Context(), *replacement); err != nil {
		t.Fatal(err)
	}
	committed, err := b.connection.CommitDispatchCancellation(t.Context(), request)
	if err != nil || committed.Disposition != "cancelled" || committed.Proof == nil || !reflect.DeepEqual(*committed.Proof, *seeded.NativeDispatch) {
		t.Fatal("actual original commit replay mismatch", err)
	}
	wrong := committed
	wrong.PreparationID = domain.NewID().String()
	if _, err = proxy.call(t.Context(), sessionworker.Request{Type: "cancel_finalize", CancelReceipt: &wrong}); err == nil {
		t.Fatal("foreign preparation finalized original ordinal")
	}
	if _, err = proxy.call(t.Context(), sessionworker.Request{Type: "cancel_finalize", CancelReceipt: &committed}); err != nil {
		t.Fatal("matching genuine commit did not finalize", err)
	}
	snapshot, err := proxy.Snapshot(t.Context())
	if err != nil || snapshot.PID != 0 || snapshot.IdentityPending || snapshot.HasTerminal {
		t.Fatal("cancellation launched native runtime", err)
	}
	settled, err := proxy.SettleDispatches(t.Context(), *replacement)
	if err != nil || settled.RetiredFloor != seeded.NativeDispatch.DispatchSequence {
		t.Fatal("actual settled cancellation could not retire contiguous floor", err)
	}
	rows, err = proxy.call(t.Context(), sessionworker.Request{Type: "dispatches"})
	if err != nil || len(rows.Dispatches) != 0 {
		t.Fatal("retired cancellation leaks lifetime journal entries", err)
	}
}
