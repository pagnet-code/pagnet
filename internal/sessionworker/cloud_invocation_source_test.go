//go:build linux || darwin

package sessionworker

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestCloudInvocationSourceOriginalIndexedLookupNotificationAndRestart(t *testing.T) {
	scope := testScope()
	scope.TenantID = uuid.NewString()
	scope.HostID = uuid.NewString()
	scope.InstanceID = uuid.NewString()
	dir := filepath.Join(t.TempDir(), "worker")
	j, e := OpenJournal(dir, scope)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = j.Close() }()
	current := lease(t, j)
	network := uuid.NewString()
	cmd, admission := uuid.NewString(), uuid.NewString()
	inv := transport.NativeInvocationSource{InvocationID: "stable-original-invocation", InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: scope.TenantID, NetworkID: network, ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: "stable-original-invocation", KeyEpochID: "original-key"}}
	grant := &Admission{NativeAdmissionID: admission, Scope: scope, TenantID: scope.TenantID, NetworkID: network, Kind: "worker", RunnerID: uuid.NewString(), RunnerEpoch: time.Now().UTC(), BootID: uuid.NewString()}
	op := Operation{Input: "real original input", InputKind: "invocation", SourceCommandID: cmd, SourceAdmissionID: admission, SourceInvocation: &inv}
	raw, _ := json.Marshal(op)
	if _, run, e := j.admit(t.Context(), current, 1, cmd, "prompt", raw, func() (*Admission, error) { return grant, nil }); e != nil || !run {
		t.Fatal("original admission", run, e)
	}
	request := CloudInvocationSourceRequest{1, cmd, admission, inv}
	pending, e := j.cloudInvocationSource(t.Context(), current, request)
	if e != nil || pending.Source != nil || !pending.Ready.valid() {
		t.Fatal("pending genuine source", pending, e)
	}
	wake := make(chan ReadinessToken, 1)
	go func() { token, _ := j.cloudReadiness.wait(t.Context(), pending.Ready); wake <- token }()
	source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "actual-original-generation", NativeSessionID: "actual-original-SID", SourceCommandID: cmd, SourceAdmissionID: admission, InputKind: "invocation", SourceInvocation: &inv}
	if e = j.BindNativeTurn(t.Context(), source); e != nil {
		t.Fatal(e)
	}
	select {
	case token := <-wake:
		if token == pending.Ready {
			t.Fatal("source commit missed notification")
		}
	case <-time.After(time.Second):
		t.Fatal("source commit did not notify")
	}
	found, e := j.cloudInvocationSource(t.Context(), current, request)
	if e != nil || !reflect.DeepEqual(found.Source, &source) {
		t.Fatal("original source relabelled", found, e)
	}
	changed := request
	changed.Invocation.InputAAD.KeyEpochID = "new-key"
	if _, e = j.cloudInvocationSource(t.Context(), current, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("replaced crypto source accepted", e)
	}
	changed = request
	changed.CommandID = uuid.NewString()
	if _, e = j.cloudInvocationSource(t.Context(), current, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("forged command accepted", e)
	}
	second := lease(t, j)
	if _, e = j.cloudInvocationSource(t.Context(), current, request); !errors.Is(e, ErrFenced) {
		t.Fatal("old controller read original source", e)
	}
	if found, e = j.cloudInvocationSource(t.Context(), second, request); e != nil || !reflect.DeepEqual(found.Source, &source) {
		t.Fatal("replacement lost original source", e)
	}
	boot := found.Ready.Boot
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = OpenJournal(dir, scope)
	if e != nil {
		t.Fatal(e)
	}
	third := lease(t, j)
	found, e = j.cloudInvocationSource(t.Context(), third, request)
	if e != nil || !reflect.DeepEqual(found.Source, &source) || found.Ready.Boot == boot {
		t.Fatal("restart inferred/replaced source or readiness boot", found, e)
	}
	var detail string
	rows, e := j.db.QueryContext(t.Context(), `EXPLAIN QUERY PLAN SELECT sequence FROM worker_turn_sources WHERE sequence=? AND source_command=? AND source_admission=? LIMIT 2`, 1, cmd, admission)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b, c int
		if e = rows.Scan(&a, &b, &c, &detail); e != nil {
			t.Fatal(e)
		}
	}
	if detail != "SEARCH worker_turn_sources USING COVERING INDEX worker_turn_original_invocation (sequence=? AND source_command=? AND source_admission=?)" {
		t.Fatal("source lookup is not indexed", detail)
	}
}

func TestCloudReadinessNotificationCancellationLeavesPrimaryLeaseCurrent(t *testing.T) {
	j, dir := testJournal(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, j, key, func(Outcome, json.RawMessage) {}) }()
	var controller *Controller
	var e error
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		controller, e = DialController(t.Context(), dir, j.scope, key, "actual-controller")
		if e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer controller.Close()
	wait, cancelWait := context.WithCancel(t.Context())
	waiting := make(chan error, 1)
	token := j.cloudReadiness.snapshot()
	go func() { _, e := controller.WaitCloudReady(wait, dir, j.scope, key, token); waiting <- e }()
	cancelWait()
	select {
	case e = <-waiting:
		if !errors.Is(e, context.Canceled) {
			t.Fatal("wait cancellation", e)
		}
	case <-time.After(time.Second):
		t.Fatal("wait retained abandoned socket")
	}
	reply, e := controller.Call(t.Context(), Request{Type: "outcome", Sequence: 1})
	if e != nil {
		t.Fatal("cancelled auxiliary notification broke primary", e)
	}
	_ = reply
	notify := make(chan ReadinessToken, 1)
	go func() { r, _ := controller.WaitCloudReady(t.Context(), dir, j.scope, key, token); notify <- r }()
	j.cloudReadiness.pulse()
	select {
	case r := <-notify:
		if r == token || !r.valid() {
			t.Fatal("notification not authenticated/changed", r)
		}
	case <-time.After(time.Second):
		t.Fatal("auxiliary channel missed committed change")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker auxiliary channels leaked on shutdown")
	}
}

func TestCloudRepresentativeSourceKeepsOriginalAccountAndSelectedNetworkDistinct(t *testing.T) {
	for _, kind := range []string{"representative", "worker", "fixed-network-worker"} {
		t.Run(kind, func(t *testing.T) {
			scope := testScope()
			scope.TenantID = uuid.NewString()
			scope.InstanceID = uuid.NewString()
			j, e := OpenJournal(filepath.Join(t.TempDir(), "worker"), scope)
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			current := lease(t, j)
			command, admission := uuid.NewString(), uuid.NewString()
			inv := transport.NativeInvocationSource{InvocationID: "selected-original-network", InputAAD: e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: uuid.NewString(), NetworkID: uuid.NewString(), ObjectType: e2ee.ObjectTypeInvocationInput, ObjectID: "selected-original-network", KeyEpochID: "selected-network-original-key"}}
			grant := &Admission{NativeAdmissionID: admission, Scope: scope, TenantID: scope.TenantID, Kind: kind, RunnerID: uuid.NewString(), RunnerEpoch: time.Now().UTC(), BootID: uuid.NewString()}
			if kind == "fixed-network-worker" {
				grant.Kind = "worker"
				grant.NetworkID = inv.InputAAD.NetworkID
			}
			raw, _ := json.Marshal(Operation{Input: "original selected request", InputKind: "invocation", SourceCommandID: command, SourceAdmissionID: admission, SourceInvocation: &inv})
			if _, run, e := j.admit(t.Context(), current, 1, command, "prompt", raw, func() (*Admission, error) { return grant, nil }); e != nil || !run {
				t.Fatal(run, e)
			}
			source := NativeTurnSource{Sequence: 1, LogicalTurnID: logicalWorkerTurn(1), NativeGeneration: "genuine-representative-generation", NativeSessionID: "genuine-representative-SID", SourceCommandID: command, SourceAdmissionID: admission, InputKind: "invocation", SourceInvocation: &inv}
			if e = j.BindNativeTurn(t.Context(), source); e != nil {
				t.Fatal(e)
			}
			got, e := j.cloudInvocationSource(t.Context(), current, CloudInvocationSourceRequest{1, command, admission, inv})
			if kind == "worker" {
				if !errors.Is(e, ErrConflict) {
					t.Fatal("networkless ordinary worker gained source disclosure", e)
				}
				return
			}
			if e != nil || !reflect.DeepEqual(got.Source, &source) {
				t.Fatal("representative original account was relabelled to selected network", got, e)
			}
		})
	}
}
