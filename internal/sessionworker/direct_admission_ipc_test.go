//go:build linux || darwin

package sessionworker

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/transport"
)

func TestDirectASKAuthenticatedIPCRoundtrip(t *testing.T) {
	var ownership transport.NativeWorkerOwnership
	f := newSideportOwnerFixture(t, func(f *sideportOwnerFixture) {
		j := f.owner.journal
		ownership = transport.NativeWorkerOwnership{ID: uuid.NewString(), InstanceID: j.scope.InstanceID, OwnershipGeneration: j.scope.Generation, Runtime: string(f.owner.spec.Runtime), ProfileFingerprint: NativeProfileFingerprint(f.owner.spec), OriginalAdmissionID: uuid.NewString(), State: "active"}
		if err := j.BindDispatchOwnership(t.Context(), f.controller.Lease, ownership, ownership.Runtime, ownership.ProfileFingerprint); err != nil {
			t.Fatal(err)
		}
	})
	j := f.owner.journal
	_, _, source, wire, _, _ := directASKFixture(t)
	snap := f.owner.physicalSnapshot()
	source.Scope, source.ServerOrigin, source.Ownership = j.scope, j.scope.ServerURL, ownership
	source.NativeSessionID, source.NativeGeneration, source.NativeStartIdentity, source.NativePID = snap.NativeSessionID, snap.NativeGeneration, snap.NativeStartIdentity, snap.PID
	request := &DirectASKRequest{Source: source, Wire: wire}
	var before int64
	err := j.db.QueryRow(`SELECT next_sequence FROM worker_meta`).Scan(&before)
	if err != nil {
		t.Fatal(err)
	}
	missing := f.call(t, Request{Type: "direct_ask_lookup_v1", DirectASK: request})
	if missing.Error != "" || missing.DirectASK == nil || missing.DirectASK.Found || missing.DirectASK.Reservation != nil {
		t.Fatalf("missing: %+v", missing)
	}
	reserved := f.call(t, Request{Type: "direct_ask_reserve_v1", DirectASK: request})
	if reserved.Error != "" || reserved.DirectASK == nil || !reserved.DirectASK.Found || reserved.DirectASK.Reservation == nil || reserved.DirectASK.Reservation.State != "reserved" {
		t.Fatalf("reserve: %+v", reserved)
	}
	// A caller that loses the first response recovers exact provenance by lookup.
	recovered := f.call(t, Request{Type: "direct_ask_lookup_v1", DirectASK: request})
	a, _ := json.Marshal(reserved.DirectASK)
	b, _ := json.Marshal(recovered.DirectASK)
	if recovered.Error != "" || string(a) != string(b) {
		t.Fatalf("lookup changed result: %+v", recovered)
	}
	for name, mutate := range map[string]func(*DirectASKRequest){
		"scope":     func(r *DirectASKRequest) { r.Source.Scope.AccountID = "other" },
		"ownership": func(r *DirectASKRequest) { r.Source.Ownership.ID = uuid.NewString() },
		"physical":  func(r *DirectASKRequest) { r.Source.NativeStartIdentity = "other" },
		"wire":      func(r *DirectASKRequest) { r.Wire = json.RawMessage(`{}`) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *request
			mutate(&bad)
			r := f.call(t, Request{Type: "direct_ask_reserve_v1", DirectASK: &bad})
			if r.Error == "" || r.DirectASK != nil {
				t.Fatalf("accepted changed provenance: %+v", r)
			}
		})
	}
	if r := f.call(t, Request{Type: "direct_ask_reserve_v1"}); r.Error == "" || r.DirectASK != nil {
		t.Fatal("missing request accepted")
	}
	// Internal request routing alone cannot mint the connection capability.
	if r := f.owner.controllerRequest(t.Context(), f.controller.Lease, Request{Type: "direct_ask_reserve_v1", DirectASK: request}); r.Error == "" {
		t.Fatal("unauthenticated routing minted authority")
	}
	var after int64
	err = j.db.QueryRow(`SELECT next_sequence FROM worker_meta`).Scan(&after)
	var dispatches int
	if e := j.db.QueryRow(`SELECT count(*) FROM worker_dispatches`).Scan(&dispatches); e != nil {
		t.Fatal(e)
	}
	if err != nil || before != after || dispatches != 1 {
		t.Fatalf("direct RPC affected Cloud sequence: %d %d %d %v", before, after, dispatches, err)
	}
	if r := f.owner.controllerRequestAuthenticated(t.Context(), f.controller.Lease+1, Request{Type: "direct_ask_lookup_v1", DirectASK: request}, &directASKController{owner: f.owner, lease: f.controller.Lease}); r.Error == "" {
		t.Fatal("stale capability accepted")
	}
}

func TestDirectASKResultRequiresExplicitAbsence(t *testing.T) {
	for _, raw := range []string{`{}`, `{"found":null}`, `{"found":"false"}`, `{"found":false,"extra":1}`} {
		var response Response
		if err := json.Unmarshal([]byte(`{"directASK":`+raw+`}`), &response); err == nil {
			t.Fatalf("accepted malformed result: %s", raw)
		}
	}
	var response Response
	if err := json.Unmarshal([]byte(`{"directASK":{"found":false}}`), &response); err != nil || response.DirectASK == nil || response.DirectASK.Found {
		t.Fatalf("explicit absence: %+v %v", response, err)
	}
}
