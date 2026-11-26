//go:build linux || darwin

package sessionworker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/transport"
)

func directASKFixture(t *testing.T) (*SessionOwner, int64, nativedirect.NativeDirectASKSource, json.RawMessage, NativeSnapshot, time.Time) {
	t.Helper()
	j, _ := testJournal(t)
	l := lease(t, j)
	ownership := dispatchOwnership(t, j, l)
	snapshot := verificationSnapshot(t, j, ownership)
	now := time.Now().UTC()
	binary := func(n int) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, n)) }
	id := uuid.NewString()
	epoch, _ := uuid.NewV7()
	w := transport.DirectChannelMessageV2{Header: transport.DirectChannelMessageHeaderV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/message", Kind: "ASK", ChannelID: binary(32), DescriptorHash: binary(32), EpochID: epoch.String(), MessageID: id, RootID: id, SenderRole: "S"}, Nonce: binary(12), Ciphertext: binary(16)}
	wire, err := w.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := transport.DirectChannelMessageHashV2(w)
	party := func(role string) transport.DirectDeliveryPartyV2 {
		return transport.DirectDeliveryPartyV2{Role: role, PrincipalID: uuid.NewString(), EndpointID: uuid.NewString(), CredentialID: uuid.NewString()}
	}
	r := transport.DirectMessageAdmissionReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/admission", AdmissionState: "admitted", AdmittedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano), Binding: transport.DirectMessageBindingV2{Context: transport.DirectDeliveryContextV2{ChannelID: w.Header.ChannelID, DescriptorHash: w.Header.DescriptorHash, PublicationHash: binary(32), ParentGrantID: uuid.NewString(), GrantGeneration: "1"}, MessageID: id, WireHash: hash, WireBytes: len(wire), Sender: party("S"), Recipient: party("P")}}
	s := nativedirect.NativeDirectASKSource{Protocol: nativedirect.Protocol, AdmissionID: uuid.NewString(), ServerOrigin: j.scope.ServerURL, Scope: j.scope, Ownership: ownership, NativeSessionID: snapshot.NativeSessionID, NativeGeneration: snapshot.NativeGeneration, NativeStartIdentity: snapshot.NativeStartIdentity, NativePID: snapshot.PID, EndpointIssueID: "issue", EndpointLeaseID: "lease", EndpointGeneration: "1", ConsentRevision: 1, Receipt: r, InputDigest: strings.Repeat("b", 64), Deadline: now.Add(time.Hour)}
	if err := s.ValidateWire(wire); err != nil {
		t.Fatal(err)
	}
	return &SessionOwner{journal: j}, l, s, wire, snapshot, now
}

func TestDirectASKControllerAndPhysicalFences(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	c := &directASKController{owner: o, lease: l}
	for name, controller := range map[string]*directASKController{
		"missing": nil, "foreign": {owner: &SessionOwner{journal: o.journal}, lease: l}, "zero-lease": {owner: o}, "wrong-lease": {owner: o, lease: l + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := o.directASK(t.Context(), controller, s, wire, true, now, func() NativeSnapshot { t.Fatal("bad controller reached snapshot"); return snap }); err == nil {
				t.Fatal("accepted unauthenticated controller")
			}
		})
	}
	for name, mutate := range map[string]func(*NativeSnapshot){
		"session":    func(s *NativeSnapshot) { s.NativeSessionID = "other" },
		"generation": func(s *NativeSnapshot) { s.NativeGeneration = "other" },
		"start":      func(s *NativeSnapshot) { s.NativeStartIdentity = "other" },
		"pending":    func(s *NativeSnapshot) { s.IdentityPending = true },
		"pid":        func(s *NativeSnapshot) { s.PID = 0 },
		"profile":    func(s *NativeSnapshot) { s.ProfileFingerprint = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := snap
			mutate(&bad)
			if _, err := o.directASK(t.Context(), c, s, wire, true, now, func() NativeSnapshot { return bad }); err == nil {
				t.Fatal("accepted changed physical identity")
			}
		})
	}
	if _, err := o.directASK(t.Context(), c, s, wire, true, s.Deadline, func() NativeSnapshot { t.Fatal("expired source reached snapshot"); return snap }); err == nil {
		t.Fatal("accepted expired source")
	}
	if _, err := o.directASK(t.Context(), c, s, wire, true, now, func() NativeSnapshot { lease(t, o.journal); return snap }); err == nil {
		t.Fatal("accepted lease replaced during snapshot")
	}
}

func TestDirectASKExactDedupConflictAndConcurrency(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	c := &directASKController{owner: o, lease: l}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			r, err := o.directASK(t.Context(), c, s, wire, true, now, func() NativeSnapshot { return snap })
			if err != nil || r == nil || r.State != "reserved" {
				t.Errorf("reserve: %v %v", r, err)
			}
		})
	}
	wg.Wait()
	for name, mutate := range map[string]func(*nativedirect.NativeDirectASKSource){
		"admission":           func(s *nativedirect.NativeDirectASKSource) { s.AdmissionID = uuid.NewString() },
		"input":               func(s *nativedirect.NativeDirectASKSource) { s.InputDigest = strings.Repeat("c", 64) },
		"endpoint-generation": func(s *nativedirect.NativeDirectASKSource) { s.EndpointGeneration = "2" },
		"publication": func(s *nativedirect.NativeDirectASKSource) {
			s.Receipt.Binding.Context.ParentGrantID = uuid.NewString()
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			mutate(&changed)
			if _, err := o.directASK(t.Context(), c, changed, wire, true, now, func() NativeSnapshot { return snap }); !errors.Is(err, ErrConflict) {
				t.Fatalf("conflict: %v", err)
			}
		})
	}
	var count, next, dispatch int
	if err := o.journal.db.QueryRow(`SELECT (SELECT count(*) FROM worker_direct_admissions),next_sequence,(SELECT count(*) FROM worker_dispatches) FROM worker_meta`).Scan(&count, &next, &dispatch); err != nil || count != 1 || next != 1 || dispatch != 0 {
		t.Fatalf("reservation touched Cloud execution: %d %d %d %v", count, next, dispatch, err)
	}
}

func TestDirectASKLostResponseLookupAndReopenUnknown(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	c := &directASKController{owner: o, lease: l}
	if r, err := o.directASK(t.Context(), c, s, wire, false, now, func() NativeSnapshot { return snap }); err != nil || r != nil {
		t.Fatalf("missing lookup: %v %v", r, err)
	}
	if _, err := o.directASK(t.Context(), c, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	r, err := o.directASK(t.Context(), c, s, wire, false, now, func() NativeSnapshot { return snap })
	if err != nil || r == nil || r.State != "reserved" {
		t.Fatalf("lost response lookup: %v %v", r, err)
	}
	dir := o.journal.dir
	if err := o.journal.Close(); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir, s.Scope)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	o.journal = j
	c = &directASKController{owner: o, lease: lease(t, j)}
	later := s.Deadline.Add(time.Minute)
	r, err = o.directASK(t.Context(), c, s, wire, false, later, func() NativeSnapshot { return snap })
	if err != nil || r == nil || r.State != "unknown" {
		t.Fatalf("reopen status: %v %v", r, err)
	}
	if _, err := o.directASK(t.Context(), c, s, wire, false, later, func() NativeSnapshot {
		replaced := snap
		replaced.NativeStartIdentity = "replacement-process"
		return replaced
	}); err == nil {
		t.Fatal("replacement process recovered original reservation")
	}
	retired := s.Ownership
	retired.State = "retired"
	if err := j.CommitOwnershipRetirement(t.Context(), c.lease, retired); err != nil {
		t.Fatal(err)
	}
	if _, err := o.directASK(t.Context(), c, s, wire, false, later, func() NativeSnapshot { return snap }); err == nil {
		t.Fatal("retired ownership status accepted")
	}
}

func TestDirectASKReopenRejectsNoncanonicalHistory(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	c := &directASKController{owner: o, lease: l}
	if _, err := o.directASK(t.Context(), c, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal(err)
	}
	if _, err := o.journal.db.Exec(`UPDATE worker_direct_admissions SET record=CAST(' ' || CAST(record AS TEXT) AS BLOB)`); err != nil {
		t.Fatal(err)
	}
	dir := o.journal.dir
	if err := o.journal.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenJournal(dir, s.Scope); err == nil {
		reopened.Close()
		t.Fatal("reopened noncanonical reservation history")
	}
}

func TestDirectASKSourceAndWireValidation(t *testing.T) {
	o, l, s, wire, snap, now := directASKFixture(t)
	c := &directASKController{owner: o, lease: l}
	for name, mutate := range map[string]func(*nativedirect.NativeDirectASKSource){
		"protocol": func(s *nativedirect.NativeDirectASKSource) { s.Protocol = "cloud" },
		"origin":   func(s *nativedirect.NativeDirectASKSource) { s.ServerOrigin = "https://other.invalid" },
		"scope":    func(s *nativedirect.NativeDirectASKSource) { s.Scope.Generation = "other" },
		"deadline": func(s *nativedirect.NativeDirectASKSource) { s.Deadline = s.Deadline.Add(time.Second) },
		"ordinal":  func(s *nativedirect.NativeDirectASKSource) { s.Ownership.LastDispatchSequence = 1 },
		"bound":    func(s *nativedirect.NativeDirectASKSource) { s.AdmissionID = strings.Repeat("a", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := s
			mutate(&changed)
			if _, err := o.directASK(t.Context(), c, changed, wire, true, now, func() NativeSnapshot { t.Fatal("invalid source reached snapshot"); return snap }); err == nil {
				t.Fatal("accepted invalid source")
			}
		})
	}
	if _, err := o.directASK(t.Context(), c, s, append([]byte(" "), wire...), true, now, func() NativeSnapshot { return snap }); err == nil {
		t.Fatal("accepted noncanonical wire")
	}
	newLease := lease(t, o.journal)
	if _, err := o.directASK(t.Context(), c, s, wire, true, now, func() NativeSnapshot { return snap }); err == nil {
		t.Fatal("old controller admitted reservation")
	}
	c = &directASKController{owner: o, lease: newLease}
	if _, err := o.directASK(t.Context(), c, s, wire, true, now, func() NativeSnapshot { return snap }); err != nil {
		t.Fatal("fresh controller rejected", err)
	}
}
