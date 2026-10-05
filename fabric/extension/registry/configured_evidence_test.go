//go:build linux || darwin

package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	domain "github.com/pagnet-code/pagnet/fabric/registry"
)

func TestConfiguredSnapshotOwnedEvidenceAndDestinationTransactionFence(t *testing.T) {
	f := fixture(t)
	s, err := Bootstrap(t.Context(), f.owner, f.config)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Install(t.Context(), f.owner, 1, installed("acme.extension"))
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := s.ConfiguredSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = json.Marshal(pinned); err == nil {
		t.Fatal("private evidence serialized")
	}
	ordinary, err := s.Snapshot()
	if err != nil || len(ordinary.evidence) != 0 {
		t.Fatal("ordinary snapshot leaked evidence", err)
	}
	verify := func(revision string, evidence []byte) error {
		return f.config.Root.WithNativeAuthority(t.Context(), f.owner, domain.AuthorityScope{HistoryOnly: true}, func(tx *domain.AuthorityTx) error { return s.VerifyConfiguredPlanTx(tx, revision, evidence) })
	}
	if err = verify(pinned.Plan.Revision(), pinned.Evidence); err != nil {
		t.Fatal(err)
	}
	owned := append([]byte(nil), pinned.Evidence...)
	pinned.Evidence[0] = '!'
	current, err := s.ConfiguredSnapshot()
	if err != nil || !bytes.Equal(current.Evidence, owned) {
		t.Fatal("snapshot input mutation reached stored publication", err)
	}
	if err = verify(current.Plan.Revision(), pinned.Evidence); err == nil {
		t.Fatal("mutated evidence admitted")
	}
	changed := installed("acme.extension")
	changed.Bindings[0].ProfileDigest = hash([]byte("different-provider-profile"))
	if _, err = s.Update(t.Context(), f.owner, 2, first.Revision, changed); err != nil {
		t.Fatal(err)
	}
	if err = verify(current.Plan.Revision(), current.Evidence); err == nil {
		t.Fatal("old configured plan admitted after update")
	}
	latest, err := s.ConfiguredSnapshot()
	if err != nil || latest.Plan.Revision() == current.Plan.Revision() {
		t.Fatal("configured revision not changed", err)
	}
	if err = verify(latest.Plan.Revision(), latest.Evidence); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredPlanFenceConstantWorkAtFiveHundredInterceptors(t *testing.T) {
	f := fixture(t)
	s, err := Bootstrap(t.Context(), f.owner, f.config)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		input := installed(fmt.Sprintf("scale.extension%d", i))
		base := input.Manifest.Interceptors[0]
		input.Manifest.Interceptors = nil
		for j := 0; j < 50; j++ {
			r := base
			r.ID = fmt.Sprintf("scale.extension%d.interceptor%d", i, j)
			input.Manifest.Interceptors = append(input.Manifest.Interceptors, r)
		}
		if _, err = s.Install(t.Context(), f.owner, uint64(i+1), input); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := s.ConfiguredSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	verify := func() error {
		return f.config.Root.WithNativeAuthority(t.Context(), f.owner, domain.AuthorityScope{HistoryOnly: true, MaxOperations: 2}, func(tx *domain.AuthorityTx) error {
			return s.VerifyConfiguredPlanTx(tx, snapshot.Plan.Revision(), snapshot.Evidence)
		})
	}
	if err = verify(); err != nil {
		t.Fatal("500 interceptor verification exceeded two signed point reads", err)
	}
	ref := s.ordered[0]
	if err = f.config.Root.WithNativeAuthority(t.Context(), f.owner, scope(f.config), func(tx *domain.AuthorityTx) error {
		row, e := tx.Get(key(ref.PhysicalID))
		if e != nil {
			return e
		}
		_, e = tx.CAS(key(ref.PhysicalID), row.Revision, []byte(`{"standalone":"different"}`), false)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = verify(); err == nil {
		t.Fatal("standalone entry CAS bypassed directory fence")
	}
}
