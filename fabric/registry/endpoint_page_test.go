package registry

import (
	"github.com/pagnet-code/pagnet/fabric"
	"testing"
)

func TestPrivateEndpointHeadsPageKeepsRetirementAndSnapshot(t *testing.T) {
	s, owner, _ := fixture(t)
	for range 4 {
		d := endpoint(t, s)
		if _, err := s.Register(t.Context(), owner, fabric.RegistryUpdate{Descriptor: d}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.ListEndpointHeads(t.Context(), owner, "", 2)
	if err != nil || len(first.Heads) != 2 || first.NextCursor == "" {
		t.Fatal("bounded page", err)
	}
	second, err := s.ListEndpointHeads(t.Context(), owner, first.NextCursor, 2)
	if err != nil || len(second.Heads) != 2 || second.NextCursor != "" {
		t.Fatal("next page", err)
	}
	if _, err = s.Retire(t.Context(), owner, first.Heads[0].Ref, first.Heads[0].Revision); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ListEndpointHeads(t.Context(), owner, first.NextCursor, 2); err == nil {
		t.Fatal("changed snapshot accepted")
	}
	all, err := s.ListEndpointHeads(t.Context(), owner, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	retired := 0
	for _, head := range all.Heads {
		if head.Retired {
			retired++
		}
	}
	if len(all.Heads) != 4 || retired != 1 {
		t.Fatal("retired worker hidden from startup classification", all)
	}
	if _, err = s.ListEndpointHeads(t.Context(), fabric.ExecutionContext{}, "", 2); err == nil {
		t.Fatal("private enumeration without actual owner")
	}
}
