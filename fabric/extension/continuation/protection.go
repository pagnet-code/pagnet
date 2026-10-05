package continuation

import (
	"bytes"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric/events/durable"
)

const maxSealOverhead = 64 << 10

type protectedIdentity struct {
	Format uint32               `json:"format"`
	Scope  Scope                `json:"scope"`
	Key    durable.KeyReference `json:"key"`
	Proof  []byte               `json:"proof"`
}

func (s *Store) protectionAAD(purpose, id string) []byte {
	raw, _ := json.Marshal(struct {
		Format, Purpose, Audience, ID string
		Key                           durable.KeyReference
	}{"pagnet.continuation.private.v3", purpose, s.scope.Audience, id, s.keyRef})
	return raw
}
func (s *Store) sealBlob(purpose, id string, plain []byte, max int) ([]byte, error) {
	if len(plain) > max {
		return nil, internal()
	}
	cipher, err := s.protector.Seal(s.protectionAAD(purpose, id), plain)
	if err != nil || len(cipher) == 0 || len(cipher) > len(plain)+maxSealOverhead {
		return nil, internal()
	}
	return cipher, nil
}
func (s *Store) openBlob(purpose, id string, cipher []byte, max int) ([]byte, error) {
	if len(cipher) == 0 || len(cipher) > max+maxSealOverhead {
		return nil, internal()
	}
	plain, err := s.protector.Open(s.protectionAAD(purpose, id), cipher)
	if err != nil || len(plain) > max {
		return nil, internal()
	}
	return plain, nil
}
func (s *Store) sealIdentity() ([]byte, error) {
	proof, err := s.sealBlob("identity", "configuration", []byte("pagnet.continuation.identity.v3"), 64)
	if err != nil {
		return nil, err
	}
	return json.Marshal(protectedIdentity{3, s.scope, s.keyRef, proof})
}
func (s *Store) verifyIdentity(raw []byte) error {
	var pin protectedIdentity
	if decode(raw, &pin, maxSealOverhead+1024) != nil || pin.Format != 3 || pin.Scope != s.scope || pin.Key != s.keyRef {
		return internal()
	}
	plain, err := s.openBlob("identity", "configuration", pin.Proof, 64)
	if err != nil || !bytes.Equal(plain, []byte("pagnet.continuation.identity.v3")) {
		return internal()
	}
	return nil
}
func (s *Store) openRow(id string, r *row) error {
	var err error
	if r.snapshot, err = s.openBlob("snapshot", id, r.snapshot, s.options.MaxSnapshotBytes); err != nil {
		return err
	}
	if digest(r.snapshot) != r.digest {
		return internal()
	}
	if len(r.receipt) != 0 {
		if r.receipt, err = s.openBlob("receipt", id, r.receipt, 16384); err != nil {
			return err
		}
	}
	if len(r.outcome) != 0 {
		if r.outcome, err = s.openBlob("outcome", id, r.outcome, s.options.MaxOutcomeBytes); err != nil {
			return err
		}
	}
	return nil
}
