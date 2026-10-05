package registry

import (
	"bytes"
	"crypto/sha256"

	domain "github.com/pagnet-code/pagnet/fabric/registry"
)

// VerifyConfiguredPlanTx consumes the immutable preflight snapshot against
// actual signed configuration rows in the destination root transaction. It
// performs no protector I/O, decryption, provider call or Store.mu acquisition.
// Holding the root transaction prevents configuration CAS until its commit.
func (s *Store) VerifyConfiguredPlanTx(tx *domain.AuthorityTx, revision string, evidence []byte) error {
	if s == nil || tx == nil {
		return failure()
	}
	snapshot := s.snapshot.Load()
	if snapshot == nil || snapshot.Plan == nil || snapshot.Plan.Revision() != revision || !bytes.Equal(snapshot.evidence, evidence) {
		return conflict()
	}
	directory, err := tx.Get(key(directoryID))
	if err != nil {
		return err
	}
	if domain.VerifyAuthorityRecord(s.identity, directory) != nil {
		return conflict()
	}
	if directory.Namespace != s.identity.Namespace || directory.StoreID != s.identity.StoreID || directory.KeyRevision != s.identity.KeyRevision || directory.Retired || directory.Revision != snapshot.Generation {
		return conflict()
	}
	if sha256.Sum256(directory.Value) != snapshot.directoryDigest {
		return conflict()
	}
	purpose, err := tx.ExtensionPurposeGeneration()
	if err != nil {
		return err
	}
	if purpose.Sequence != snapshot.purpose.Sequence || purpose.Revision != snapshot.purpose.Revision || !bytes.Equal(purpose.Signature, snapshot.purpose.Signature) {
		return conflict()
	}

	return nil
}
