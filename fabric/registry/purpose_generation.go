package registry

import (
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

type purposeGeneration struct {
	Format           uint32              `json:"format"`
	Purpose          NativeAuthorityKind `json:"purpose"`
	Generation       uint64              `json:"generation,string"`
	MutationSequence uint64              `json:"mutationSequence,string"`
}

func purposeGenerationKey() AuthorityKey {
	return AuthorityKey{Kind: AuthorityPurposeGeneration, ID: string(AuthorityExtensionConfiguration)}
}

// ExtensionPurposeGeneration reads the intrinsic signed source generation with
// one indexed lookup. Callers cannot mutate this record through CAS.
func (a *AuthorityTx) ExtensionPurposeGeneration() (AuthorityRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(); err != nil {
		return AuthorityRecord{}, err
	}
	r, err := a.get(purposeGenerationKey())
	if err != nil {
		return AuthorityRecord{}, err
	}
	identity := AuthorityIdentity{a.store.identity.Namespace, a.store.identity.StoreID, a.store.identity.Owner, a.store.identity.PublicKey, 1}
	if err = VerifyAuthorityRecord(identity, r); err != nil {
		return AuthorityRecord{}, err
	}
	if err = validatePurposeGeneration(r); err != nil {
		return AuthorityRecord{}, err
	}
	return cloneAuthorityRecord(r), nil
}

func validatePurposeGeneration(r AuthorityRecord) error {
	var v purposeGeneration
	if r.Key != purposeGenerationKey() || r.Retired || json.Unmarshal(r.Value, &v) != nil || v.Format != 1 || v.Purpose != AuthorityExtensionConfiguration || v.Generation != r.Revision || v.MutationSequence == 0 || v.MutationSequence+1 != r.Sequence {
		return invalid("Intrinsic purpose generation is invalid")
	}
	return nil
}

// The savepoint makes the source mutation and its signed generation inseparable
// even when trusted callback code catches a failed CAS and continues its TX.
func (a *AuthorityTx) casExtensionConfiguration(k AuthorityKey, expected uint64, value []byte, retire bool) (r AuthorityRecord, err error) {
	if _, err = a.tx.ExecContext(a.ctx, "SAVEPOINT extension_purpose_mutation"); err != nil {
		return r, err
	}
	defer func() {
		if err == nil {
			_, err = a.tx.ExecContext(a.ctx, "RELEASE extension_purpose_mutation")
			if err == nil {
				return
			}
		}
		_, rollback := a.tx.Exec("ROLLBACK TO extension_purpose_mutation")
		_, release := a.tx.Exec("RELEASE extension_purpose_mutation")
		err = errors.Join(err, rollback, release)
		r = AuthorityRecord{}
		if rollback != nil || release != nil {
			a.failure = err
		}
	}()
	old, oldErr := a.get(k)
	r, err = a.cas(k, expected, value, retire)
	if err != nil {
		return r, err
	}
	if oldErr == nil && old.Sequence == r.Sequence {
		return r, nil
	}
	var generation uint64
	previous, getErr := a.get(purposeGenerationKey())
	if getErr == nil {
		if err = validatePurposeGeneration(previous); err != nil {
			return r, err
		}
		generation = previous.Revision
	} else if !isAuthorityNotFound(getErr) {
		return r, getErr
	}
	raw, err := json.Marshal(purposeGeneration{1, AuthorityExtensionConfiguration, generation + 1, r.Sequence})
	if err != nil {
		return r, err
	}
	_, err = a.cas(purposeGenerationKey(), generation, raw, false)
	return r, err
}

func isAuthorityNotFound(err error) bool {
	var e *fabric.Error
	return errors.As(err, &e) && e.Code == fabric.CodeNotFound
}
