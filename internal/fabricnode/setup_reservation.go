package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

type setupCreateCipher struct {
	Cipher []byte `json:"cipher"`
}
type setupCreateReservation struct {
	Version  int                `json:"version"`
	InputSHA [32]byte           `json:"inputSha"`
	Ref      fabric.EndpointRef `json:"ref"`
}

// ReserveSetupEndpoint commits a stable local setup identity before publication.
// Only these closed operator operations own this purpose; exact retries retain
// their reference and changed input cannot create or repurpose another identity.
func (n *InstalledNode) ReserveSetupEndpoint(current context.Context, access *fabricauth.OwnerAdministration, operation, requestID string, raw []byte) (fabric.EndpointRef, error) {
	var zero fabric.EndpointRef
	if n == nil || n.Installation == nil || access == nil || access.VerifyCurrent(current) != nil || len(raw) == 0 || len(raw) > 32<<10 || len(requestID) == 0 || len(requestID) > 128 {
		return zero, localDenied()
	}
	var purpose, prefix string
	switch operation {
	case "agent.create":
		purpose = "pagnet.agent.create.v1"
		prefix = "agent/create/"
	case "service.add":
		purpose = "pagnet.service.add.v1"
		prefix = "service/add/"
	default:
		return zero, localDenied()
	}
	owner, e := n.Installation.Operator(current)
	if e != nil {
		return zero, e
	}
	if access.PrincipalView() != owner.PrincipalView() {
		return zero, localDenied()
	}
	digest := sha256.Sum256(raw)
	keyDigest := sha256.Sum256([]byte(purpose + "\x00" + requestID))
	key := registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: prefix + hex.EncodeToString(keyDigest[:])}
	aad := []byte(n.Installation.Store.Namespace() + "/" + key.ID)
	var ref fabric.EndpointRef
	root := n.Installation.Store.AuthorityIdentity()
	e = n.Installation.Store.WithNativeAuthority(current, owner, registry.AuthorityScope{MaxOperations: 4, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
		row, readErr := tx.Get(key)
		if readErr == nil {
			if row.Retired {
				return localDenied()
			}
			var box setupCreateCipher
			if fabric.DecodeJSON(row.Value, &box) != nil {
				return localDenied()
			}
			plain, decryptErr := n.Installation.Keys.Open(aad, box.Cipher)
			if decryptErr != nil {
				return localDenied()
			}
			defer clear(plain)
			var saved setupCreateReservation
			if fabric.DecodeJSON(plain, &saved) != nil || saved.Version != 1 || saved.InputSHA != digest || saved.Ref.IsOffer() || saved.Ref.Domain() != n.Installation.Store.Namespace() {
				return fabric.NewError(fabric.CodeInvalidMutation, "Setup request conflicts with its retained identity")
			}
			ref = saved.Ref
			return nil
		}
		var failure *fabric.Error
		if !errors.As(readErr, &failure) || failure.Code != fabric.CodeNotFound {
			return readErr
		}
		ref, e = fabric.NewEndpointRef(root.PublicKey)
		if e != nil {
			return e
		}
		value, e := json.Marshal(setupCreateReservation{1, digest, ref})
		if e != nil {
			return e
		}
		defer clear(value)
		encrypted, e := n.Installation.Keys.Seal(aad, value)
		if e != nil {
			return e
		}
		defer clear(encrypted)
		encoded, e := json.Marshal(setupCreateCipher{Cipher: encrypted})
		if e != nil {
			return e
		}
		defer clear(encoded)
		_, e = tx.CAS(key, 0, encoded, false)
		return e
	})
	if e != nil {
		return zero, e
	}
	if e = access.VerifyCurrent(current); e != nil {
		return zero, e
	}
	return ref, nil
}
