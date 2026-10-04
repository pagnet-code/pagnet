package nativeauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

// LocalControl refreshes authenticated physical-worker control without inventing
// invocation/source admission or rewriting original capture ownership.
type LocalControl struct {
	CurrentBinding    fabricidentity.Binding    `json:"currentBinding"`
	CurrentController fabricidentity.Controller `json:"currentController"`
}

func ValidateLocalControl(pinned Scope, c LocalControl) error {
	local, ok := pinned.Local()
	if !ok || pinned.Validate() != nil {
		return errors.New("local control ownership invalid")
	}
	root := registry.AuthorityIdentity{Namespace: local.Namespace, StoreID: local.StoreID, Owner: local.Owner, PublicKey: local.PublicKey[:], KeyRevision: local.KeyRevision}
	binding, e := NewLocalScope(root, c.CurrentBinding)
	if e != nil || !pinned.SamePhysical(binding) || c.CurrentController.Scope != c.CurrentBinding.Scope || c.CurrentController.Epoch() == 0 {
		return errors.New("local control physical binding differs")
	}
	fields, _ := json.Marshal([]string{local.Endpoint.String(), local.BindingID})
	digest := sha256.Sum256(fields)
	var signed fabricidentity.Controller
	if e = verifyRecord(root, c.CurrentController.Proof, registry.AuthorityKey{Kind: registry.AuthorityController, ID: "current:" + hex.EncodeToString(digest[:])}, &signed); e != nil {
		return e
	}
	signed.Proof = c.CurrentController.Proof
	if !sameJSON(signed, c.CurrentController) {
		return errors.New("local controller differs from signed authority")
	}
	return nil
}
