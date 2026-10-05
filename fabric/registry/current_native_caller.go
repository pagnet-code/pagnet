package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/pagnet-code/pagnet/fabric"
)

// NativeCallerAuthority contains genuine retained source proofs supplied by
// trusted kernel/worker authentication. This port verifies their current ledger
// state in the SAME destination transaction. It does not establish kernel
// liveness or authenticate a principal from these public records alone.
type NativeCallerAuthority struct {
	Principal                   fabric.Principal
	Endpoint                    fabric.EndpointRef
	DescriptorRevision          fabric.Revision
	BindingID                   string
	NativeGeneration            string
	Controller, Binding, Origin AuthorityRecord
}

type nativeCallerScope struct {
	Endpoint           fabric.EndpointRef `json:"endpoint"`
	DescriptorRevision fabric.Revision    `json:"descriptorRevision"`
	BindingID          string             `json:"bindingId"`
}

func nativeCallerKey(prefix string, parts ...string) string {
	raw, _ := json.Marshal(parts)
	sum := sha256.Sum256(raw)
	return prefix + hex.EncodeToString(sum[:])
}
func (a *AuthorityTx) currentCallerRecord(provided AuthorityRecord, key AuthorityKey) error {
	root := AuthorityIdentity{Namespace: a.store.identity.Namespace, StoreID: a.store.identity.StoreID, Owner: a.store.identity.Owner, PublicKey: a.store.identity.PublicKey, KeyRevision: 1}
	if provided.Retired || provided.Key != key || VerifyAuthorityRecord(root, provided) != nil {
		return invalid("Current native caller proof issuer or scope differs")
	}
	actual, err := a.get(key)
	if err != nil {
		return err
	}
	got, _ := json.Marshal(actual)
	expected, _ := json.Marshal(provided)
	if actual.Retired || !bytes.Equal(got, expected) {
		return conflict("Current native caller proof is stale or retired")
	}
	return nil
}

func (a *AuthorityTx) VerifyCurrentNativeCaller(f NativeCallerAuthority) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.guard(); err != nil {
		return err
	}
	if f.Endpoint.IsOffer() || f.Endpoint.Domain() != a.store.identity.Namespace || f.Principal.Ref != f.Endpoint.String() || f.Principal.Issuer != a.store.identity.Namespace || f.DescriptorRevision == "" || !text(f.BindingID, 256, false) || !text(f.NativeGeneration, 256, false) {
		return invalid("Current native caller selection outside actual root")
	}
	descriptor, err := loadObject(a.ctx, a.tx, f.Endpoint.String())
	if err != nil {
		return err
	}
	if descriptor.retired || descriptor.kind != "endpoint" || descriptor.revision != f.DescriptorRevision {
		return conflict("Current native caller descriptor is stale or retired")
	}
	var endpoint fabric.EndpointDescriptor
	if err = a.store.decode(descriptor.payload, &endpoint); err != nil {
		return err
	}
	if endpoint.Ref != f.Endpoint || endpoint.Kind != f.Principal.Kind {
		return invalid("Current native caller principal differs from registered source")
	}
	published := false
	for _, binding := range endpoint.Bindings {
		published = published || binding.ID == f.BindingID
	}
	if !published {
		return conflict("Current native caller binding unavailable")
	}
	if err = a.currentCallerRecord(f.Controller, AuthorityKey{Kind: AuthorityController, ID: nativeCallerKey("current:", f.Endpoint.String(), f.BindingID)}); err != nil {
		return err
	}
	if err = a.currentCallerRecord(f.Binding, AuthorityKey{Kind: AuthorityBinding, Endpoint: f.Endpoint, ID: f.BindingID}); err != nil {
		return err
	}
	if f.Origin.Key.Kind != AuthorityOrigin || f.Origin.Key.Endpoint != f.Endpoint {
		return invalid("Current native caller origin outside source")
	}
	if err = a.currentCallerRecord(f.Origin, f.Origin.Key); err != nil {
		return err
	}
	var controller struct {
		Scope nativeCallerScope `json:"scope"`
	}
	var binding struct {
		Scope  nativeCallerScope `json:"scope"`
		Worker json.RawMessage   `json:"worker"`
	}
	var origin struct {
		ID                      string            `json:"id"`
		Scope                   nativeCallerScope `json:"scope"`
		Worker                  json.RawMessage   `json:"worker"`
		NativeGeneration        string            `json:"nativeGeneration"`
		OriginalControllerEpoch uint64            `json:"originalControllerEpoch,string"`
	}
	if fabric.DecodeJSON(f.Controller.Value, &controller) != nil || fabric.DecodeJSON(f.Binding.Value, &binding) != nil || fabric.DecodeJSON(f.Origin.Value, &origin) != nil {
		return invalid("Current native caller ledger profile malformed")
	}
	scope := nativeCallerScope{f.Endpoint, f.DescriptorRevision, f.BindingID}
	if controller.Scope != scope || binding.Scope != scope || origin.Scope.Endpoint != f.Endpoint || origin.Scope.BindingID != f.BindingID || origin.ID != f.Origin.Key.ID || origin.NativeGeneration != f.NativeGeneration || origin.OriginalControllerEpoch == 0 || origin.OriginalControllerEpoch > f.Controller.Revision || !bytes.Equal(binding.Worker, origin.Worker) {
		return conflict("Current native caller physical origin differs")
	}
	_, err = a.get(AuthorityKey{Kind: AuthorityRetirement, Endpoint: f.Endpoint, ID: nativeCallerKey("retired:", origin.ID)})
	if err == nil {
		return conflict("Current native caller origin retired")
	}
	var typed *fabric.Error
	if !errors.As(err, &typed) || typed.Code != fabric.CodeNotFound {
		return err
	}
	return nil
}
