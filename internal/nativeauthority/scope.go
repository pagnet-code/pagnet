// Package nativeauthority defines the closed authority boundary for native
// ownership. Public scope metadata is never authentication. Cloud and local
// authority have independent, immutable representations and no invented fields.
package nativeauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

type Kind string

const (
	Cloud Kind = "cloud"
	Local Kind = "local"
)

// CloudScope is the existing cloud ownership representation. Field order and
// JSON names intentionally preserve the original six-field signed/capture bytes.
type CloudScope struct {
	ServerURL  string `json:"serverUrl"`
	TenantID   string `json:"tenantId"`
	AccountID  string `json:"accountId"`
	HostID     string `json:"hostId"`
	InstanceID string `json:"instanceId"`
	Generation string `json:"generation"`
}

// LocalScope carries actual registry authority and local worker ownership.
// WorkerID is a local physical worker identity, never a cloud instance ID.
type LocalScope struct {
	Namespace           string             `json:"namespace"`
	StoreID             string             `json:"storeId"`
	KeyRevision         uint64             `json:"keyRevision"`
	PublicKey           [32]byte           `json:"publicKey"`
	Owner               fabric.Principal   `json:"owner"`
	Endpoint            fabric.EndpointRef `json:"endpoint"`
	DescriptorRevision  fabric.Revision    `json:"descriptorRevision"`
	BindingID           string             `json:"bindingId"`
	BindingDigest       [32]byte           `json:"bindingDigest"`
	StateDirectoryID    string             `json:"stateDirectoryId"`
	WorkerID            string             `json:"workerId"`
	OwnershipGeneration string             `json:"ownershipGeneration"`
	ActualRuntime       string             `json:"actualRuntime"`
	ProfileDigest       [32]byte           `json:"profileDigest"`
}

// Scope is comparable by value, never by pointers to independently decoded
// authority objects. Its private discriminant admits exactly one variant.
type Scope struct {
	kind  Kind
	cloud CloudScope
	local LocalScope
}

func (s Scope) Kind() Kind                { return s.kind }
func (s Scope) Cloud() (CloudScope, bool) { return s.cloud, s.kind == Cloud }
func (s Scope) Local() (LocalScope, bool) { return s.local, s.kind == Local }
func (s Scope) WorkerID() string {
	if s.kind == Cloud {
		return s.cloud.InstanceID
	}
	if s.kind == Local {
		return s.local.WorkerID
	}
	return ""
}
func (s Scope) OwnershipGeneration() string {
	if s.kind == Cloud {
		return s.cloud.Generation
	}
	if s.kind == Local {
		return s.local.OwnershipGeneration
	}
	return ""
}
func text(s string, max int) bool { return s != "" && len(s) <= max && utf8.ValidString(s) }
func (scope CloudScope) Validate() error {
	server, e := url.Parse(scope.ServerURL)
	if e != nil || (server.Scheme != "https" && server.Scheme != "http") || server.Host == "" || server.User != nil || server.RawQuery != "" || server.Fragment != "" || !text(scope.ServerURL, 2048) || !text(scope.TenantID, 256) || !text(scope.AccountID, 256) || !text(scope.HostID, 256) || !text(scope.InstanceID, 256) || !text(scope.Generation, 256) {
		return errors.New("cloud native authority scope is incomplete")
	}
	return nil
}

// NewCloudScope performs structural validation only. A real cloud admission must
// still come from the authenticated configured control-plane connection.
func NewCloudScope(cloud CloudScope) (Scope, error) {
	if e := cloud.Validate(); e != nil {
		return Scope{}, e
	}
	return Scope{kind: Cloud, cloud: cloud}, nil
}
func (scope LocalScope) Validate() error {
	namespace, e := fabric.DomainNamespace(scope.PublicKey[:])
	store, e2 := hex.DecodeString(scope.StoreID)
	if e != nil || e2 != nil || len(store) != 32 || hex.EncodeToString(store) != scope.StoreID || namespace != scope.Namespace || scope.Endpoint.Domain() != namespace || scope.Endpoint.IsOffer() || scope.KeyRevision != 1 || !text(scope.StoreID, 64) || len(scope.StoreID) != 64 || !text(string(scope.DescriptorRevision), 256) || !text(scope.BindingID, 256) || !text(scope.StateDirectoryID, 256) || !text(scope.WorkerID, 256) || !text(scope.OwnershipGeneration, 256) || !text(scope.ActualRuntime, 256) || scope.ProfileDigest == ([32]byte{}) || scope.BindingDigest == ([32]byte{}) || !text(scope.Owner.Ref, 4096) || !text(scope.Owner.Issuer, 4096) || !fabric.ValidNamespacedName(scope.Owner.Kind) {
		return errors.New("local native authority scope is incomplete")
	}
	return nil
}

// NewLocalScope verifies a binding against a root already pinned by trusted
// composition (actual private domain store/verified bootstrap). A root key
// supplied alongside wire assertions is NOT a trust pin. This constructor does
// not authenticate a local peer or establish current native process liveness.
func NewLocalScope(root registry.AuthorityIdentity, binding fabricidentity.Binding) (Scope, error) {
	if registry.VerifyAuthorityRecord(root, binding.Proof) != nil || binding.Proof.Retired || binding.Proof.Key.Kind != registry.AuthorityBinding || binding.Proof.Key.Endpoint != binding.Scope.Endpoint || binding.Proof.Key.ID != binding.Scope.BindingID {
		return Scope{}, errors.New("local native binding proof root or scope mismatch")
	}
	var stored fabricidentity.Binding
	if e := fabric.DecodeJSON(binding.Proof.Value, &stored); e != nil {
		return Scope{}, e
	}
	stored.Proof = binding.Proof
	supplied, e := json.Marshal(binding)
	if e != nil {
		return Scope{}, e
	}
	canonical, e := json.Marshal(stored)
	if e != nil || !bytes.Equal(supplied, canonical) {
		return Scope{}, errors.New("local native binding fields differ from proof")
	}
	var key [32]byte
	copy(key[:], root.PublicKey)
	local := LocalScope{Namespace: root.Namespace, StoreID: root.StoreID, KeyRevision: root.KeyRevision, PublicKey: key, Owner: root.Owner, Endpoint: binding.Scope.Endpoint, DescriptorRevision: binding.Scope.DescriptorRevision, BindingID: binding.Scope.BindingID, BindingDigest: sha256.Sum256(supplied), StateDirectoryID: binding.Worker.StateDirectoryID, WorkerID: binding.Worker.WorkerID, OwnershipGeneration: binding.Worker.OwnershipGeneration, ActualRuntime: binding.Worker.ActualRuntime, ProfileDigest: binding.Worker.ProfileDigest}
	if e = local.Validate(); e != nil {
		return Scope{}, e
	}
	return Scope{kind: Local, local: local}, nil
}
func (s Scope) Validate() error {
	switch s.kind {
	case Cloud:
		if s.local != (LocalScope{}) {
			return errors.New("cloud authority contains local scope")
		}
		return s.cloud.Validate()
	case Local:
		if s.cloud != (CloudScope{}) {
			return errors.New("local authority contains cloud scope")
		}
		return s.local.Validate()
	default:
		return errors.New("native authority variant missing")
	}
}
func (s Scope) MarshalJSON() ([]byte, error) {
	if e := s.Validate(); e != nil {
		return nil, e
	}
	if s.kind == Cloud {
		return json.Marshal(struct {
			Format string     `json:"format"`
			Cloud  CloudScope `json:"cloud"`
		}{"pagnet.native-authority.cloud.v1", s.cloud})
	}
	return json.Marshal(struct {
		Format string     `json:"format"`
		Local  LocalScope `json:"local"`
	}{"pagnet.native-authority.local.v1", s.local})
}

// UnmarshalJSON validates a public assertion only. The worker must compare it to
// its authenticated private bootstrap and revalidate signed admission proofs.
func (s *Scope) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Format string      `json:"format"`
		Cloud  *CloudScope `json:"cloud,omitempty"`
		Local  *LocalScope `json:"local,omitempty"`
	}
	if e := fabric.DecodeJSONWithLimits(raw, &wire, fabric.WireLimits{MaxBytes: 16 << 10, MaxDepth: 8, MaxMembers: 256}); e != nil {
		return e
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if e := strict.Decode(&wire); e != nil {
		return errors.New("native authority contains unsupported fields")
	}
	var presence map[string]json.RawMessage
	if e := json.Unmarshal(raw, &presence); e != nil {
		return e
	}
	if len(presence) != 2 {
		return errors.New("native authority variant must contain only format and its exact scope")
	}
	var result Scope
	switch wire.Format {
	case "pagnet.native-authority.cloud.v1":
		if wire.Cloud == nil || wire.Local != nil {
			return errors.New("cloud authority variant malformed")
		}
		result = Scope{kind: Cloud, cloud: *wire.Cloud}
	case "pagnet.native-authority.local.v1":
		if wire.Local == nil || wire.Cloud != nil {
			return errors.New("local authority variant malformed")
		}
		result = Scope{kind: Local, local: *wire.Local}
	default:
		return errors.New("unsupported native authority scope format")
	}
	if e := result.Validate(); e != nil {
		return e
	}
	*s = result
	return nil
}

// SamePhysical compares immutable ownership only. Descriptor revision and the
// fresh binding authorization digest may renew explicitly; creation provenance
// remains in original Scope/capture bytes. This comparison grants no authority.
func (s Scope) SamePhysical(other Scope) bool {
	if s.Validate() != nil || other.Validate() != nil || s.kind != other.kind {
		return false
	}
	if s.kind == Cloud {
		return s.cloud == other.cloud
	}
	a, b := s.local, other.local
	a.DescriptorRevision = ""
	b.DescriptorRevision = ""
	a.BindingDigest = [32]byte{}
	b.BindingDigest = [32]byte{}
	return a == b
}
