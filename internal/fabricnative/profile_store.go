package fabricnative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// Profile is private operator-selected execution configuration. It is never a
// descriptor, caller argument or provider credential. Publishing it does not
// launch a process; replacing a physical worker remains an explicit operation.
type Profile struct {
	Native    sessionworker.NativeSpec `json:"native"`
	Worker    identity.WorkerBinding   `json:"worker"`
	Directory string                   `json:"directory"`
}
type profileRecord struct {
	Version            string   `json:"version"`
	Profile            Profile  `json:"profile"`
	ProfileEnvironment []string `json:"profileEnvironment"`
}
type ProfileStore struct {
	store     *registry.Store
	owner     fabric.ExecutionContext
	root      registry.AuthorityIdentity
	protector durable.DataProtector
}

func NewProfileStore(ctx context.Context, store *registry.Store, owner fabric.ExecutionContext, protector durable.DataProtector) (*ProfileStore, error) {
	if ctx == nil || store == nil || protector == nil {
		return nil, checkpointDenied()
	}
	root, err := store.CurrentAuthorityIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if owner.VerifyAuthenticated(root.Namespace) != nil || owner.PrincipalView() != root.Owner {
		return nil, checkpointDenied()
	}
	return &ProfileStore{store, owner, root, protector}, nil
}
func (s *ProfileStore) aad(scope registry.DescriptorBatchScope) []byte {
	// Descriptor renewal does not change the private physical execution profile.
	// The registry independently fences the requested CURRENT descriptor revision.
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store, Endpoint, Binding string }{"pagnet.native.profile.v1", s.root.Namespace, s.root.StoreID, scope.Endpoint.String(), scope.BindingID})
	return raw
}
func validProfile(p Profile) bool {
	// Bound every variable-length part BEFORE validation/fingerprinting allocates.
	if len(p.Native.Env) > 256 || len(p.Native.PrefixArgs) > 128 || len(p.Native.NativeDirs) > 128 || len(p.Native.CredentialEnvKeys) > 64 || p.Native.ProtectedContext != nil {
		return false
	}
	bytes := len(p.Directory)
	for _, field := range []string{string(p.Native.Runtime), p.Native.Binary, p.Native.Workspace, p.Native.Model, p.Native.StandingInstructions, p.Native.MCPExecutable, p.Native.NetworkID, p.Native.Kind, p.Native.TenantID, p.Native.NetworkTenantID, p.Native.InitialNativeSessionID, p.Native.ContextStateDir, p.Native.NetworkStateDir, p.Native.LocalFabricSocket, p.Native.LocalAuthorityDirectory} {
		bytes += len(field)
		if bytes > 32<<10 {
			return false
		}
	}
	for _, fields := range [][]string{p.Native.Env, p.Native.PrefixArgs, p.Native.NativeDirs, p.Native.CredentialEnvKeys} {
		for _, field := range fields {
			bytes += len(field)
			if bytes > 32<<10 {
				return false
			}
		}
	}
	if !filepath.IsAbs(p.Directory) || filepath.Clean(p.Directory) != p.Directory || len(p.Directory) > 4096 || sessionworker.ValidateLocalRuntimeEnvironment(p.Native, nil) != nil || p.Native.Kind != "local" || string(p.Native.Runtime) != p.Worker.ActualRuntime {
		return false
	}
	for _, field := range []string{p.Worker.WorkerID, p.Worker.StateDirectoryID, p.Worker.OwnershipGeneration} {
		if field == "" || len(field) > 256 {
			return false
		}
	}
	return hex.EncodeToString(p.Worker.ProfileDigest[:]) == sessionworker.LocalNativeProfileFingerprint(p.Native)
}

func (s *ProfileStore) nativeBinding(ctx context.Context, scope registry.DescriptorBatchScope) error {
	descriptor, err := s.store.GetEndpoint(ctx, scope.Endpoint, scope.ExpectedEndpointRevision)
	if err != nil {
		return err
	}
	for _, binding := range descriptor.Bindings {
		if binding.ID == scope.BindingID && binding.Protocol == "local.native" && binding.Version == "1" {
			return nil
		}
	}
	return fabric.NewError(fabric.CodeUnsupported, "Selected binding is not a native execution profile")
}

// Put uses the existing signed binding projection and its CAS generation. There
// is no second database, filesystem registry or unbounded enumeration. Secrets
// are resolved separately into the launcher's memory-only credential pipe.
func (s *ProfileStore) Put(ctx context.Context, scope registry.DescriptorBatchScope, p Profile) (uint64, error) {
	if s == nil || ctx == nil || !validProfile(p) {
		return 0, checkpointDenied()
	}
	if err := s.nativeBinding(ctx, scope); err != nil {
		return 0, err
	}
	raw, err := json.Marshal(profileRecord{"pagnet.native.profile.v1", p, p.Native.Env})
	if err != nil || len(raw) > 32<<10 {
		return 0, fabric.NewError(fabric.CodeInvalidInput, "Private native profile exceeds byte budget")
	}
	defer clear(raw)
	sealed, err := s.protector.Seal(s.aad(scope), raw)
	if err != nil || len(sealed) > 64<<10 {
		return 0, checkpointDenied()
	}
	limits := registry.DescriptorBatchLimits{MaxRows: 1, MaxBytes: 64 << 10, MaxChanges: 1, MaxValueBytes: 64 << 10}
	request, err := json.Marshal(struct {
		Scope  registry.DescriptorBatchScope
		Sealed []byte
	}{scope, sealed})
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(request)
	result, err := s.store.ApplyDescriptorBatch(ctx, s.owner, scope, registry.DescriptorBatch{RequestID: hex.EncodeToString(digest[:]), Limits: limits, PrivateConfig: sealed})
	return result.ProjectionRevision, err
}

func (s *ProfileStore) Get(ctx context.Context, scope registry.DescriptorBatchScope) (Profile, uint64, error) {
	if s == nil || ctx == nil {
		return Profile{}, 0, checkpointDenied()
	}
	if err := s.nativeBinding(ctx, scope); err != nil {
		return Profile{}, 0, err
	}
	page, err := s.store.ReadBindingProjection(ctx, s.owner, scope, "", 1)
	if err != nil {
		return Profile{}, 0, err
	}
	if len(page.PrivateConfig) == 0 || len(page.PrivateConfig) > 64<<10 || len(page.Rows) != 0 {
		return Profile{}, 0, checkpointDenied()
	}
	raw, err := s.protector.Open(s.aad(scope), page.PrivateConfig)
	if err != nil {
		return Profile{}, 0, checkpointDenied()
	}
	defer clear(raw)
	var record profileRecord
	if fabric.DecodeJSONWithLimits(raw, &record, fabric.WireLimits{MaxBytes: 32 << 10, MaxDepth: 16, MaxMembers: 1024}) != nil || record.Version != "pagnet.native.profile.v1" {
		return Profile{}, 0, checkpointDenied()
	}
	record.Profile.Native.Env = record.ProfileEnvironment
	if !validProfile(record.Profile) {
		return Profile{}, 0, checkpointDenied()
	}
	return record.Profile, page.Generation, nil
}
