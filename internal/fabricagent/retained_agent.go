package fabricagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricnative"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
)

// RetainedAgent preserves the existing private definition/instance distinction.
// Instance contains configuration, not asserted PID, session or observed status.
// The actual worker remains the sole source of those observations.
type RetainedAgent struct {
	Version     int
	Ref         fabric.EndpointRef
	InputSHA    [32]byte
	Definition  domain.AgentDefinition
	Instance    domain.AgentInstance
	Profile     fabricnative.Profile
	Environment []string
}

type RetainedAgentStore struct {
	store     *registry.Store
	owner     fabric.ExecutionContext
	protector durable.DataProtector
	root      registry.AuthorityIdentity
}

func NewRetainedAgentStore(ctx context.Context, store *registry.Store, owner fabric.ExecutionContext, protector durable.DataProtector) (*RetainedAgentStore, error) {
	if ctx == nil || store == nil || protector == nil {
		return nil, agentDenied()
	}
	root, e := store.CurrentAuthorityIdentity(ctx)
	if e != nil {
		return nil, e
	}
	if owner.VerifyAuthenticated(root.Namespace) != nil || owner.PrincipalView() != root.Owner {
		return nil, agentDenied()
	}
	return &RetainedAgentStore{store, owner, protector, root}, nil
}
func agentDenied() error {
	return fabric.NewError(fabric.CodeUnauthenticated, "Current retained agent configuration required")
}
func (s *RetainedAgentStore) key(ref fabric.EndpointRef) (registry.AuthorityKey, []byte, error) {
	if s == nil || ref.IsOffer() || ref.Domain() != s.root.Namespace {
		return registry.AuthorityKey{}, nil, agentDenied()
	}
	digest := sha256.Sum256([]byte(ref.String()))
	key := registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "agent/runtime/" + hex.EncodeToString(digest[:])}
	aad, _ := json.Marshal(struct{ Purpose, Namespace, Store, Key string }{"pagnet.agent.runtime.v1", s.root.Namespace, s.root.StoreID, key.ID})
	return key, aad, nil
}

type agentCipher struct {
	Cipher []byte `json:"cipher"`
}

func (s *RetainedAgentStore) decode(aad []byte, row registry.AuthorityRecord) (RetainedAgent, error) {
	var a RetainedAgent
	var box agentCipher
	if row.Retired || fabric.DecodeJSON(row.Value, &box) != nil {
		return a, agentDenied()
	}
	plain, e := s.protector.Open(aad, box.Cipher)
	if e != nil {
		return a, agentDenied()
	}
	defer clear(plain)
	if len(plain) > 32<<10 || fabric.DecodeJSONWithLimits(plain, &a, fabric.WireLimits{MaxBytes: 32 << 10, MaxDepth: 64, MaxMembers: 4096}) != nil || a.Version != 1 || a.Definition.ID == "" || a.Instance.ID == "" || a.Instance.DefinitionID != a.Definition.ID || a.Ref.Domain() != s.root.Namespace || a.Instance.PID != nil || a.Instance.RuntimeSessionID != nil || a.Instance.Status != "" {
		return RetainedAgent{}, agentDenied()
	}
	if _, e := domain.ParseID(string(a.Definition.ID)); e != nil {
		return RetainedAgent{}, agentDenied()
	}
	if _, e := domain.ParseID(string(a.Instance.ID)); e != nil {
		return RetainedAgent{}, agentDenied()
	}
	if a.Definition.ExecutionMode != domain.ExecutionModeManaged || a.Definition.DefaultRuntime != a.Instance.Runtime || a.Instance.Runtime != a.Profile.Native.Runtime || a.Definition.Instruction != a.Profile.Native.StandingInstructions || a.Definition.DefaultModel != a.Profile.Native.Model || a.Instance.PrincipalID != a.Definition.PrincipalID || a.Profile.Worker.WorkerID != string(a.Instance.ID) || a.Instance.NetworkID != "" || a.Instance.HostID != "" || a.Profile.Native.InitialNativeSessionID != "" {
		return RetainedAgent{}, agentDenied()
	}
	a.Profile.Native.Env = append([]string(nil), a.Environment...)
	if sessionworker.ValidateLocalRuntimeEnvironment(a.Profile.Native, nil) != nil || hex.EncodeToString(a.Profile.Worker.ProfileDigest[:]) != sessionworker.LocalNativeProfileFingerprint(a.Profile.Native) {
		return RetainedAgent{}, agentDenied()
	}
	return a, nil
}

// Reserve retains exact private configuration before publishing the callable
// binding. FULL retries keep definition/instance/physical worker IDs; changed
// input never remaps an original setup into a second worker.
func (s *RetainedAgentStore) Reserve(ctx context.Context, ref fabric.EndpointRef, inputSHA [32]byte, spec sessionworker.NativeSpec, workerParent string) (RetainedAgent, error) {
	var result RetainedAgent
	if ctx == nil || inputSHA == [32]byte{} {
		return result, fabric.NewError(fabric.CodeInvalidInput, "Agent setup context and exact commitment required")
	}
	key, aad, e := s.key(ref)
	if e != nil {
		return result, e
	}
	if spec.InitialNativeSessionID != "" {
		return result, UnsupportedHostedAdoption()
	}
	if !filepath.IsAbs(workerParent) || filepath.Clean(workerParent) != workerParent || spec.Kind != "local" || sessionworker.ValidateLocalRuntimeEnvironment(spec, nil) != nil {
		return result, fabric.NewError(fabric.CodeInvalidInput, "Invalid private agent runtime profile")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e = s.store.WithNativeAuthority(ctx, s.owner, registry.AuthorityScope{MaxOperations: 4, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
		row, readErr := tx.Get(key)
		if readErr == nil {
			result, e = s.decode(aad, row)
			if e != nil {
				return e
			}
			if result.Ref != ref || result.InputSHA != inputSHA {
				return fabric.NewError(fabric.CodeInvalidMutation, "Agent runtime setup conflicts with its retained instance")
			}
			if result.Profile.Directory != filepath.Join(workerParent, string(result.Instance.ID)) || sessionworker.LocalNativeProfileFingerprint(result.Profile.Native) != sessionworker.LocalNativeProfileFingerprint(spec) {
				return fabric.NewError(fabric.CodeInvalidMutation, "Agent runtime selection changed under its retained setup")
			}
			return nil
		}
		var failure *fabric.Error
		if !errors.As(readErr, &failure) || failure.Code != fabric.CodeNotFound {
			return readErr
		}
		now := time.Now().UTC()
		definition, instance := domain.ID(uuid.NewString()), domain.ID(uuid.NewString())
		worker := identity.WorkerBinding{WorkerID: string(instance), StateDirectoryID: uuid.NewString(), OwnershipGeneration: uuid.NewString(), ActualRuntime: string(spec.Runtime)}
		fp, _ := hex.DecodeString(sessionworker.LocalNativeProfileFingerprint(spec))
		copy(worker.ProfileDigest[:], fp)
		result = RetainedAgent{Version: 1, Ref: ref, InputSHA: inputSHA, Definition: domain.AgentDefinition{ID: definition, PrincipalID: definition, ExecutionMode: domain.ExecutionModeManaged, DefaultRuntime: spec.Runtime, DefaultModel: spec.Model, Instruction: spec.StandingInstructions, ExecutionSettings: domain.DefaultExecutionSettings(), CreatedAt: now, UpdatedAt: now}, Instance: domain.AgentInstance{ID: instance, DefinitionID: definition, PrincipalID: definition, Runtime: spec.Runtime, CreatedAt: now}, Profile: fabricnative.Profile{Native: spec, Worker: worker, Directory: filepath.Join(workerParent, string(instance))}, Environment: append([]string(nil), spec.Env...)}
		raw, e := json.Marshal(result)
		if e != nil {
			return e
		}
		defer clear(raw)
		if len(raw) > 32<<10 {
			return fabric.NewError(fabric.CodeInvalidInput, "Agent configuration exceeds byte budget")
		}
		sealed, e := s.protector.Seal(aad, raw)
		if e != nil {
			return e
		}
		defer clear(sealed)
		encoded, e := json.Marshal(agentCipher{sealed})
		if e != nil {
			return e
		}
		defer clear(encoded)
		_, e = tx.CAS(key, 0, encoded, false)
		return e
	})
	return result, e
}

func (s *RetainedAgentStore) Get(ctx context.Context, ref fabric.EndpointRef) (RetainedAgent, error) {
	var result RetainedAgent
	key, aad, e := s.key(ref)
	if e != nil {
		return result, e
	}
	e = s.store.WithNativeAuthority(ctx, s.owner, registry.AuthorityScope{MaxOperations: 1, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
		row, e := tx.Get(key)
		if e != nil {
			return e
		}
		result, e = s.decode(aad, row)
		return e
	})
	if e == nil && result.Ref != ref {
		return RetainedAgent{}, agentDenied()
	}
	return result, e
}

// Cloud conversations are not transferable ownership evidence. A genuine
// current daemon/source bridge must be supplied rather than spawning a fork.
func UnsupportedHostedAdoption() error {
	return fabric.NewError(fabric.CodeUnsupported, "Existing hosted agents require their original authenticated daemon lifecycle; a session ID alone cannot authorize a new local worker")
}
