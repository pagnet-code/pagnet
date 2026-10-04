package nativeauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/fabric"
	fabricidentity "github.com/pagnet-code/pagnet/fabric/identity"
)

// 128KiB valid prompt text may expand sixfold under JSON escaping.
// The eventual private IPC frame must additionally budget actual proof metadata.
const MaxNativeOperationBytes = 800 << 10

// PreparedOperation commits exact bytes and the immutable executable selector /
// spec. The trusted binder derives them from the finalized envelope, never from
// separately submitted caller executable assertions.
type PreparedOperation struct {
	Kind       string
	Payload    json.RawMessage
	SpecDigest [32]byte
}
type OperationBinder interface {
	Bind(fabric.Envelope) (PreparedOperation, error)
}

// VerifiedIntent is delivered only inside the current authority fence. Its
// operation bytes/digest and original admission A must be durably recorded
// together before acknowledging admission, independent of current controller B.
type VerifiedIntent struct {
	Scope             Scope
	CurrentBinding    fabricidentity.Binding
	CurrentController fabricidentity.Controller
	OriginalAdmission fabricidentity.Admission
	Commitment        fabricidentity.NativeIntentCommitment
	Operation         PreparedOperation
	Finalized         json.RawMessage
}

// LocalController connects trusted local domain authority to the actual worker
// durable admission port. It holds no domain private key and exports no cloud
// identity. The owner context comes from genuine trusted local authentication.
type LocalController struct {
	authority *fabricidentity.Authority
	owner     fabric.ExecutionContext
	binding   fabricidentity.Binding
	scope     Scope
	binder    OperationBinder
}

func NewLocalController(authority *fabricidentity.Authority, owner fabric.ExecutionContext, binding fabricidentity.Binding, binder OperationBinder) (*LocalController, error) {
	if authority == nil || binder == nil {
		return nil, errors.New("local native authority or operation binder missing")
	}
	root := authority.Identity()
	if owner.VerifyAuthenticated(root.Namespace) != nil || owner.PrincipalView() != root.Owner {
		return nil, errors.New("local native owner authentication mismatches pinned root")
	}
	scope, e := NewLocalScope(root, binding)
	if e != nil {
		return nil, e
	}
	return &LocalController{authority: authority, owner: owner, binding: binding, scope: scope, binder: binder}, nil
}

// NewLocalControllerForOwnership renews current descriptor authorization
// without rewriting an existing worker's original capture/IPC ownership scope.
func NewLocalControllerForOwnership(authority *fabricidentity.Authority, owner fabric.ExecutionContext, ownership Scope, currentBinding fabricidentity.Binding, binder OperationBinder) (*LocalController, error) {
	c, e := NewLocalController(authority, owner, currentBinding, binder)
	if e != nil {
		return nil, e
	}
	if ownership.Kind() != Local || !ownership.SamePhysical(c.scope) {
		return nil, errors.New("current native binding differs from original physical ownership")
	}
	c.scope = ownership
	return c, nil
}
func (c *LocalController) Scope() Scope {
	if c == nil {
		return Scope{}
	}
	return c.scope
}
func (c *LocalController) AdmitIntent(ctx context.Context, current fabricidentity.Controller, source fabricidentity.Admission, caller fabric.ExecutionContext, original, finalized []byte, commandID string, sequence int64, appendIntent func(context.Context, VerifiedIntent) (fabricidentity.NativeIntentReceipt, error)) (fabricidentity.NativeIntentReceipt, error) {
	if c == nil || c.authority == nil || c.binder == nil || ctx == nil || appendIntent == nil {
		return fabricidentity.NativeIntentReceipt{}, errors.New("local native intent port missing")
	}
	var final fabric.Envelope
	if e := fabric.DecodeJSON(finalized, &final); e != nil {
		return fabricidentity.NativeIntentReceipt{}, e
	}
	if e := final.Validate(); e != nil {
		return fabricidentity.NativeIntentReceipt{}, e
	}
	operation, e := c.binder.Bind(final)
	if e != nil {
		return fabricidentity.NativeIntentReceipt{}, e
	}
	if !text(operation.Kind, 64) || len(operation.Payload) == 0 || len(operation.Payload) > MaxNativeOperationBytes || operation.SpecDigest != c.binding.Worker.ProfileDigest {
		return fabricidentity.NativeIntentReceipt{}, errors.New("native binder returned invalid selector or executable commitment")
	}
	var bounded any
	if e = fabric.DecodeJSONWithLimits(operation.Payload, &bounded, fabric.WireLimits{MaxBytes: MaxNativeOperationBytes, MaxDepth: 16, MaxMembers: 1024}); e != nil {
		return fabricidentity.NativeIntentReceipt{}, e
	}
	operation.Payload = bytes.Clone(operation.Payload)
	selector, e := json.Marshal(struct {
		Purpose, Kind string
		SpecDigest    [32]byte
	}{"pagnet.native-local-selector.v1", operation.Kind, operation.SpecDigest})
	if e != nil {
		return fabricidentity.NativeIntentReceipt{}, e
	}
	commitment := fabricidentity.NativeIntentCommitment{CommandID: commandID, Sequence: sequence, OperationDigest: sha256.Sum256(operation.Payload), SelectorDigest: sha256.Sum256(selector), SpecDigest: operation.SpecDigest}
	verified := VerifiedIntent{Scope: c.scope, CurrentBinding: c.binding, CurrentController: current, OriginalAdmission: source, Commitment: commitment, Operation: operation, Finalized: bytes.Clone(finalized)}
	return c.authority.FenceNativeIntent(ctx, c.owner, current, c.binding, source, caller, original, finalized, commitment, func(lifetime context.Context) (fabricidentity.NativeIntentReceipt, error) {
		return appendIntent(lifetime, verified)
	})
}

// JSONPromptBinder is the explicit local native invocation schema. It maps
// {"input":string} to a native prompt. Cloud tasks/capabilities, runtime config
// and executable selectors are not accepted as application arguments.
type JSONPromptBinder struct{ ProfileDigest [32]byte }

func (b JSONPromptBinder) Bind(final fabric.Envelope) (PreparedOperation, error) {
	var input struct {
		Input string `json:"input"`
	}
	if final.Operation != fabric.OperationInvoke {
		return PreparedOperation{}, errors.New("native prompt requires invocation")
	}
	if e := fabric.DecodeJSONWithLimits(final.Payload, &input, fabric.WireLimits{MaxBytes: MaxNativeOperationBytes, MaxDepth: 2, MaxMembers: 8}); e != nil {
		return PreparedOperation{}, e
	}
	strict := json.NewDecoder(bytes.NewReader(final.Payload))
	strict.DisallowUnknownFields()
	if strict.Decode(&input) != nil || !utf8.ValidString(input.Input) || input.Input == "" || len(input.Input) > 128<<10 {
		return PreparedOperation{}, errors.New("native prompt input invalid")
	}
	payload, e := json.Marshal(struct {
		Input     string `json:"input"`
		InputKind string `json:"inputKind"`
	}{input.Input, "local-native"})
	if e != nil {
		return PreparedOperation{}, e
	}
	return PreparedOperation{Kind: "prompt", Payload: payload, SpecDigest: b.ProfileDigest}, nil
}
