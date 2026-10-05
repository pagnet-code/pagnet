package fabricnode

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	extregistry "github.com/pagnet-code/pagnet/fabric/extension/registry"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// InstalledExtensionAdministration owns private source paging. It is composed
// once with the retained node; it never bootstraps or installs provider software.
type InstalledExtensionAdministration struct {
	node  *InstalledNode
	pager *extensionAdminPager
}

func NewInstalledExtensionAdministration(n *InstalledNode, options ExtensionPagerOptions) (*InstalledExtensionAdministration, error) {
	if n == nil || n.Node == nil || n.Extensions == nil {
		return nil, localDenied()
	}
	pager, err := newExtensionAdminPager(n.Extensions, options)
	if err != nil {
		return nil, err
	}
	return &InstalledExtensionAdministration{n, pager}, nil
}
func (a *InstalledExtensionAdministration) CloseContext(ctx context.Context) error {
	if a == nil {
		return nil
	}
	return a.pager.CloseContext(ctx)
}
func decodeExtensionAdmin(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > fabricadmin.MaxRequestBytes {
		return localDenied()
	}
	if err := fabric.DecodeJSONWithLimits(raw, target, fabric.WireLimits{MaxBytes: fabricadmin.MaxRequestBytes, MaxDepth: 32, MaxMembers: 2048}); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Unsupported extension administration fields")
	}
	return nil
}

type extensionMutationInput struct {
	Generation   uint64                   `json:"generation,string"`
	Revision     uint64                   `json:"revision,string,omitempty"`
	Installation extregistry.Installation `json:"installation"`
}
type extensionReferenceInput struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation,string,omitempty"`
	Revision   uint64 `json:"revision,string,omitempty"`
}
type extensionListInput struct {
	After string `json:"after,omitempty"`
	Limit int    `json:"limit"`
}

func extensionAdminJSON(v any, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	return raw, err
}
func (a *InstalledExtensionAdministration) Handlers() map[string]fabricadmin.Handler {
	if a == nil {
		return nil
	}
	operations := []string{"extension.profile.put", "extension.install", "extension.update", "extension.inspect", "extension.list", "extension.remove", "continuation.inspect", "continuation.stop", "continuation.recover", "continuation.rotate", "continuation.resume", "continuation.stream.page", "continuation.stream.close"}
	handlers := make(map[string]fabricadmin.Handler, len(operations))
	for _, operation := range operations {
		handlers[operation] = a.handle
	}
	return handlers
}
func (a *InstalledExtensionAdministration) handle(ctx context.Context, owner *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
	if a == nil || owner == nil || request.ExpectedRevision != "" || owner.VerifyCurrent(ctx) != nil {
		return nil, localDenied()
	}
	runtime := a.node.Extensions
	switch request.Operation {
	case "extension.profile.put":
		var input ExtensionProfile
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		digest, err := runtime.PutProfile(ctx, owner, input)
		return extensionAdminJSON(struct {
			Digest string `json:"digest"`
		}{digest}, err)
	case "extension.install", "extension.update":
		var input extensionMutationInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		var result extregistry.Reference
		var err error
		if request.Operation == "extension.install" {
			if input.Revision != 0 {
				return nil, localDenied()
			}
			result, err = runtime.Install(ctx, owner, input.Generation, input.Installation)
		} else {
			result, err = runtime.Update(ctx, owner, input.Generation, input.Revision, input.Installation)
		}
		return extensionAdminJSON(result, err)
	case "extension.inspect":
		var input extensionReferenceInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		if input.Generation != 0 || input.Revision != 0 {
			return nil, localDenied()
		}
		reference, installed, err := runtime.Inspect(ctx, owner, input.ID)
		return extensionAdminJSON(struct {
			Reference    extregistry.Reference    `json:"reference"`
			Installation extregistry.Installation `json:"installation"`
		}{reference, installed}, err)
	case "extension.list":
		var input extensionListInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		result, err := runtime.List(ctx, owner, input.After, input.Limit)
		return extensionAdminJSON(result, err)
	case "extension.remove":
		var input extensionReferenceInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		err := runtime.Remove(ctx, owner, input.Generation, input.Revision, input.ID)
		return extensionAdminJSON(struct {
			Removed bool `json:"removed"`
		}{err == nil}, err)
	case "continuation.recover", "continuation.rotate":
		var input extensionReferenceInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		if input.Generation != 0 || request.Operation == "continuation.recover" && input.Revision != 0 {
			return nil, localDenied()
		}
		if request.Operation == "continuation.recover" {
			err := runtime.RecoverNotification(ctx, owner, input.ID)
			return extensionAdminJSON(struct {
				Published bool `json:"published"`
			}{err == nil}, err)
		}
		issued, err := runtime.RotatePendingCapability(ctx, owner, input.ID, input.Revision)
		return extensionAdminJSON(struct {
			ID       string `json:"id"`
			Revision uint64 `json:"capabilityRevision,string"`
		}{issued.ID, issued.CapabilityRevision}, err)
	case "continuation.inspect", "continuation.stop":
		var input extensionResumeInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		var result ExtensionResumeReceipt
		var err error
		if request.Operation == "continuation.inspect" {
			result, err = a.pager.InspectClaim(ctx, owner, input)
		} else {
			result, err = a.pager.StopClaim(ctx, owner, input)
		}
		return extensionAdminJSON(result, err)
	case "continuation.resume":
		var input extensionResumeInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		result, err := a.pager.Resume(ctx, owner, input, a.node.Node.Service)
		return extensionAdminJSON(result, err)
	case "continuation.stream.page":
		var input extensionPageInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		result, err := a.pager.Page(ctx, owner, input)
		return extensionAdminJSON(result, err)
	case "continuation.stream.close":
		var input extensionPageInput
		if err := decodeExtensionAdmin(request.Input, &input); err != nil {
			return nil, err
		}
		err := a.pager.CloseSource(ctx, owner, input)
		return extensionAdminJSON(struct {
			Stopped bool `json:"stopped"`
		}{err == nil}, err)
	}
	return nil, fabric.NewError(fabric.CodeUnsupported, "Extension administration operation unavailable")
}
