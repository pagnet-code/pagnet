package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
)

// AgentCreateInput publishes only the chosen network-facing description.
// Runtime instructions/credentials belong to private execution profiles.
type AgentCreateInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
type agentCreateCipher struct {
	Cipher []byte `json:"cipher"`
}

type agentCreateReservation struct {
	Version  int                `json:"version"`
	InputSHA [32]byte           `json:"inputSha"`
	Ref      fabric.EndpointRef `json:"ref"`
}

// AgentAdministration consumes genuine owner callbacks and the installation's
// original writer. Creating a searchable identity does not launch a turn.
func (n *InstalledNode) AgentAdministration(committed func()) map[string]fabricadmin.Handler {
	return map[string]fabricadmin.Handler{"agent.create": func(ctx context.Context, access *fabricauth.OwnerAdministration, request fabricadmin.Request) (json.RawMessage, error) {
		if n == nil || n.Installation == nil || n.Node == nil || access == nil || request.Operation != "agent.create" || request.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
			return nil, localDenied()
		}
		owner, err := n.Installation.Operator(ctx)
		if err != nil {
			return nil, err
		}
		if access.PrincipalView() != owner.PrincipalView() {
			return nil, localDenied()
		}
		var input AgentCreateInput
		if err = fabric.DecodeJSON(request.Input, &input); err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(request.Input))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&input); err != nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent setup contains unsupported fields")
		}
		if strings.TrimSpace(input.Name) == "" || len(input.Name) > 256 || strings.ContainsAny(input.Name, "\x00\r\n") || strings.TrimSpace(input.Description) == "" || len(input.Description) > 4096 || strings.ContainsRune(input.Description, 0) {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Agent name and network description required")
		}
		var output json.RawMessage
		err = n.Installation.WithCurrentOperator(ctx, owner, func(current context.Context) error {
			if e := access.VerifyCurrent(current); e != nil {
				return e
			}
			// Retain the random reference before publication. An interrupted setup
			// repeats the exact registry mutation on that same identity, never creates
			// another agent or changes an existing identity under the same request ID.
			raw, e := json.Marshal(input)
			if e != nil {
				return e
			}
			defer clear(raw)
			digest := sha256.Sum256(raw)
			keyDigest := sha256.Sum256([]byte("pagnet.agent.create.v1\x00" + request.ID))
			key := registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "agent/create/" + hex.EncodeToString(keyDigest[:])}
			aad := []byte(n.Installation.Store.Namespace() + "/" + key.ID)
			var ref fabric.EndpointRef
			root := n.Installation.Store.AuthorityIdentity()
			e = n.Installation.Store.WithNativeAuthority(current, owner, registry.AuthorityScope{MaxOperations: 4, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
				row, readErr := tx.Get(key)
				if readErr == nil {
					if row.Retired {
						return localDenied()
					}
					var box agentCreateCipher
					if fabric.DecodeJSON(row.Value, &box) != nil {
						return localDenied()
					}
					plain, decryptErr := n.Installation.Keys.Open(aad, box.Cipher)
					if decryptErr != nil {
						return localDenied()
					}
					defer clear(plain)
					var saved agentCreateReservation
					if fabric.DecodeJSON(plain, &saved) != nil || saved.Version != 1 || saved.InputSHA != digest || saved.Ref.IsOffer() || saved.Ref.Domain() != n.Installation.Store.Namespace() {
						return fabric.NewError(fabric.CodeInvalidMutation, "Agent setup request conflicts with its retained identity")
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
				value, e := json.Marshal(agentCreateReservation{1, digest, ref})
				if e != nil {
					return e
				}
				defer clear(value)
				encrypted, e := n.Installation.Keys.Seal(aad, value)
				if e != nil {
					return e
				}
				defer clear(encrypted)
				encoded, e := json.Marshal(agentCreateCipher{Cipher: encrypted})
				if e != nil {
					return e
				}
				defer clear(encoded)
				_, e = tx.CAS(key, 0, encoded, false)
				return e
			})
			if e != nil {
				return e
			}
			if e = access.VerifyCurrent(current); e != nil {
				return e
			}
			revision, e := n.Installation.Store.Register(current, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "actor.agent", Name: input.Name, Description: input.Description}})
			if e != nil {
				return e
			}
			if committed != nil {
				committed()
			}
			output, e = json.Marshal(struct {
				Ref      fabric.EndpointRef `json:"ref"`
				Revision fabric.Revision    `json:"revision"`
				Name     string             `json:"name"`
			}{ref, revision, input.Name})
			return e
		})
		return output, err
	}}
}
