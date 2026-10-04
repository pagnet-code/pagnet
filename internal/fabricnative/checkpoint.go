package fabricnative

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/identity"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

const checkpointChunkBytes = 32 << 10
const checkpointMaxBytes = 3 << 20
const checkpointMaxChunks = checkpointMaxBytes / checkpointChunkBytes

// OriginalCheckpoint is private recovery infrastructure. It preserves exact
// signed input bytes, never refreshed permissions or a new execution deadline.
type OriginalCheckpoint struct {
	Admission       identity.Admission `json:"admission"`
	OriginalBinding identity.Binding   `json:"originalBinding"`
	Original        []byte             `json:"original"`
	Finalized       []byte             `json:"finalized"`
}

type checkpointManifest struct {
	Version string               `json:"version"`
	ID      string               `json:"id"`
	Digest  string               `json:"digest"`
	Bytes   int                  `json:"bytes"`
	Chunks  int                  `json:"chunks"`
	Key     durable.KeyReference `json:"key"`
}

// Checkpoints uses the actual registry's signed FULL transaction and quota.
// No second root/database is created. Encryption happens outside its SQL lock.
type Checkpoints struct {
	store     *registry.Store
	authority *identity.Authority
	owner     fabric.ExecutionContext
	root      registry.AuthorityIdentity
	protector durable.DataProtector
	key       durable.KeyReference
}

func NewCheckpoints(store *registry.Store, authority *identity.Authority, owner fabric.ExecutionContext, protector durable.DataProtector) (*Checkpoints, error) {
	if store == nil || authority == nil || protector == nil {
		return nil, checkpointDenied()
	}
	root, err := store.CurrentAuthorityIdentity(context.Background())
	if err != nil || owner.VerifyAuthenticated(root.Namespace) != nil || owner.PrincipalView() != root.Owner || authority.Identity().StoreID != root.StoreID || authority.Identity().Namespace != root.Namespace {
		return nil, checkpointDenied()
	}
	key := protector.Reference()
	if key.ID == "" || key.Version == "" || len(key.ID) > 256 || len(key.Version) > 256 {
		return nil, checkpointDenied()
	}
	return &Checkpoints{store, authority, owner, root, protector, key}, nil
}

func checkpointDenied() error {
	return fabric.NewError(fabric.CodeProtocolError, "Original native checkpoint unavailable or changed")
}

func checkpointID(principal fabric.Principal, invocation string) string {
	raw, _ := json.Marshal(struct {
		Purpose    string
		Principal  fabric.Principal
		Invocation string
	}{"pagnet.native.checkpoint.identity.v1", principal, invocation})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func checkpointKey(id string, index int) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: fmt.Sprintf("source/%s/%d", id, index)}
}
func (c *Checkpoints) aad(m checkpointManifest, index int) []byte {
	raw, _ := json.Marshal(struct {
		Purpose, Domain, Store string
		Manifest               checkpointManifest
		Index                  int
	}{"pagnet.native.checkpoint.chunk.v1", c.root.Namespace, c.root.StoreID, m, index})
	return raw
}
func decodeCheckpoint(raw []byte, out any) error {
	return fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: checkpointMaxBytes, MaxDepth: 64, MaxMembers: 8192})
}

func (c *Checkpoints) validate(ctx context.Context, value OriginalCheckpoint) (fabric.ExecutionContext, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || len(value.Original) == 0 || len(value.Finalized) == 0 || len(value.Original) > fabric.DefaultWireLimits.MaxBytes || len(value.Finalized) > fabric.DefaultWireLimits.MaxBytes {
		return fabric.ExecutionContext{}, checkpointDenied()
	}
	if value.OriginalBinding.Scope != value.Admission.Scope || value.OriginalBinding.Proof.Retired || registry.VerifyAuthorityRecord(c.root, value.OriginalBinding.Proof) != nil {
		return fabric.ExecutionContext{}, checkpointDenied()
	}
	braw, err := json.Marshal(value.OriginalBinding)
	if err != nil || sha256.Sum256(braw) != value.Admission.BindingDigest {
		return fabric.ExecutionContext{}, checkpointDenied()
	}
	return c.authority.RestoreOriginalCaller(ctx, c.owner, value.Admission, value.Original, value.Finalized)
}

// Save must precede worker intent ACK. A retry can only find the same exact
// source; changing target, identity, bytes or binding cannot create a new entry.
func (c *Checkpoints) Save(ctx context.Context, value OriginalCheckpoint) (string, error) {
	if _, err := c.validate(ctx, value); err != nil {
		return "", err
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > checkpointMaxBytes {
		return "", checkpointDenied()
	}
	id := checkpointID(value.Admission.OriginalCaller, value.Admission.InvocationID)
	h := sha256.Sum256(raw)
	m := checkpointManifest{"pagnet.native.checkpoint.v1", id, hex.EncodeToString(h[:]), len(raw), (len(raw) + checkpointChunkBytes - 1) / checkpointChunkBytes, c.key}
	if m.Chunks < 1 || m.Chunks > checkpointMaxChunks || c.protector.Reference() != c.key {
		return "", checkpointDenied()
	}
	// Each ciphertext remains below the actual authority record's64KiB bound.
	sealed := make([][]byte, m.Chunks)
	for i := range sealed {
		end := min(len(raw), (i+1)*checkpointChunkBytes)
		cipher, e := c.protector.Seal(c.aad(m, i), raw[i*checkpointChunkBytes:end])
		if e != nil || len(cipher) == 0 || len(cipher) > checkpointChunkBytes+1024 {
			return "", checkpointDenied()
		}
		sealed[i], e = json.Marshal(struct {
			Ciphertext []byte `json:"ciphertext"`
		}{cipher})
		if e != nil {
			return "", checkpointDenied()
		}
	}
	manifest, _ := json.Marshal(m)
	err = c.store.WithNativeAuthority(ctx, c.owner, registry.AuthorityScope{MaxOperations: checkpointMaxChunks + 2}, func(tx *registry.AuthorityTx) error {
		old, e := tx.Get(checkpointKey(id, -1))
		if e == nil {
			if old.Retired || !bytes.Equal(old.Value, manifest) {
				return checkpointDenied()
			}
			return nil
		}
		var fe *fabric.Error
		if !errors.As(e, &fe) || fe.Code != fabric.CodeNotFound {
			return e
		}
		for i, chunk := range sealed {
			if _, e = tx.CAS(checkpointKey(id, i), 0, chunk, false); e != nil {
				return e
			}
		}
		_, e = tx.CAS(checkpointKey(id, -1), 0, manifest, false)
		return e
	})
	if err != nil {
		return "", err
	}
	// Ambiguous commit is resolved only by reading and authenticating the entire
	// original checkpoint; a matching manifest alone never stands in for content.
	if _, _, err = c.Load(ctx, value.Admission.OriginalCaller, value.Admission.InvocationID); err != nil {
		return "", err
	}
	return id, nil
}

func (c *Checkpoints) Load(ctx context.Context, principal fabric.Principal, invocation string) (OriginalCheckpoint, fabric.ExecutionContext, error) {
	var zero OriginalCheckpoint
	if c == nil || ctx == nil || invocation == "" || len(invocation) > 256 || c.protector.Reference() != c.key {
		return zero, fabric.ExecutionContext{}, checkpointDenied()
	}
	id := checkpointID(principal, invocation)
	var m checkpointManifest
	var cipherChunks [][]byte
	err := c.store.WithNativeAuthority(ctx, c.owner, registry.AuthorityScope{MaxOperations: checkpointMaxChunks + 1}, func(tx *registry.AuthorityTx) error {
		r, e := tx.Get(checkpointKey(id, -1))
		if e != nil {
			return e
		}
		if r.Retired || decodeCheckpoint(r.Value, &m) != nil || m.Version != "pagnet.native.checkpoint.v1" || m.ID != id || m.Bytes < 1 || m.Bytes > checkpointMaxBytes || m.Chunks != (m.Bytes+checkpointChunkBytes-1)/checkpointChunkBytes || m.Chunks > checkpointMaxChunks || m.Key != c.key {
			return checkpointDenied()
		}
		cipherChunks = make([][]byte, m.Chunks)
		for i := range cipherChunks {
			r, e = tx.Get(checkpointKey(id, i))
			if e != nil {
				return e
			}
			var chunk struct {
				Ciphertext []byte `json:"ciphertext"`
			}
			if r.Retired || decodeCheckpoint(r.Value, &chunk) != nil || len(chunk.Ciphertext) == 0 || len(chunk.Ciphertext) > checkpointChunkBytes+1024 {
				return checkpointDenied()
			}
			cipherChunks[i] = chunk.Ciphertext
		}
		return nil
	})
	if err != nil {
		return zero, fabric.ExecutionContext{}, err
	}
	raw := make([]byte, 0, m.Bytes)
	for i, cipher := range cipherChunks {
		part, e := c.protector.Open(c.aad(m, i), cipher)
		expected := min(checkpointChunkBytes, m.Bytes-i*checkpointChunkBytes)
		if e != nil || len(part) != expected {
			return zero, fabric.ExecutionContext{}, checkpointDenied()
		}
		raw = append(raw, part...)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != m.Digest || decodeCheckpoint(raw, &zero) != nil || zero.Admission.OriginalCaller != principal || zero.Admission.InvocationID != invocation {
		return OriginalCheckpoint{}, fabric.ExecutionContext{}, checkpointDenied()
	}
	caller, err := c.validate(ctx, zero)
	if err != nil {
		return OriginalCheckpoint{}, fabric.ExecutionContext{}, err
	}
	return zero, caller, nil
}
