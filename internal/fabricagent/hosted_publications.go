package fabricagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/transport"
)

const hostedPublicationChunkBytes = 24 << 10
const hostedPublicationMaxBytes = 512 << 10

type hostedPublicationMarker struct {
	Format           int             `json:"format"`
	Bytes            int             `json:"bytes"`
	Chunks           int             `json:"chunks"`
	CipherDigest     [32]byte        `json:"cipherDigest"`
	ProfileDigest    [32]byte        `json:"profileDigest"`
	ExpectedRevision fabric.Revision `json:"expectedRevision"`
}

func hostedPublicationKey(scope registry.DescriptorBatchScope) registry.AuthorityKey {
	raw, _ := json.Marshal(scope)
	digest := sha256.Sum256(raw)
	return registry.AuthorityKey{Kind: registry.AuthorityNativeCheckpoint, ID: "hosted/catalog/" + hex.EncodeToString(digest[:])}
}
func publicationChunkKey(key registry.AuthorityKey, index int) registry.AuthorityKey {
	key.ID += "/chunk/" + strconv.Itoa(index)
	return key
}
func (s *HostedProfiles) publicationAAD(key registry.AuthorityKey) []byte {
	raw, _ := json.Marshal(struct{ Purpose, Domain, Store, Key string }{"pagnet.hosted.catalog.retry.v1", s.root.Namespace, s.root.StoreID, key.ID})
	return raw
}
func publicationMatches(p transport.FabricHostedPublication, scope registry.DescriptorBatchScope, profile HostedProfile, root registry.AuthorityIdentity, expected fabric.Revision) bool {
	return p.Validate() == nil && p.Ref == scope.Endpoint && p.Revision == scope.ExpectedEndpointRevision && p.ExpectedRevision == expected && bytes.Equal(p.DomainPublicKey, root.PublicKey) && p.NetworkID == profile.NetworkID && p.InstanceID == profile.Scope.InstanceID && p.OwnershipID == profile.OwnershipID && p.OwnershipGeneration == profile.Scope.Generation
}
func publicationProfileDigest(p HostedProfile, row registry.AuthorityRecord) [32]byte {
	raw, _ := json.Marshal(struct {
		Profile  HostedProfile
		Revision uint64
	}{p, row.Revision})
	defer clear(raw)
	return sha256.Sum256(raw)
}
func (s *HostedProfiles) readPublication(tx *registry.AuthorityTx, scope registry.DescriptorBatchScope, digest [32]byte, expected fabric.Revision) (transport.FabricHostedPublication, error) {
	var out transport.FabricHostedPublication
	key := hostedPublicationKey(scope)
	row, err := tx.Get(key)
	if err != nil {
		return out, err
	}
	if row.Retired || registry.VerifyAuthorityRecord(s.root, row) != nil {
		return out, hostedProfileError()
	}
	var marker hostedPublicationMarker
	if fabric.DecodeJSONWithLimits(row.Value, &marker, fabric.WireLimits{MaxBytes: 2048, MaxDepth: 3, MaxMembers: 80}) != nil || marker.Format != 1 || marker.ProfileDigest != digest || marker.ExpectedRevision != expected || marker.Bytes < 1 || marker.Bytes > hostedPublicationMaxBytes+1024 || marker.Chunks != (marker.Bytes+hostedPublicationChunkBytes-1)/hostedPublicationChunkBytes || marker.Chunks > 22 {
		return out, hostedProfileError()
	}
	cipher := make([]byte, 0, marker.Bytes)
	defer func() { clear(cipher) }()
	for i := 0; i < marker.Chunks; i++ {
		chunk, err := tx.Get(publicationChunkKey(key, i))
		if err != nil || chunk.Retired || registry.VerifyAuthorityRecord(s.root, chunk) != nil {
			return out, hostedProfileError()
		}
		var value []byte
		if json.Unmarshal(chunk.Value, &value) != nil || len(value) != min(hostedPublicationChunkBytes, marker.Bytes-i*hostedPublicationChunkBytes) {
			return out, hostedProfileError()
		}
		cipher = append(cipher, value...)
		clear(value)
	}
	if sha256.Sum256(cipher) != marker.CipherDigest {
		return out, hostedProfileError()
	}
	raw, err := s.protector.Open(s.publicationAAD(key), cipher)
	if err != nil {
		return out, hostedProfileError()
	}
	defer clear(raw)
	if fabric.DecodeJSONWithLimits(raw, &out, fabric.WireLimits{MaxBytes: hostedPublicationMaxBytes, MaxDepth: 16, MaxMembers: 512}) != nil {
		return transport.FabricHostedPublication{}, hostedProfileError()
	}
	return out, nil
}

// PreparePublication journals the EXACT encrypted publication before any send.
// Genuine kernel owner administration and original worker proof are mandatory.
// A trusted composition callback prepares ciphertext only on the first request;
// retries and process restarts retain its original request ID, epoch and bytes.
// Chunking bounds each signed root value without limiting ordinary descriptors
// to the root's individual record size. All chunks and marker commit atomically.
func (s *HostedProfiles) PreparePublication(ctx context.Context, access *fabricauth.OwnerAdministration, scope registry.DescriptorBatchScope, expected fabric.Revision, prepare func(context.Context, HostedProfile) (transport.FabricHostedPublication, error)) (transport.FabricHostedPublication, error) {
	var out transport.FabricHostedPublication
	if s == nil || access == nil || prepare == nil || len(expected) > 256 || access.VerifyCurrent(ctx) != nil || !access.MatchesAuthority(s.root) {
		return out, hostedProfileError()
	}
	profile, _, err := s.Get(ctx, scope)
	if err != nil {
		return out, err
	}
	if err = s.probe(ctx, profile); err != nil {
		return out, err
	}
	owner, err := s.owner(ctx)
	if err != nil {
		return out, err
	}
	with := func(next func(*registry.AuthorityTx) error) error {
		return s.store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{Endpoint: scope.Endpoint, ExpectedRevision: scope.ExpectedEndpointRevision, BindingID: scope.BindingID, MaxOperations: 128, Timeout: 5 * time.Second}, next)
	}
	var fingerprint [32]byte
	missing := false
	err = with(func(tx *registry.AuthorityTx) error {
		if !access.MatchesAuthority(s.root) {
			return hostedProfileError()
		}
		actual, row, err := s.decode(tx, scope)
		if err != nil || actual != profile {
			return hostedProfileError()
		}
		fingerprint = publicationProfileDigest(actual, row)
		out, err = s.readPublication(tx, scope, fingerprint, expected)
		var typed *fabric.Error
		if errors.As(err, &typed) && typed.Code == fabric.CodeNotFound {
			missing = true
			return nil
		}
		if err == nil && !publicationMatches(out, scope, profile, s.root, expected) {
			return hostedProfileError()
		}
		return err
	})
	if err != nil || !missing {
		return out, err
	}
	prepared, err := prepare(ctx, profile)
	if err != nil {
		return out, err
	}
	if !publicationMatches(prepared, scope, profile, s.root, expected) {
		return out, hostedProfileError()
	}
	raw, err := json.Marshal(prepared)
	if err != nil || len(raw) > hostedPublicationMaxBytes {
		return out, hostedProfileError()
	}
	defer clear(raw)
	key := hostedPublicationKey(scope)
	cipher, err := s.protector.Seal(s.publicationAAD(key), raw)
	if err != nil {
		return out, err
	}
	defer clear(cipher)
	if len(cipher) > hostedPublicationMaxBytes+1024 {
		return out, hostedProfileError()
	}
	marker := hostedPublicationMarker{1, len(cipher), (len(cipher) + hostedPublicationChunkBytes - 1) / hostedPublicationChunkBytes, sha256.Sum256(cipher), fingerprint, expected}
	if access.VerifyCurrent(ctx) != nil {
		return out, hostedProfileError()
	}
	if err = s.probe(ctx, profile); err != nil {
		return out, err
	}
	err = with(func(tx *registry.AuthorityTx) error {
		if !access.MatchesAuthority(s.root) {
			return hostedProfileError()
		}
		actual, row, err := s.decode(tx, scope)
		if err != nil || actual != profile || publicationProfileDigest(actual, row) != fingerprint {
			return hostedProfileError()
		}
		retained, err := s.readPublication(tx, scope, fingerprint, expected)
		if err == nil {
			if !publicationMatches(retained, scope, profile, s.root, expected) {
				return hostedProfileError()
			}
			out = retained
			return nil
		}
		var typed *fabric.Error
		if !errors.As(err, &typed) || typed.Code != fabric.CodeNotFound {
			return err
		}
		for i := 0; i < marker.Chunks; i++ {
			value, _ := json.Marshal(cipher[i*hostedPublicationChunkBytes : min((i+1)*hostedPublicationChunkBytes, len(cipher))])
			if _, err = tx.CAS(publicationChunkKey(key, i), 0, value, false); err != nil {
				return err
			}
		}
		value, _ := json.Marshal(marker)
		if _, err = tx.CAS(key, 0, value, false); err != nil {
			return err
		}
		out = prepared
		return nil
	})
	return out, err
}
