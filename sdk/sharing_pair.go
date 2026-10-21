package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SharingPairStatus is the authenticated server consent and pin snapshot.
// Pins rely on the server directory on first contact. Fingerprints can be
// compared through a separate trusted channel before enrollment.
type SharingPairStatus struct {
	GrantID              string            `json:"grantId"`
	InvitationID         string            `json:"invitationId"`
	NetworkID            string            `json:"networkId"`
	OwningTenantID       string            `json:"owningTenantId"`
	IssuerTenantID       string            `json:"issuerTenantId"`
	RecipientTenantID    string            `json:"recipientTenantId"`
	IssuerPrincipalID    string            `json:"issuerPrincipalId"`
	RecipientPrincipalID string            `json:"recipientPrincipalId"`
	Generation           int64             `json:"generation"`
	State                string            `json:"state"`
	ActivationEpoch      *string           `json:"activationEpoch"`
	ExpiresAt            string            `json:"expiresAt"`
	Permissions          []string          `json:"permissions"`
	Limits               SharingPairLimits `json:"limits"`
	IssuerPublicKey      *string           `json:"issuerPublicKey"`
	RecipientPublicKey   *string           `json:"recipientPublicKey"`
}

// SharingPairLimits describes the server consent limits.
type SharingPairLimits = pairLimits

// SharingPairEnrollment is pending until both parties have proved possession.
type SharingPairEnrollment struct {
	Status               SharingPairStatus
	Pending              bool
	IssuerFingerprint    string
	RecipientFingerprint string
}

func (s SharingPairStatus) descriptor(epoch string) pairDescriptor {
	d := pairDescriptor{Version: 1, Suite: pairSuite, GrantID: s.GrantID, Generation: s.Generation, InvitationID: s.InvitationID, NetworkID: s.NetworkID, OwningTenantID: s.OwningTenantID, IssuerTenantID: s.IssuerTenantID, RecipientTenantID: s.RecipientTenantID, IssuerPrincipalID: s.IssuerPrincipalID, RecipientPrincipalID: s.RecipientPrincipalID, EpochID: epoch, ExpiresAt: s.ExpiresAt, Permissions: s.Permissions, Limits: s.Limits}
	if s.IssuerPublicKey != nil {
		d.IssuerPublicKey = *s.IssuerPublicKey
	}
	if s.RecipientPublicKey != nil {
		d.RecipientPublicKey = *s.RecipientPublicKey
	}
	return d
}

func pairEnrollment(s SharingPairStatus) SharingPairEnrollment {
	r := SharingPairEnrollment{Status: s, Pending: true}
	for i, pin := range []*string{s.IssuerPublicKey, s.RecipientPublicKey} {
		if pin != nil {
			if key, err := pairKey(*pin); err == nil {
				h := sha256.Sum256(key)
				if i == 0 {
					r.IssuerFingerprint = hex.EncodeToString(h[:])
				} else {
					r.RecipientFingerprint = hex.EncodeToString(h[:])
				}
			}
		}
	}
	return r
}

// ListSharingPairs returns one page and the server cursor for the next page.
func (c *Client) ListSharingPairs(ctx context.Context, cursor string) ([]SharingPairStatus, string, error) {
	if !c.connected.Load() || c.endpointID.Load() == "" {
		return nil, "", errors.New("sdk: sharing enrollment requires a connected endpoint")
	}
	var out []SharingPairStatus
	var headers http.Header
	err := c.rest.doWithHeaders(ctx, http.MethodGet, "/sharing-pairs?"+url.Values{"endpointId": {c.endpointID.Load()}, "cursor": {cursor}}.Encode(), nil, &out, &headers)
	return out, headers.Get("X-Next-Cursor"), err
}

type sharingPairEpoch struct {
	EpochID        string `json:"epochId"`
	Descriptor     []byte `json:"descriptor"`
	DescriptorHash []byte `json:"descriptorHash"`
	Enc            []byte `json:"enc"`
	Ciphertext     []byte `json:"ciphertext"`
}

// EnrollSharingPair explicitly advances one enrollment attempt. Pending results
// require a later explicit call; this operation never polls for the peer.
func (c *Client) EnrollSharingPair(ctx context.Context, grantID string) (SharingPairEnrollment, error) {
	var result SharingPairEnrollment
	if !validPairPathID(grantID) {
		return result, errors.New("sdk: invalid sharing grant ID")
	}
	if !c.connected.Load() || c.endpointID.Load() == "" || c.principalID.Load() == "" {
		return result, errors.New("sdk: sharing enrollment requires a connected endpoint")
	}
	cred, _ := c.credential.Load().(string)
	if !strings.HasPrefix(cred, "pgn_epd_v1_") {
		return result, errors.New("sdk: sharing enrollment requires an endpoint credential")
	}
	endpoint, principal, connection := c.endpointID.Load(), c.principalID.Load(), c.connGeneration.Load()
	sameConnection := func() bool {
		return c.connected.Load() && c.endpointID.Load() == endpoint && c.connGeneration.Load() == connection
	}
	var status SharingPairStatus
	cursor := ""
	for {
		page, next, err := c.ListSharingPairs(ctx, cursor)
		if err != nil {
			return result, err
		}
		for _, s := range page {
			if s.GrantID == grantID {
				status = s
				break
			}
		}
		if status.GrantID != "" || next == "" {
			break
		}
		if next <= cursor {
			return result, errors.New("sdk: invalid sharing page cursor")
		}
		cursor = next
	}
	if status.GrantID == "" {
		return result, errors.New("sdk: sharing pair not found")
	}
	generation := status.Generation
	if generation < 1 {
		return result, errors.New("sdk: invalid sharing generation")
	}
	base := "/sharing-pairs/" + grantID
	query := "?" + url.Values{"generation": {strconv.FormatInt(generation, 10)}, "endpointId": {endpoint}}.Encode()
	request := map[string]any{"generation": generation, "endpointId": endpoint}
	getStatus := func() error { return c.rest.do(ctx, http.MethodGet, base+"/status"+query, nil, &status) }
	if err := getStatus(); err != nil {
		return result, err
	}
	if err := c.rest.do(ctx, http.MethodPost, base+"/pin", request, &status); err != nil {
		return result, err
	}
	if err := getStatus(); err != nil {
		return result, err
	}
	result = pairEnrollment(status)
	if status.GrantID != grantID || status.Generation != generation || (principal != status.IssuerPrincipalID && principal != status.RecipientPrincipalID) {
		return result, errors.New("sdk: sharing status binding mismatch")
	}
	ownPin := status.RecipientPublicKey
	issuer := principal == status.IssuerPrincipalID
	if issuer {
		ownPin = status.IssuerPublicKey
	}
	if ownPin == nil || *ownPin != base64.RawURLEncoding.EncodeToString(c.identityPub) {
		return result, errors.New("sdk: sharing identity pin mismatch")
	}
	if status.IssuerPublicKey == nil || status.RecipientPublicKey == nil {
		return result, nil
	}
	var epoch sharingPairEpoch
	err := c.rest.do(ctx, http.MethodGet, base+"/epoch"+query, nil, &epoch)
	if err != nil {
		var re *restError
		if !errors.As(err, &re) || re.status != http.StatusNotFound {
			return result, err
		}
		if !issuer {
			return result, nil
		}
		// Resume a durable unpublished package before creating any fresh material.
		pending, pendingErr := c.kr.loadPendingPairEpoch(grantID, uint64(generation))
		var material pairIssuerMaterial
		if pendingErr == nil {
			if err = json.Unmarshal(pending.Publication, &material.Package); err != nil {
				return result, err
			}
			material.ReadinessVerifier, err = pairReadinessKey(pending)
		} else {
			// Only an unreserved binding permits a new epoch. Corrupt/missing reserved
			// records fail closed even if the server has not received publication yet.
			unlock, lockErr := c.kr.lockPendingPairs()
			if lockErr != nil {
				return result, lockErr
			}
			index, _, indexErr := c.kr.readPendingPairIndex()
			reserved := index[filepath.Base(c.kr.pendingPairDir(grantID, uint64(generation)))]
			unlock()
			if indexErr != nil {
				return result, indexErr
			}
			if reserved {
				return result, pendingErr
			}
			id, idErr := uuid.NewV7()
			if idErr != nil {
				return result, idErr
			}
			descriptorRequest := map[string]any{"generation": generation, "endpointId": endpoint, "epochId": id.String()}
			var raw struct {
				Descriptor []byte `json:"descriptor"`
			}
			if err = c.rest.do(ctx, http.MethodPost, base+"/descriptor", descriptorRequest, &raw); err != nil {
				return result, err
			}
			key := make([]byte, 32)
			if _, err = rand.Read(key); err != nil {
				return result, err
			}
			material, err = c.kr.prepareIssuerPairEpoch(raw.Descriptor, status.descriptor(id.String()), c.identityPriv, key, time.Now())
		}
		if err != nil {
			return result, err
		}
		epoch = sharingPairEpoch{EpochID: material.Package.EpochID, Descriptor: material.Package.Descriptor, Enc: material.Package.Enc, Ciphertext: material.Package.Ciphertext}
		if _, _, _, err = validatePairDescriptor(epoch.Descriptor, status.descriptor(epoch.EpochID), time.Now()); err != nil {
			return result, err
		}
		publication := map[string]any{"generation": generation, "endpointId": endpoint, "epochId": epoch.EpochID, "descriptor": epoch.Descriptor, "enc": epoch.Enc, "ciphertext": epoch.Ciphertext, "readinessVerifier": material.ReadinessVerifier}
		if err = c.rest.do(ctx, http.MethodPost, base+"/epoch", publication, &status); err != nil {
			// A lost publication response is resolved by reading the immutable package.
			if readErr := c.rest.do(ctx, http.MethodGet, base+"/epoch"+query, nil, &epoch); readErr != nil {
				return result, err
			}
		}
	}
	expected := result.Status.descriptor(epoch.EpochID)
	if _, _, _, err = validatePairDescriptor(epoch.Descriptor, expected, time.Now()); err != nil {
		return result, err
	}
	hash := sha256.Sum256(epoch.Descriptor)
	if len(epoch.DescriptorHash) > 0 && !bytes.Equal(epoch.DescriptorHash, hash[:]) {
		return result, errors.New("sdk: pair descriptor hash mismatch")
	}
	if issuer {
		p, loadErr := c.kr.loadPendingPairEpoch(grantID, uint64(generation))
		if loadErr != nil {
			return result, loadErr
		}
		var stored pairEpochPackage
		if json.Unmarshal(p.Publication, &stored) != nil || stored.EpochID != epoch.EpochID || !bytes.Equal(stored.Descriptor, epoch.Descriptor) || !bytes.Equal(stored.Enc, epoch.Enc) || !bytes.Equal(stored.Ciphertext, epoch.Ciphertext) {
			return result, errors.New("sdk: published pair package differs from durable record")
		}
	} else if err = c.kr.prepareRecipientPairEpoch(epoch.Descriptor, expected, c.identityPriv, epoch.Enc, epoch.Ciphertext, time.Now()); err != nil {
		return result, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		if !sameConnection() {
			return result, errors.New("sdk: sharing endpoint connection changed")
		}
		var challenge struct {
			ChallengeID string    `json:"challengeId"`
			Transcript  []byte    `json:"transcript"`
			ExpiresAt   time.Time `json:"expiresAt"`
		}
		if err = c.rest.do(ctx, http.MethodPost, base+"/challenge", request, &challenge); err != nil {
			return result, err
		}
		var transcript pairProofTranscript
		if json.Unmarshal(challenge.Transcript, &transcript) != nil {
			return result, errors.New("sdk: invalid sharing challenge")
		}
		credentialID, parseErr := uuid.Parse(transcript.CredentialID)
		if parseErr != nil || credentialID == uuid.Nil || credentialID.String() != transcript.CredentialID {
			return result, errors.New("sdk: invalid sharing challenge credential ID")
		}
		proof, proofErr := c.kr.pendingPairReadinessProof(expected, pairProofChallenge{challenge.ChallengeID, challenge.Transcript, challenge.ExpiresAt}, pairProofActor{principal, endpoint, transcript.CredentialID}, time.Now())
		if proofErr != nil {
			return result, proofErr
		}
		err = c.rest.do(ctx, http.MethodPost, base+"/prove", map[string]any{"generation": generation, "endpointId": endpoint, "challengeId": challenge.ChallengeID, "proof": proof}, &status)
		if err == nil {
			break
		}
		if statusErr := getStatus(); statusErr != nil {
			return result, err
		}
		if attempt == 1 {
			return result, err
		}
	}
	result = pairEnrollment(status)
	if status.GrantID != grantID || status.Generation != generation {
		return result, errors.New("sdk: sharing proof status binding mismatch")
	}
	if status.State != "active" {
		return result, nil
	}
	if status.ActivationEpoch == nil || *status.ActivationEpoch != epoch.EpochID {
		return result, errors.New("sdk: sharing activation epoch mismatch")
	}
	if _, _, _, err = validatePairDescriptor(epoch.Descriptor, status.descriptor(epoch.EpochID), time.Now()); err != nil {
		return result, err
	}
	if !sameConnection() {
		return result, errors.New("sdk: sharing endpoint connection changed")
	}
	if err = c.kr.activatePendingPairEpoch(grantID, uint64(generation), expected.NetworkID, epoch.EpochID, hash); err != nil {
		return result, err
	}
	c.cryptoMu.Lock()
	defer c.cryptoMu.Unlock()
	if !sameConnection() {
		return result, errors.New("sdk: sharing endpoint connection changed")
	}
	c.networkTenants.Store(expected.NetworkID, expected.OwningTenantID)
	if c.sharingReady == nil {
		c.sharingReady = make(map[string]int64)
	}
	c.sharingReady[expected.NetworkID] = connection
	result.Pending = false
	return result, nil
}
