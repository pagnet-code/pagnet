//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

// validateDirectReconcileEnrollmentReadiness validates public reader evidence.
// Challenge expiry relative to now belongs to the caller: a proof receipt may
// have been received during an already expired challenge's validity interval.
func validateDirectReconcileEnrollmentReadiness(b directEndpointReconcileBinding, publication []byte, role string, e directhttp.Enrollment, now time.Time) ([]byte, time.Time, error) {
	reject := func() ([]byte, time.Time, error) { return nil, time.Time{}, errDirectEndpointReconcileBinding }
	raw, err := b.Descriptor.CanonicalBytes()
	hash := sha256.Sum256(raw)
	expires, expiryErr := time.Parse(time.RFC3339Nano, b.Descriptor.ExpiresAt)
	channel, channelErr := transport.DirectChannelIDV2(b.Descriptor)
	a := e.Authority
	if (role != "S" && role != "P") || err != nil || expiryErr != nil || channelErr != nil || !bytes.Equal(raw, b.DescriptorBytes) || hash != b.DescriptorHash || e.DescriptorHash != base64.RawURLEncoding.EncodeToString(hash[:]) || !directReconcileEnrollmentTime(e.ObservedAt) || e.ObservedAt.After(now) || !e.ObservedAt.Before(expires) || !directReconcileEnrollmentTime(a.ExpiresAt) || a.ParentGrantID != b.Descriptor.ParentGrantID || a.GrantGeneration != b.Descriptor.GrantGeneration || a.ChannelID != channel || a.ChannelGeneration != b.Descriptor.ChannelGeneration || a.EpochID != b.Descriptor.EpochID || !a.ExpiresAt.Equal(expires) || a.ParentGrantID != b.Authority.ParentGrantID || a.GrantGeneration != b.Authority.GrantGeneration || a.ChannelID != b.Authority.ChannelID || a.ChannelGeneration != b.Authority.ChannelGeneration || a.EpochID != b.Authority.EpochID || !a.ExpiresAt.Equal(b.Authority.ExpiresAt) {
		return reject()
	}
	if e.PublicationHash != nil && !directReconcileEnrollmentDigest(*e.PublicationHash) {
		return reject()
	}
	if e.Challenge == nil {
		if e.Proof != nil || e.Activation != nil {
			return reject()
		}
		return nil, time.Time{}, nil
	}
	if !reconcilePublicationHash(e, publication) {
		return reject()
	}
	challenge, challengeExpiry, err := validateDirectReconcileChallengeBinding(b, publication, role, e.Challenge.Challenge, e.ObservedAt)
	transcript := sha256.Sum256(challenge)
	if err != nil || e.Challenge.TranscriptHash != base64.RawURLEncoding.EncodeToString(transcript[:]) {
		return reject()
	}
	if e.Proof != nil {
		issued, _ := time.Parse(time.RFC3339Nano, e.Challenge.Challenge.IssuedAt)
		p := e.Proof
		if !directReconcileEnrollmentDigest(p.Digest) || !directReconcileEnrollmentTime(p.ReceivedAt) || p.ReceivedAt.Before(issued) || !p.ReceivedAt.Before(challengeExpiry) || p.ReceivedAt.After(e.ObservedAt) {
			return reject()
		}
	}
	if e.Activation != nil {
		x := e.Activation
		if e.Proof == nil || !directReconcileEnrollmentTime(x.ActivatedAt) || !directReconcileEnrollmentTime(x.ExpiresAt) || x.ActivatedAt.Before(e.Proof.ReceivedAt) || x.ActivatedAt.After(e.ObservedAt) || !x.ExpiresAt.After(x.ActivatedAt) || !x.ExpiresAt.Equal(a.ExpiresAt) {
			return reject()
		}
	}
	return challenge, challengeExpiry, nil
}

func directReconcileEnrollmentTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && offset == 0
}

func directReconcileEnrollmentDigest(s string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(raw) == sha256.Size && base64.RawURLEncoding.EncodeToString(raw) == s
}
