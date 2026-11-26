//go:build linux || darwin

package daemon

import (
	"bytes"
	"crypto/sha256"
	"time"

	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

// validateDirectReconcileActivation binds an authenticated activation response
// to the descriptor and the caller's verified enrollment proof receipt.
func validateDirectReconcileActivation(b directEndpointReconcileBinding, e directhttp.Enrollment, value directhttp.Activation, upper time.Time) error {
	raw, err := b.Descriptor.CanonicalBytes()
	expires, expiryErr := time.Parse(time.RFC3339Nano, b.Descriptor.ExpiresAt)
	channel, channelErr := transport.DirectChannelIDV2(b.Descriptor)
	if err != nil || expiryErr != nil || channelErr != nil || !bytes.Equal(raw, b.DescriptorBytes) || sha256.Sum256(raw) != b.DescriptorHash || e.PublicationHash == nil || e.Challenge == nil || e.Proof == nil || upper.IsZero() {
		return errDirectEndpointReconcileBinding
	}
	if !directReconcileEnrollmentTime(e.Proof.ReceivedAt) || !directReconcileEnrollmentTime(value.ActivatedAt) || !directReconcileEnrollmentTime(value.ExpiresAt) || value.ActivatedAt.Before(e.Proof.ReceivedAt) || value.ActivatedAt.After(upper) || !value.ExpiresAt.After(value.ActivatedAt) || !value.ExpiresAt.Equal(expires) || !value.ExpiresAt.Equal(e.Authority.ExpiresAt) || !value.ExpiresAt.Equal(b.Authority.ExpiresAt) || value.ChannelID != channel || value.ChannelID != e.Authority.ChannelID || value.ChannelID != b.Authority.ChannelID {
		return errDirectEndpointReconcileBinding
	}
	return nil
}
