package directhttp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/pagnet-code/pagnet/transport"
	"strings"
	"testing"
	"time"
)

func directV2TestID(n byte) string {
	return "00000000-0000-4000-8000-0000000000" + hex.EncodeToString([]byte{n})
}
func directV2TestBinary(n byte, size int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{n}, size))
}
func directV2TestPoint(n byte) string {
	b := make([]byte, 32)
	b[0] = n
	return base64.RawURLEncoding.EncodeToString(b)
}
func directV2TestFixture(t *testing.T) (transport.DirectChannelPublicationV2, transport.DirectChannelReadinessChallengeV2, transport.DirectChannelReadinessProofV2, []byte, time.Time) {
	t.Helper()
	limits := transport.DirectChannelLimitsV2{4096, 5, 100, 1048576, 2, 8}
	endpoint := func(n byte) transport.DirectChannelEndpointV2 {
		return transport.DirectChannelEndpointV2{directV2TestID(n), directV2TestID(n + 1), directV2TestID(n + 2), directV2TestPoint(n), directV2TestID(n + 3), strings.Repeat("ab", 32)}
	}
	d := transport.DirectChannelDescriptorV2{Domain: transport.DirectChannelDomainV2, Suite: transport.DirectChannelSuiteV2, ParentGrantID: directV2TestID(1), GrantGeneration: "1", ChannelGeneration: "2", DirectIntentID: directV2TestID(2), NetworkID: directV2TestID(3), AuthorizationDigest: strings.Repeat("cd", 32), S: endpoint(9), P: endpoint(10), EpochID: "01900000-0000-7000-8000-000000000001", ExpiresAt: "2030-01-01T01:00:00Z", Budget: transport.DirectChannelBudgetV2{directV2TestID(4), "3", strings.Repeat("ef", 32), "2030-01-01T02:00:00Z", transport.DirectChannelCountingVersionV2, limits}, Limits: limits}
	p := transport.DirectChannelPublicationV2{d, directV2TestPoint(11), directV2TestBinary(7, 48)}
	channel, err := transport.DirectChannelIDV2(d)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := transport.DescriptorHashV2(d)
	if err != nil {
		t.Fatal(err)
	}
	ph, err := transport.PublicationHashV2(p)
	if err != nil {
		t.Fatal(err)
	}
	c := transport.DirectChannelReadinessChallengeV2{transport.DirectChannelDomainV2 + "/proof", directV2TestID(5), "S", d.S.PrincipalID, d.S.EndpointID, d.S.CredentialID, channel, d.ParentGrantID, d.GrantGeneration, d.ChannelGeneration, d.DirectIntentID, dh, ph, d.EpochID, directV2TestBinary(8, 32), "2030-01-01T00:00:00Z", "2030-01-01T00:05:00Z"}
	key := bytes.Repeat([]byte{0x42}, 32)
	return p, c, directV2TestSign(t, c, key), key, time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC)
}
func directV2TestSign(t *testing.T, c transport.DirectChannelReadinessChallengeV2, key []byte) transport.DirectChannelReadinessProofV2 {
	t.Helper()
	raw, err := c.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return transport.DirectChannelReadinessProofV2{transport.DirectChannelReadinessProtocolV2, c.ChallengeID, base64.RawURLEncoding.EncodeToString(digest[:]), base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
}
