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
	limits := transport.DirectChannelLimitsV2{MaxMessageWireBytes: 4096, MaxMessagesPerMinute: 5, MaxMessagesPerDay: 100, MaxWireBytesPerDay: 1048576, MaxInFlight: 2, MaxTurnsPerThread: 8}
	endpoint := func(n byte) transport.DirectChannelEndpointV2 {
		return transport.DirectChannelEndpointV2{TenantID: directV2TestID(n), PrincipalID: directV2TestID(n + 1), EndpointID: directV2TestID(n + 2), PublicKey: directV2TestPoint(n), CredentialID: directV2TestID(n + 3), KeyEvidenceDigest: strings.Repeat("ab", 32)}
	}
	d := transport.DirectChannelDescriptorV2{Domain: transport.DirectChannelDomainV2, Suite: transport.DirectChannelSuiteV2, ParentGrantID: directV2TestID(1), GrantGeneration: "1", ChannelGeneration: "2", DirectIntentID: directV2TestID(2), NetworkID: directV2TestID(3), AuthorizationDigest: strings.Repeat("cd", 32), S: endpoint(9), P: endpoint(10), EpochID: "01900000-0000-7000-8000-000000000001", ExpiresAt: "2030-01-01T01:00:00Z", Budget: transport.DirectChannelBudgetV2{AgreementID: directV2TestID(4), AcceptedRevision: "3", TermsDigest: strings.Repeat("ef", 32), ExpiresAt: "2030-01-01T02:00:00Z", CountingVersion: transport.DirectChannelCountingVersionV2, GrantLimits: limits}, Limits: limits}
	p := transport.DirectChannelPublicationV2{Descriptor: d, Enc: directV2TestPoint(11), Ciphertext: directV2TestBinary(7, 48)}
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
	c := transport.DirectChannelReadinessChallengeV2{Domain: transport.DirectChannelDomainV2 + "/proof", ChallengeID: directV2TestID(5), Role: "S", PrincipalID: d.S.PrincipalID, EndpointID: d.S.EndpointID, CredentialID: d.S.CredentialID, ChannelID: channel, ParentGrantID: d.ParentGrantID, GrantGeneration: d.GrantGeneration, ChannelGeneration: d.ChannelGeneration, DirectIntentID: d.DirectIntentID, DescriptorHash: dh, PublicationHash: ph, EpochID: d.EpochID, Nonce: directV2TestBinary(8, 32), IssuedAt: "2030-01-01T00:00:00Z", ExpiresAt: "2030-01-01T00:05:00Z"}
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
	return transport.DirectChannelReadinessProofV2{ProtocolVersion: transport.DirectChannelReadinessProtocolV2, ChallengeID: c.ChallengeID, TranscriptHash: base64.RawURLEncoding.EncodeToString(digest[:]), Confirmation: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
}
