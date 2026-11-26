//go:build linux || darwin

package daemon

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/nativedirect"
	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

type reservationCompositionInbox struct{ delivery transport.DirectDeliveryV2 }

func (f reservationCompositionInbox) Inbox(_ context.Context, _ string, q transport.DirectInboxRequestV2) (transport.DirectInboxPageV2, error) {
	return transport.DirectInboxPageV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/inbox-page", Context: q.Context, Recipient: q.Recipient, Deliveries: []transport.DirectDeliveryV2{f.delivery}}, nil
}

// The HTTP reader/inbox supply authenticated-response fixtures. Everything from
// consent authority and endpoint custody through HPKE/ASK decryption, source
// construction, dispatch journaling and the authenticated controller is real.
// The worker receiver is a protocol fixture and accepts only ownership and
// reservation requests; no native submission is available to this composition.
func TestDirectReservationComposition(t *testing.T) {
	for _, mode := range []string{"reserved", "invalid ciphertext", "postflight revocation"} {
		t.Run(mode, func(t *testing.T) {
			f, evidence, enrollment := newReconcileObservationTargetFixture(t)
			private, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			descriptor := evidence.Descriptor
			descriptor.S.PublicKey = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
			enrollment = reconcileEnrollment(t, descriptor, time.Now())
			evidence, err = validateDirectTargetReconcileBindingContext(t.Context(), f.s, f.captured, f.target, descriptor, enrollment, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			raw, err := descriptor.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			sourceMaterial, publication, err := directchannelcrypto.Prepare(raw, descriptor, private.Bytes(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer sourceMaterial.Clear()
			reader := observationReader(t, f.s, evidence, enrollment)
			reader.publication, err = transport.DecodeDirectChannelPublicationV2(publication)
			if err != nil {
				t.Fatal(err)
			}
			reader.enrollment = publishedEnrollment(enrollment, publication)
			consent, err := newDirectChannelConsentStore(t.Context(), f.d.nativeRegistry, f.d.ServerURL, f.captured.Session)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := deriveDirectChannelConsentBinding(f.s, f.captured, consent.installation, evidence, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = consent.Enable(t.Context(), binding, 0, "enable"); err != nil {
				t.Fatal(err)
			}
			// Replace the ownership-only fixture receiver with a reservation-aware one.
			_ = f.token.proxy.controller.Close()
			snapshot := reconcileOperationSnapshot(t, f.token)
			reserves := make(chan nativedirect.NativeDirectASKSource, 1)
			f.token.proxy.controller = endpointRPCController(t, f.token.proxy.scope, f.token.proxy.connection, func(server net.Conn, _ *NativeObservationConnection) {
				var saved *sessionworker.DirectASKReservation
				for {
					var request sessionworker.Request
					if swReadFrame(server, &request) != nil {
						return
					}
					var response sessionworker.Response
					switch request.Type {
					case "ownership_verify":
						response.OwnershipVerify = &sessionworker.NativeOwnershipVerifyResult{Snapshot: snapshot}
					case "direct_ask_reserve_v1":
						if request.DirectASK == nil || request.DirectASK.Source.ValidateWire(request.DirectASK.Wire) != nil {
							t.Error("invalid source at worker")
							return
						}
						saved = &sessionworker.DirectASKReservation{Source: request.DirectASK.Source, Wire: request.DirectASK.Wire, State: "reserved"}
						response.DirectASK = &sessionworker.DirectASKResult{Found: true, Reservation: saved}
						reserves <- saved.Source
						if mode == "postflight revocation" {
							f.s.Remove()
						}
					case "direct_ask_lookup_v1":
						response.DirectASK = &sessionworker.DirectASKResult{Found: saved != nil, Reservation: saved}
					default:
						t.Errorf("unexpected worker request %s", request.Type)
						return
					}
					if swWriteFrame(server, response) != nil {
						return
					}
				}
			})
			c, err := newDirectTargetReservationCoordinatorWithReader(t.Context(), f.d, f.captured, f.s, f.target, consent, 1, reader)
			if err != nil {
				t.Fatal(err)
			}
			b := c.deps.Binding
			id := uuid.NewString()
			header := transport.DirectChannelMessageHeaderV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/message", Kind: "ASK", ChannelID: b.Context.ChannelID, DescriptorHash: b.Context.DescriptorHash, EpochID: descriptor.EpochID, MessageID: id, RootID: id, SenderRole: "S"}
			aad, err := header.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			key, err := hkdf.Key(sha256.New, sourceMaterial.Key[:], sourceMaterial.Hash[:], transport.DirectChannelDomainV2+"/ASK", 32)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(key)
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, aead.NonceSize())
			if _, err = rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			plaintext := []byte("authenticated remote question")
			ciphertext := aead.Seal(nil, nonce, plaintext, aad)
			if mode == "invalid ciphertext" {
				ciphertext[0] ^= 1
			}
			ask := transport.DirectChannelMessageV2{Header: header, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext)}
			wire, err := ask.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			hash, _ := transport.DirectChannelMessageHashV2(ask)
			now := time.Now().UTC()
			expiry := now.Add(time.Minute)
			descriptorExpiry, _ := time.Parse(time.RFC3339Nano, descriptor.ExpiresAt)
			if descriptorExpiry.Before(expiry) {
				expiry = descriptorExpiry
			}
			sender := transport.DirectDeliveryPartyV2{Role: "S", PrincipalID: descriptor.S.PrincipalID, EndpointID: descriptor.S.EndpointID, CredentialID: descriptor.S.CredentialID}
			receipt := transport.DirectMessageAdmissionReceiptV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/admission", AdmissionState: "admitted", AdmittedAt: now.Format(time.RFC3339Nano), ExpiresAt: expiry.Format(time.RFC3339Nano), Binding: transport.DirectMessageBindingV2{Context: b.Context, MessageID: id, WireHash: hash, WireBytes: len(wire), Sender: sender, Recipient: b.Recipient}}
			c.deps.Client = reservationCompositionInbox{delivery: transport.DirectDeliveryV2{Version: 2, Domain: transport.DirectChannelDomainV2 + "/delivery/item", Admission: receipt, DeliveryState: "pending", Wire: wire}}
			journalKey, found, err := c.ReceiveOne(t.Context())
			if mode == "invalid ciphertext" {
				if err == nil || found {
					t.Fatal("invalid ciphertext accepted")
				}
				select {
				case <-reserves:
					t.Fatal("invalid ciphertext reserved")
				default:
				}
				return
			}
			if !found {
				t.Fatal("authenticated delivery not journaled", err)
			}
			var got nativedirect.NativeDirectASKSource
			select {
			case got = <-reserves:
			case <-time.After(2 * time.Second):
				t.Fatal("no worker reserve", err)
			}
			expectedDigest := sha256.Sum256(plaintext)
			expectedIssue := sha256.Sum256(mustRuntimeJSON(f.target))
			if got.InputDigest != hex.EncodeToString(expectedDigest[:]) || got.EndpointIssueID != hex.EncodeToString(expectedIssue[:]) || got.EndpointLeaseID != f.s.binding.leaseID || got.Scope != snapshot.Scope || got.NativePID != snapshot.PID || got.NativeStartIdentity != snapshot.NativeStartIdentity {
				t.Fatal("real source derivation mismatch")
			}
			record, loadErr := c.store.load(context.Background(), journalKey)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if mode == "postflight revocation" {
				if err == nil || record.Stage != "attempted" {
					t.Fatal("revoked response trusted", err, record.Stage)
				}
			} else {
				if err != nil || record.Stage != "reserved" {
					t.Fatal("real composition failed", err, record.Stage)
				}
				if err = c.Recover(t.Context(), journalKey); err != nil {
					t.Fatal("real lookup failed", err)
				}
			}
		})
	}
}
