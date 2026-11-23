package sdk

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/transport"
)

func TestEnrollmentTransportErrorPreservesCause(t *testing.T) {
	cause := errors.New("proof write failed")
	err := fmt.Errorf("enrollment: %w", &enrollmentTransportError{cause: cause})
	var transportErr *enrollmentTransportError
	if !errors.As(err, &transportErr) || !errors.Is(err, cause) {
		t.Fatalf("proof transport error lost classification or cause: %v", err)
	}
}

func TestCryptoEnrollmentProofWriteFailureReconnects(t *testing.T) {
	for _, queued := range []bool{false, true} {
		name := "direct"
		if queued {
			name = "queued"
		}
		t.Run(name, func(t *testing.T) {
			fs := newFakeServer(t)
			network := fs.createNetwork("enrolled", true)
			principal, credential := fs.createPrincipal("service", "svc", network)
			client := mustConnect(t, fs, credential, t.TempDir())
			first := waitForCryptoReady(t, fs, principal)
			client.connMu.Lock()
			pc := client.cur
			client.connMu.Unlock()
			fs.mu.Lock()
			ep := fs.endpoints[first]
			key, epoch := fs.epochKey, fs.epochID
			fs.mu.Unlock()

			// Use a fresh network so ownership proves that answerChallenge has
			// decrypted and validated the challenge before we close the socket.
			pendingNetwork := fs.createNetwork("pending-enrollment", true)
			aad := e2ee.AAD{ProtocolVersion: transport.ProtocolVersion, TenantID: fakeTenantID,
				NetworkID: pendingNetwork, ObjectType: "e2ee_challenge", KeyEpochID: epoch}
			envelope, err := e2ee.Encrypt([]byte("enrollment challenge"), key, aad)
			if err != nil {
				t.Fatal(err)
			}
			challenge := EndpointCryptoChallengePayload{NetworkID: pendingNetwork,
				Challenge: e2ee.Challenge{Envelope: envelope, AAD: aad, Nonce: []byte("nonce")}}
			if !queued {
				if err := client.kr.StoreEpoch(pendingNetwork, epoch, key); err != nil {
					t.Fatal(err)
				}
			}

			// Hold the proof write until sendRegister closes this connection.
			// readLoop cannot return (and the supervisor cannot replace cur)
			// until the write is released and fails on the closed socket.
			pc.sendMu.Lock()
			locked := true
			defer func() {
				if locked {
					pc.sendMu.Unlock()
				}
			}()
			if err := fs.sendTo(ep, MsgEndpointCryptoChallenge, challenge); err != nil {
				t.Fatal(err)
			}
			if queued {
				waitFor(t, time.Second, "queued enrollment challenge", func() bool {
					client.pendingMu.Lock()
					defer client.pendingMu.Unlock()
					_, ok := client.pendingChallenges[pendingNetwork]
					return ok
				})
				enc, ciphertext, err := e2ee.HPKEWrap(client.identityPub, []byte(enrollmentInfo), nil, key[:])
				if err != nil {
					t.Fatal(err)
				}
				if err := fs.sendTo(ep, MsgEndpointCryptoKeyPackage, EndpointCryptoKeyPackagePayload{
					NetworkID: pendingNetwork, EpochID: epoch,
					WrappedKey: transport.CryptoHPKEWrap{Enc: enc, Ciphertext: ciphertext},
				}); err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, time.Second, "authenticated enrollment challenge", func() bool {
				return client.authorizedNetworkTenant(pendingNetwork) == fakeTenantID
			})
			if err := client.sendRegister(); err != nil {
				t.Fatal(err)
			}
			pc.sendMu.Unlock()
			locked = false
			select {
			case <-pc.dead:
			case <-time.After(time.Second):
				t.Fatal("proof write failure did not end the old read loop")
			}
			if err := client.Err(); err != nil {
				t.Fatalf("proof write failure permanently stopped client: %v", err)
			}
			waitFor(t, 5*time.Second, "reconnect and successful enrollment", func() bool {
				current := fs.endpointForPrincipal(principal)
				return current != "" && current != first && client.EndpointID() == current &&
					client.connected.Load() && fs.cryptoReadyFor(current)
			})
			if err := client.Err(); err != nil {
				t.Fatalf("client failed after reconnect: %v", err)
			}
		})
	}
}
