package sdk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"encoding/base64"
)

type pairRESTFixture struct {
	t               *testing.T
	server          *httptest.Server
	status          SharingPairStatus
	epoch           *sharingPairEpoch
	verifier        []byte
	installed       map[string]bool
	pins            map[string]string
	challenges      map[string]pairProofChallenge
	proofs          int
	lostProof       bool
	lostEpoch       bool
	wrongDescriptor bool
	wrongKey        bool
}

func newPairRESTFixture(t *testing.T) (*pairRESTFixture, *Client, *Client) {
	t.Helper()
	d, _, issuerPrivate, recipientPrivate, _ := pairCryptoFixture(t)
	f := &pairRESTFixture{t: t, status: SharingPairStatus{GrantID: d.GrantID, Generation: d.Generation, InvitationID: d.InvitationID, NetworkID: d.NetworkID, OwningTenantID: d.OwningTenantID, IssuerTenantID: d.IssuerTenantID, RecipientTenantID: d.RecipientTenantID, IssuerPrincipalID: d.IssuerPrincipalID, RecipientPrincipalID: d.RecipientPrincipalID, ExpiresAt: d.ExpiresAt, Permissions: d.Permissions, Limits: d.Limits, State: "enrolling"}, installed: map[string]bool{}, challenges: map[string]pairProofChallenge{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	makeClient := func(principal string, private []byte) *Client {
		kr, err := newKeyring(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		key, err := ecdh.X25519().NewPrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		c := &Client{kr: kr, identityPriv: private, identityPub: key.PublicKey().Bytes()}
		c.principalID.Store(principal)
		c.endpointID.Store(principal + "-endpoint")
		c.credential.Store("pgn_epd_v1_" + principal)
		c.connected.Store(true)
		c.connGeneration.Store(1)
		c.rest = newRestClient(f.server.URL, "test", func() string { return c.credential.Load().(string) })
		return c
	}
	return f, makeClient(d.IssuerPrincipalID, issuerPrivate), makeClient(d.RecipientPrincipalID, recipientPrivate)
}

func (f *pairRESTFixture) serve(w http.ResponseWriter, r *http.Request) {
	principal := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer pgn_epd_v1_")
	var req struct {
		Generation        int64  `json:"generation"`
		EndpointID        string `json:"endpointId"`
		EpochID           string `json:"epochId"`
		Descriptor        []byte `json:"descriptor"`
		Enc               []byte `json:"enc"`
		Ciphertext        []byte `json:"ciphertext"`
		ReadinessVerifier []byte `json:"readinessVerifier"`
		ChallengeID       string `json:"challengeId"`
		Proof             []byte `json:"proof"`
	}
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			f.t.Error(err)
		}
	}
	write := func(v any) {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			f.t.Error(err)
		}
	}
	switch {
	case r.URL.Path == "/api/v1/sharing-pairs":
		write([]SharingPairStatus{f.status})
	case strings.HasSuffix(r.URL.Path, "/status"):
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/pin"):
		// Registered endpoint public keys come from a fixed fixture directory.
		pin := f.directoryPin(principal)
		if f.wrongKey {
			pin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}
		if principal == "issuer" {
			f.status.IssuerPublicKey = &pin
		} else {
			f.status.RecipientPublicKey = &pin
		}
		write(f.status)
	case strings.HasSuffix(r.URL.Path, "/descriptor"):
		raw, _ := json.Marshal(f.status.descriptor(req.EpochID))
		if f.wrongDescriptor {
			raw = append(raw, ' ')
		}
		write(map[string]any{"descriptor": raw})
	case strings.HasSuffix(r.URL.Path, "/epoch"):
		if r.Method == http.MethodPost {
			f.epoch = &sharingPairEpoch{EpochID: req.EpochID, Descriptor: req.Descriptor, Enc: req.Enc, Ciphertext: req.Ciphertext}
			hash := sha256.Sum256(req.Descriptor)
			f.epoch.DescriptorHash = hash[:]
			f.verifier = req.ReadinessVerifier
			if f.lostEpoch {
				f.lostEpoch = false
				http.Error(w, "lost response", 502)
				return
			}
			write(f.status)
		} else if f.epoch == nil {
			http.NotFound(w, r)
		} else {
			write(f.epoch)
		}
	case strings.HasSuffix(r.URL.Path, "/challenge"):
		actor := pairProofActor{principal, req.EndpointID, "00000000-0000-4000-8000-000000000001"}
		challenge := pairChallenge(f.t, f.status.descriptor(f.epoch.EpochID), f.epoch.Descriptor, actor, time.Now())
		f.challenges[principal] = challenge
		write(map[string]any{"challengeId": challenge.ID, "transcript": challenge.Transcript, "expiresAt": challenge.ExpiresAt})
	case strings.HasSuffix(r.URL.Path, "/prove"):
		challenge := f.challenges[principal]
		mac := hmac.New(sha256.New, f.verifier)
		mac.Write(challenge.Transcript)
		if !hmac.Equal(req.Proof, mac.Sum(nil)) {
			http.Error(w, "bad proof", 400)
			return
		}
		f.proofs++
		f.installed[principal] = true
		if f.installed["issuer"] && f.installed["recipient"] {
			f.status.State = "active"
			f.status.ActivationEpoch = &f.epoch.EpochID
		}
		if f.lostProof {
			f.lostProof = false
			http.Error(w, "lost response", 502)
			return
		}
		write(f.status)
	default:
		http.NotFound(w, r)
	}
}

// The directory is captured without exposing private keys on the wire.
func (f *pairRESTFixture) directoryPin(principal string) string { return f.pins[principal] }

func pairRESTClients(t *testing.T) (*pairRESTFixture, *Client, *Client) {
	f, i, r := newPairRESTFixture(t)
	f.pins = map[string]string{"issuer": encodePairPin(i.identityPub), "recipient": encodePairPin(r.identityPub)}
	return f, i, r
}

func TestSharingPairRESTOfflineRecipientReconnectAndLostResponses(t *testing.T) {
	f, i, r := pairRESTClients(t)
	ctx := context.Background()
	enroll := func(c *Client, pending bool) {
		t.Helper()
		result, err := c.EnrollSharingPair(ctx, "grant")
		if err != nil {
			t.Fatal(err)
		}
		if result.Pending != pending {
			t.Fatalf("pending=%v want %v", result.Pending, pending)
		}
	}
	enroll(i, true)
	if f.epoch != nil {
		t.Fatal("published before peer pin")
	}
	enroll(r, true)
	f.lostEpoch = true
	enroll(i, true)
	if i.cryptoReady("network") {
		t.Fatal("issuer ready before active")
	}
	f.lostProof = true
	enroll(r, false)
	if !r.cryptoReady("network") {
		t.Fatal("recipient not ready")
	}
	enroll(i, false)
	before := f.proofs
	i.connGeneration.Add(1)
	i.endpointID.Store("issuer-reconnected")
	if i.cryptoReady("network") {
		t.Fatal("reconnect retained readiness")
	}
	enroll(i, false)
	if f.proofs != before+1 {
		t.Fatal("reconnect skipped proof")
	}
	publication := *f.epoch
	i.kr, _ = newKeyring(t.TempDir())
	if _, err := i.EnrollSharingPair(ctx, "grant"); err == nil {
		t.Fatal("missing issuer record regenerated published package")
	}
	if !bytes.Equal(publication.Ciphertext, f.epoch.Ciphertext) {
		t.Fatal("published ciphertext changed")
	}
}

func TestSharingPairRESTRejectsWrongKeyAndDescriptor(t *testing.T) {
	for _, what := range []string{"key", "descriptor"} {
		t.Run(what, func(t *testing.T) {
			f, i, r := pairRESTClients(t)
			ctx := context.Background()
			if _, err := r.EnrollSharingPair(ctx, "grant"); err != nil {
				t.Fatal(err)
			}
			f.wrongKey = what == "key"
			f.wrongDescriptor = what == "descriptor"
			if _, err := i.EnrollSharingPair(ctx, "grant"); err == nil {
				t.Fatal("accepted invalid " + what)
			}
			if f.epoch != nil || i.cryptoReady("network") {
				t.Fatal("invalid material published or promoted")
			}
		})
	}
}

func encodePairPin(key []byte) string { return base64.RawURLEncoding.EncodeToString(key) }
