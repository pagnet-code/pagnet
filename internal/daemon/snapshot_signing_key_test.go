package daemon

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	hostcrypto "github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func TestSnapshotSigningPublicKeyUsesPersistedHostIdentity(t *testing.T) {
	d := &Daemon{StateDir: t.TempDir(), ServerURL: "https://example.test", bootID: "boot"}
	key, err := d.snapshotSigningPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := hostcrypto.LoadHostIdentity(d.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if key != base64.StdEncoding.EncodeToString(identity.Ed25519Pub) {
		t.Fatal("offer does not match persisted identity")
	}
	restarted := &Daemon{StateDir: d.StateDir}
	if next, err := restarted.snapshotSigningPublicKey(); err != nil || next != key {
		t.Fatal("restart changed signing identity", err)
	}
	u, err := url.Parse(d.wsURLWithSnapshotSigningKey(t.Context(), key))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("snapshot_signing_key") != transport.HostSnapshotSigningKeyProtocol || q.Get("snapshot_signing_public_key") != key || q.Get("native_observations") != transport.NativeObservationReceiptProtocol {
		t.Fatal("missing signing or native observation offer")
	}
}

func TestSnapshotSigningPublicKeyRejectsInvalidSignerBeforeDial(t *testing.T) {
	for _, mutation := range []string{"short private", "short public", "mismatched public", "corrupt private seed", "corrupt private suffix"} {
		t.Run(mutation, func(t *testing.T) {
			identity, err := hostcrypto.NewHostIdentity()
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "short private":
				identity.Ed25519Priv = identity.Ed25519Priv[:31]
			case "short public":
				identity.Ed25519Pub = identity.Ed25519Pub[:31]
			case "mismatched public":
				identity.Ed25519Pub[0] ^= 1
			case "corrupt private seed":
				identity.Ed25519Priv[0] ^= 1
			case "corrupt private suffix":
				identity.Ed25519Priv[32] ^= 1
			}
			d := &Daemon{ServerURL: "http://127.0.0.1:1"}
			d.cryptoManager().identity = identity
			if key, err := d.snapshotSigningPublicKey(); err == nil || key != "" {
				t.Fatal("invalid signer offered")
			}
			if _, err := d.connectAndRun(t.Context()); err == nil || !strings.Contains(err.Error(), "snapshot signing identity") {
				t.Fatal("invalid signer reached dial", err)
			}
		})
	}
}

func TestSnapshotSigningKeyAdmission(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	other := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", ed25519.PublicKeySize)))
	for _, test := range []struct {
		name, offer, echo string
		feature, reject   bool
	}{
		{"accepted", key, key, true, false},
		{"old server", key, "", false, false},
		{"no offer old server", "", "", false, false},
		{"feature without key", key, "", true, true},
		{"key without feature", key, key, false, true},
		{"mismatch", key, other, true, true},
		{"unsolicited", "", key, true, true},
		{"unpadded", key, strings.TrimRight(key, "="), true, true},
		{"newline", key, key + "\n", true, true},
		{"short key", key, base64.StdEncoding.EncodeToString(make([]byte, 31)), true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, p := snapshotSigningAdmissionFixture(test.offer)
			p.SnapshotSigningPublicKey = test.echo
			if test.feature {
				p.ProtocolFeatures = append(p.ProtocolFeatures, transport.HostSnapshotSigningKeyProtocol)
			}
			err := c.Admit(p)
			if test.reject {
				if !errors.Is(err, ErrNativeObservationConflict) {
					t.Fatal("invalid signing admission accepted", err)
				}
				if _, err := c.AuthenticatedNativeHostSession(); err == nil {
					t.Fatal("rejected session retained")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := c.Admit(p); err != nil {
					t.Fatal("identical duplicate rejected", err)
				}
			}
		})
	}
}

func TestSnapshotSigningKeyAdmissionCannotChangeWithinConnection(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	for _, initiallyNegotiated := range []bool{false, true} {
		c, p := snapshotSigningAdmissionFixture(key)
		negotiated := p
		negotiated.SnapshotSigningPublicKey = key
		negotiated.ProtocolFeatures = append([]string{transport.HostSnapshotSigningKeyProtocol}, p.ProtocolFeatures...)
		first, second := p, negotiated
		if initiallyNegotiated {
			first, second = second, first
		}
		if err := c.Admit(first); err != nil {
			t.Fatal(err)
		}
		if err := c.Admit(second); !errors.Is(err, ErrNativeObservationConflict) {
			t.Fatal("duplicate changed signing negotiation", err)
		}
	}
	other := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", ed25519.PublicKeySize)))
	old, p := snapshotSigningAdmissionFixture(key)
	fresh, _ := snapshotSigningAdmissionFixture(other)
	p.HostID, p.BootID = fresh.hostID, fresh.bootID
	p.ProtocolFeatures = append(p.ProtocolFeatures, transport.HostSnapshotSigningKeyProtocol)
	p.SnapshotSigningPublicKey = key
	if err := fresh.Admit(p); !errors.Is(err, ErrNativeObservationConflict) {
		t.Fatal("fresh connection accepted previous offer", err)
	}
	p.HostID, p.BootID = old.hostID, old.bootID
	if err := old.Admit(p); err != nil {
		t.Fatal("previous connection lost its offer", err)
	}
}

func snapshotSigningAdmissionFixture(offer string) (*NativeObservationConnection, transport.HostSessionPayload) {
	host, boot, runner := domain.NewID().String(), domain.NewID().String(), domain.NewID().String()
	c := NewNativeObservationConnection("https://example.test", host, boot, nil)
	c.offeredSnapshotSigningPublicKey = offer
	p := transport.HostSessionPayload{TenantID: host, AccountID: host, OwnershipScope: "personal", NativeAdmissionID: domain.NewID().String(), HostID: host, BootID: boot, RunnerID: runner, RunnerEpoch: time.Now().UTC(), ProtocolFeatures: []string{transport.NativeObservationReceiptProtocol}}
	return c, p
}
