//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

type reconcileMaterialFixture struct {
	journal      *directEnrollmentJournal
	subscription *DirectEndpointSubscription
	binding      directEndpointReconcileBinding
	enrollment   directhttp.Enrollment
	vector       enrollmentVector
	private      []byte
	peerPrivate  []byte
	now          time.Time
}

func newReconcileMaterialFixture(t *testing.T, role string) *reconcileMaterialFixture {
	t.Helper()
	j, s, _, v := enrollmentFixture(t)
	var keys struct {
		SourcePrivate, PeerPrivate []byte
		Now                        time.Time
	}
	raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
	if err != nil || json.Unmarshal(raw, &keys) != nil {
		t.Fatal("vector")
	}
	d, err := transport.DecodeDirectChannelDescriptorV2(v.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	local, peer := d.S, d.P
	private := keys.SourcePrivate
	protocol := directManagedSourceCredentialProtocolV2
	if role == "P" {
		local, peer = d.P, d.S
		private = keys.PeerPrivate
		protocol = managedDirectCredentialProtocolV1
	}
	s.binding.metadata.Role = role
	s.binding.metadata.TenantID = domain.ID(local.TenantID)
	s.binding.metadata.PrincipalID = domain.ID(local.PrincipalID)
	s.binding.metadata.EndpointID = domain.ID(local.EndpointID)
	s.binding.metadata.CredentialID = domain.ID(local.CredentialID)
	lk, _ := base64.RawURLEncoding.DecodeString(local.PublicKey)
	pk, _ := base64.RawURLEncoding.DecodeString(peer.PublicKey)
	e := reconcileEnrollment(t, d, keys.Now)
	b := directEndpointReconcileBinding{Descriptor: d, DescriptorBytes: bytes.Clone(v.Descriptor), DescriptorHash: sha256.Sum256(v.Descriptor), LocalFingerprint: sha256.Sum256(lk), PeerFingerprint: sha256.Sum256(pk), Authority: e.Authority, Protocol: protocol}
	t.Cleanup(func() { clear(keys.SourcePrivate); clear(keys.PeerPrivate) })
	return &reconcileMaterialFixture{j, s, b, e, v, private, keys.PeerPrivate, keys.Now}
}
func (f *reconcileMaterialFixture) operation(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
	return use(ctx, endpointMaterial{private: f.private})
}
func (f *reconcileMaterialFixture) acquire(e directhttp.Enrollment, wire []byte, operation directEndpointMaterialOperation) (*directchannelcrypto.Material, []byte, error) {
	if f.subscription.binding.metadata.Role == "S" {
		return acquireDirectSourceReconcileMaterial(context.Background(), f.subscription, f.binding, e, f.journal.registry, func() time.Time { return f.now }, operation)
	}
	return acquireDirectTargetReconcileMaterial(context.Background(), f.subscription, f.binding, e, wire, f.journal.registry, func() time.Time { return f.now }, operation)
}
func publishedEnrollment(e directhttp.Enrollment, wire []byte) directhttp.Enrollment {
	h := sha256.Sum256(wire)
	hash := base64.RawURLEncoding.EncodeToString(h[:])
	e.PublicationHash = &hash
	return e
}
func TestDirectReconcileMaterialVectors(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcileMaterialFixture(t, role)
			binding, err := enrollmentBinding(f.subscription, f.binding.Protocol, f.binding.DescriptorBytes, f.binding.LocalFingerprint, f.binding.PeerFingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.journal.reserve(f.subscription, binding); err != nil {
				t.Fatal(err)
			}
			if role == "S" {
				if _, err = f.journal.material(f.subscription, binding, func() ([]byte, []byte, error) { return bytes.Clone(f.vector.EpochKey), f.vector.Publication, nil }); err != nil {
					t.Fatal(err)
				}
			}
			e := publishedEnrollment(f.enrollment, f.vector.Publication)
			m, wire, err := f.acquire(e, f.vector.Publication, f.operation)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Clear()
			if !bytes.Equal(m.Key[:], f.vector.EpochKey) || !bytes.Equal(wire, f.vector.Publication) {
				t.Fatal("vector material changed")
			}
			index := 0
			if role == "P" {
				index = 1
			}
			party := f.binding.Descriptor.S
			if role == "P" {
				party = f.binding.Descriptor.P
			}
			proof, err := m.ReadinessProof(f.vector.Challenges[index], party.CredentialID, f.now)
			if err != nil || !bytes.Equal(proof, f.vector.Proofs[index]) {
				t.Fatal("readiness vector mismatch")
			}
			// Fresh acquisition opens a new journal and restores exact bytes without a key.
			f.private = nil
			restored, replay, err := f.acquire(e, wire, f.operation)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Clear()
			if restored.Key != m.Key || !bytes.Equal(replay, wire) {
				t.Fatal("restart changed committed candidate")
			}
		})
	}
}
func TestDirectReconcileMaterialConcurrentSource(t *testing.T) {
	f := newReconcileMaterialFixture(t, "S")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first []byte
	var root [32]byte
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, wire, err := f.acquire(f.enrollment, nil, f.operation)
			if errors.Is(err, errDirectEndpointLocalBusy) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			defer m.Clear()
			mu.Lock()
			defer mu.Unlock()
			if first == nil {
				first = wire
				root = m.Key
			} else if root != m.Key || !bytes.Equal(first, wire) {
				t.Error("multiple committed candidates")
			}
		}()
	}
	wg.Wait()
	if first == nil {
		t.Fatal("no acquisition completed")
	}
	restored, replay, err := f.acquire(f.enrollment, nil, f.operation)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Clear()
	if restored.Key != root || !bytes.Equal(replay, first) {
		t.Fatal("concurrent candidate not retained")
	}
	m, err := directchannelcrypto.Accept(first, f.binding.Descriptor, f.peerPrivate, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Clear()
	if m.Key != root {
		t.Fatal("source/target root mismatch")
	}
}
func TestDirectReconcileMaterialRejects(t *testing.T) {
	for _, kind := range []string{"missing source root", "wrong hash", "tamper", "descriptor", "stale", "role", "reject", "after callback", "panic", "cancel", "twice", "no callback", "revoke"} {
		t.Run(kind, func(t *testing.T) {
			role := "P"
			if kind == "missing source root" {
				role = "S"
			}
			f := newReconcileMaterialFixture(t, role)
			wire := bytes.Clone(f.vector.Publication)
			e := publishedEnrollment(f.enrollment, wire)
			operation := directEndpointMaterialOperation(f.operation)
			switch kind {
			case "wrong hash":
				h := "wrong"
				e.PublicationHash = &h
			case "tamper":
				p, _ := transport.DecodeDirectChannelPublicationV2(wire)
				ct, _ := base64.RawURLEncoding.DecodeString(p.Ciphertext)
				ct[0] ^= 1
				p.Ciphertext = base64.RawURLEncoding.EncodeToString(ct)
				wire, _ = p.CanonicalBytes()
				e = publishedEnrollment(e, wire)
			case "descriptor":
				f.binding.DescriptorHash[0] ^= 1
			case "stale":
				f.now = f.now.Add(2 * time.Hour)
			case "role":
				f.subscription.binding.metadata.Role = "S"
			case "no callback":
				operation = func(context.Context, func(context.Context, endpointMaterial) error) error { return nil }
			case "revoke":
				operation = func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
					if err := f.operation(ctx, use); err != nil {
						return err
					}
					f.subscription.owner.close()
					return nil
				}
			case "reject":
				operation = func(context.Context, func(context.Context, endpointMaterial) error) error {
					return errors.New("rejected")
				}
			case "after callback":
				operation = func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
					if err := f.operation(ctx, use); err != nil {
						return err
					}
					return errors.New("acceptance failed")
				}
			case "panic":
				operation = func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
					_ = f.operation(ctx, use)
					panic("operation")
				}
			case "cancel":
				operation = func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
					ctx, cancel := context.WithCancel(ctx)
					cancel()
					return f.operation(ctx, use)
				}
			case "twice":
				operation = func(ctx context.Context, use func(context.Context, endpointMaterial) error) error {
					_ = f.operation(ctx, use)
					_ = f.operation(ctx, use)
					return nil
				}
			}
			m, got, err := f.acquire(e, wire, operation)
			if err == nil || m != nil || got != nil {
				if m != nil {
					m.Clear()
				}
				t.Fatal("failed operation exposed result")
			}
		})
	}
}
func TestDirectReconcileMaterialUncertainCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
			f := newReconcileMaterialFixture(t, "P")
			connector := enrollmentContextWrap(t, f.journal)
			commits := 0
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if query == "COMMIT" {
					commits++
					if commits == 3 {
						if committed {
							if _, err := next.ExecContext(ctx, query, args); err != nil {
								return nil, err
							}
						}
						return nil, errors.New("lost acknowledgement")
					}
				}
				return next.ExecContext(ctx, query, args)
			}
			e := publishedEnrollment(f.enrollment, f.vector.Publication)
			m, wire, err := f.acquire(e, f.vector.Publication, f.operation)
			if err == nil || m != nil || wire != nil {
				t.Fatal("uncertain commit exposed material")
			}
			connector.exec = nil
			if committed {
				f.private = nil
			}
			m, wire, err = f.acquire(e, f.vector.Publication, f.operation)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Clear()
			if !bytes.Equal(m.Key[:], f.vector.EpochKey) || !bytes.Equal(wire, f.vector.Publication) {
				t.Fatal("uncertain recovery changed material")
			}
		})
	}
}

func TestDirectReconcileMaterialRetainedConflict(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcileMaterialFixture(t, role)
			b, err := enrollmentBinding(f.subscription, f.binding.Protocol, f.binding.DescriptorBytes, f.binding.LocalFingerprint, f.binding.PeerFingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.journal.reserve(f.subscription, b); err != nil {
				t.Fatal(err)
			}
			row, err := f.journal.material(f.subscription, b, func() ([]byte, []byte, error) { return bytes.Clone(f.vector.EpochKey), f.vector.Publication, nil })
			clear(row.Root)
			if err != nil {
				t.Fatal(err)
			}
			p, _ := transport.DecodeDirectChannelPublicationV2(f.vector.Publication)
			ciphertext, _ := base64.RawURLEncoding.DecodeString(p.Ciphertext)
			ciphertext[0] ^= 1
			p.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
			wire, _ := p.CanonicalBytes()
			e := publishedEnrollment(f.enrollment, wire)
			f.private = nil
			m, got, err := f.acquire(e, wire, f.operation)
			if err == nil || m != nil || got != nil {
				if m != nil {
					m.Clear()
				}
				t.Fatal("conflicting remote publication replaced retained material")
			}
			// The rejected evidence leaves the committed candidate available unchanged.
			m, got, err = f.acquire(publishedEnrollment(f.enrollment, f.vector.Publication), f.vector.Publication, f.operation)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Clear()
			if !bytes.Equal(m.Key[:], f.vector.EpochKey) || !bytes.Equal(got, f.vector.Publication) {
				t.Fatal("retained material changed")
			}
		})
	}
}
