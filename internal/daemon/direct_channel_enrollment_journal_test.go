//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/transport"
)

type enrollmentVector struct {
	Descriptor, Publication, EpochKey []byte
	Challenges, Proofs                [][]byte
}

func enrollmentFixture(t *testing.T) (*directEnrollmentJournal, *DirectEndpointSubscription, directEnrollmentBinding, enrollmentVector) {
	t.Helper()
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenNativeWorkerRegistry(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	j, err := newDirectEnrollmentJournal(r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v enrollmentVector
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	d, err := transport.DecodeDirectChannelDescriptorV2(v.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	if err = r.db.QueryRow(`SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	owner := &directEndpointSubscriptions{}
	s := owner.add(directEndpointBinding{metadata: DirectEndpointSubscriptionMetadata{InstallationID: domain.ID(id), TenantID: domain.ID(d.S.TenantID), PrincipalID: domain.ID(d.S.PrincipalID), EndpointID: domain.ID(d.S.EndpointID), IntentID: domain.ID(d.DirectIntentID), OriginID: domain.NewID(), ServerOrigin: "https://example.test", CredentialID: domain.ID(d.S.CredentialID), Role: "S", Deadline: time.Now().Add(time.Hour)}, issueDigest: enrollmentHash([]byte("issue")), subject: nativeManagedSubject{InstanceID: domain.ID("worker"), OwnershipGeneration: "1", NativeGeneration: "native-1"}})
	t.Cleanup(owner.close)
	b, err := enrollmentBinding(s, directManagedSourceCredentialProtocolV2, v.Descriptor, enrollmentHash([]byte("local")), enrollmentHash([]byte("peer")))
	if err != nil {
		t.Fatal(err)
	}
	return j, s, b, v
}
func TestDirectEnrollmentSingleGrantAndReplay(t *testing.T) {
	j, s, b, v := enrollmentFixture(t)
	if _, e := j.reserve(s, b); e != nil {
		t.Fatal(e)
	}
	registry, e := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
	if e != nil {
		t.Fatal(e)
	}
	defer registry.Close()
	other, e := newDirectEnrollmentJournal(registry)
	if e != nil {
		t.Fatal(e)
	}
	var generated atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			active := j
			if i%2 == 0 {
				active = other
			}
			row, e := active.material(s, b, func() ([]byte, []byte, error) { generated.Add(1); return bytes.Clone(v.EpochKey), v.Publication, nil })
			if e != nil {
				t.Error(e)
				return
			}
			if !bytes.Equal(row.Root, v.EpochKey) || !bytes.Equal(row.Publication, v.Publication) {
				t.Error("material changed")
			}
		}(i)
	}
	wg.Wait()
	if generated.Load() != 1 {
		t.Fatalf("candidates %d", generated.Load())
	}
	if _, e := j.bindProof(s, b, v.Challenges[0], v.Proofs[0]); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"publication", "challenge", "proof", "activation"} {
		// A retained challenge is already authoritative and cannot be dispatched again.
		if kind == "challenge" {
			continue
		}
		if _, e := j.markDispatch(s, b, kind); e != nil {
			t.Fatal(e)
		}
		if _, e := j.markDispatch(s, b, kind); e == nil {
			t.Fatal("unknown outcome replayed")
		}
		if _, e := j.observeAbsent(s, b, kind); e != nil {
			t.Fatal(e)
		}
		row, e := j.markDispatch(s, b, kind)
		if e != nil {
			t.Fatal(e)
		}
		if row.Attempts[kind].Count != 2 || row.Attempts[kind].Recovered != 1 {
			t.Fatal("nonmonotonic attempts")
		}
	}
	replay, e := other.material(s, b, func() ([]byte, []byte, error) { t.Fatal("regenerated root"); return nil, nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(replay.Root, v.EpochKey) || !bytes.Equal(replay.Proof, v.Proofs[0]) {
		t.Fatal("replay changed bytes")
	}
}
func TestDirectEnrollmentCrashPhases(t *testing.T) {
	for _, phase := range []string{"reserved", "started", "material"} {
		t.Run(phase, func(t *testing.T) {
			j, s, b, v := enrollmentFixture(t)
			if _, e := j.reserve(s, b); e != nil {
				t.Fatal(e)
			}
			if phase == "started" {
				if _, e := j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error { r.State = "started"; return nil }); e != nil {
					t.Fatal(e)
				}
			}
			if phase == "material" {
				if _, e := j.material(s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), v.Publication, nil }); e != nil {
					t.Fatal(e)
				}
			}
			registry, e := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
			if e != nil {
				t.Fatal(e)
			}
			defer registry.Close()
			reopened, e := newDirectEnrollmentJournal(registry)
			if e != nil {
				t.Fatal(e)
			}
			calls := 0
			row, e := reopened.material(s, b, func() ([]byte, []byte, error) { calls++; return bytes.Clone(v.EpochKey), v.Publication, nil })
			if e != nil {
				t.Fatal(e)
			}
			expected := 1
			if phase == "material" {
				expected = 0
			}
			if calls != expected || !bytes.Equal(row.Root, v.EpochKey) {
				t.Fatal("incorrect crash recovery")
			}
		})
	}
}

// Legacy start rows are constructed only as authenticated migration fixtures.
type enrollmentLegacyGrant struct {
	j *directEnrollmentJournal
	b directEnrollmentBinding
}

func enrollmentLegacyStart(j *directEnrollmentJournal, s *DirectEndpointSubscription, b directEnrollmentBinding) (*enrollmentLegacyGrant, error) {
	_, e := j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "reserved" {
			return errDirectEnrollment
		}
		r.State = "started"
		return nil
	})
	return &enrollmentLegacyGrant{j, b}, e
}
func (g *enrollmentLegacyGrant) material(s *DirectEndpointSubscription, root, publication []byte) (directEnrollmentRecord, error) {
	return g.j.material(s, g.b, func() ([]byte, []byte, error) { return bytes.Clone(root), publication, nil })
}
func TestDirectEnrollmentTampering(t *testing.T) {
	for _, kind := range []string{"mac", "noncanonical", "oversize", "identity", "descriptor", "key-missing", "key-mode", "key-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			j, s, b, _ := enrollmentFixture(t)
			if _, e := j.reserve(s, b); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "identity":
				b.Generation = "2"
			case "descriptor":
				d, e := transport.DecodeDirectChannelDescriptorV2(b.Descriptor)
				if e != nil {
					t.Fatal(e)
				}
				d.AuthorizationDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				b.Descriptor, e = d.CanonicalBytes()
				if e != nil {
					t.Fatal(e)
				}
				b.DescriptorHash = enrollmentHash(b.Descriptor)
				sameChannel, _ := transport.DirectChannelIDV2(d)
				if sameChannel != b.Channel {
					t.Fatal("fixture changed channel")
				}
			case "key-missing":
				if e := os.Remove(filepath.Join(j.registry.root, directEnrollmentNamespace, "journal.mac")); e != nil {
					t.Fatal(e)
				}
			case "key-mode":
				if e := os.Chmod(filepath.Join(j.registry.root, directEnrollmentNamespace, "journal.mac"), 0644); e != nil {
					t.Fatal(e)
				}
			case "key-hardlink":
				if e := os.Link(filepath.Join(j.registry.root, directEnrollmentNamespace, "journal.mac"), filepath.Join(t.TempDir(), "link")); e != nil {
					t.Fatal(e)
				}
			default:
				if e := j.locked(func(c *sql.Conn, key []byte) error {
					var raw []byte
					if e := c.QueryRowContext(context.Background(), `SELECT payload FROM native_direct_enrollment_v1`).Scan(&raw); e != nil {
						return e
					}
					mac := []byte("invalid")
					if kind == "noncanonical" {
						raw = append(raw, ' ')
						mac = enrollmentMAC(key, b, raw)
					}
					if kind == "oversize" {
						raw = bytes.Repeat([]byte("x"), directEnrollmentMaxBytes+1)
						mac = enrollmentMAC(key, b, raw)
					}
					_, e := c.ExecContext(context.Background(), `UPDATE native_direct_enrollment_v1 SET payload=?,mac=?`, raw, mac)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := j.reserve(s, b); e == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
}
func TestDirectEnrollmentLostEmptyKeyAndRevocation(t *testing.T) {
	j, s, b, _ := enrollmentFixture(t)
	if e := os.Remove(filepath.Join(j.registry.root, directEnrollmentNamespace, "journal.mac")); e != nil {
		t.Fatal(e)
	}
	if _, e := newDirectEnrollmentJournal(j.registry); e == nil {
		t.Fatal("lost empty key regenerated")
	}
	j, s, b, _ = enrollmentFixture(t)
	s.Remove()
	if _, e := j.reserve(s, b); e == nil {
		t.Fatal("revoked subscription accepted")
	}
}

func TestDirectEnrollmentCapacityNoEviction(t *testing.T) {
	j, s, b, _ := enrollmentFixture(t)
	if e := j.locked(func(c *sql.Conn, key []byte) error {
		for i := 0; i < directEnrollmentMaxRecords; i++ {
			if _, e := c.ExecContext(context.Background(), `INSERT INTO native_direct_enrollment_v1 VALUES(?,?,?,?,?)`, b.Installation, b.Server, fmt.Sprint(i), []byte("occupied"), []byte("occupied")); e != nil {
				return e
			}
			if _, e := c.ExecContext(context.Background(), `INSERT INTO native_direct_enrollment_v1_fences VALUES(?,?,?,?,?)`, b.Installation, b.Server, fmt.Sprint(i), []byte("occupied"), []byte("occupied")); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := j.reserve(s, b); e == nil {
		t.Fatal("capacity exceeded")
	}
	var count int
	if e := j.registry.db.QueryRow(`SELECT COUNT(*) FROM native_direct_enrollment_v1`).Scan(&count); e != nil || count != directEnrollmentMaxRecords {
		t.Fatalf("count %d error %v", count, e)
	}
}

func TestDirectEnrollmentUnknownCommitPoisonsHandle(t *testing.T) {
	j, s, b, _ := enrollmentFixture(t)
	if e := j.locked(func(c *sql.Conn, key []byte) error {
		_ = c.Raw(func(any) error { return driver.ErrBadConn })
		return nil
	}); e == nil {
		t.Fatal("unknown commit accepted")
	}
	if _, e := j.reserve(s, b); e == nil {
		t.Fatal("unknown commit handle remained usable")
	}
}

func TestDirectEnrollmentSubscriptionPartyBinding(t *testing.T) {
	for _, field := range []string{"tenant", "principal", "endpoint", "intent"} {
		t.Run(field, func(t *testing.T) {
			j, s, b, _ := enrollmentFixture(t)
			if s.binding.metadata.OriginID == s.binding.metadata.EndpointID {
				t.Fatal("fixture conflates runtime origin with endpoint")
			}
			if _, e := j.reserve(s, b); e != nil {
				t.Fatal(e)
			}
			switch field {
			case "tenant":
				s.binding.metadata.TenantID = domain.NewID()
			case "principal":
				s.binding.metadata.PrincipalID = domain.NewID()
			case "endpoint":
				s.binding.metadata.EndpointID = domain.NewID()
			case "intent":
				s.binding.metadata.IntentID = domain.NewID()
			}
			if _, e := j.reserve(s, b); e == nil {
				t.Fatal("wrong subscription party accepted")
			}
			if _, e := enrollmentBinding(s, b.Protocol, b.Descriptor, b.LocalFingerprint, b.PeerFingerprint); e == nil {
				t.Fatal("wrong party constructed binding")
			}
		})
	}
}

func TestDirectEnrollmentDeletedRecordCannotRecreate(t *testing.T) {
	for _, phase := range []string{"started", "material"} {
		t.Run(phase, func(t *testing.T) {
			j, s, b, v := enrollmentFixture(t)
			if _, e := j.reserve(s, b); e != nil {
				t.Fatal(e)
			}
			g, e := enrollmentLegacyStart(j, s, b)
			if e != nil {
				t.Fatal(e)
			}
			if phase == "material" {
				if _, e = g.material(s, v.EpochKey, v.Publication); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = j.registry.db.Exec(`DELETE FROM native_direct_enrollment_v1`); e != nil {
				t.Fatal(e)
			}
			r, e := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			other, e := newDirectEnrollmentJournal(r)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = other.reserve(s, b); e == nil {
				t.Fatal("deleted row recreated")
			}
			if _, e = enrollmentLegacyStart(other, s, b); e == nil {
				t.Fatal("second creation grant")
			}
			if _, e = r.db.Exec(`DELETE FROM native_direct_enrollment_v1_fences`); e == nil {
				t.Fatal("immutable fence deleted")
			}
		})
	}
}

func TestDirectEnrollmentDeletedRecordRejectsOppositeRole(t *testing.T) {
	for _, firstRole := range []string{"S", "P"} {
		for _, phase := range []string{"started", "material"} {
			t.Run(firstRole+"/"+phase, func(t *testing.T) {
				j, source, sourceBinding, v := enrollmentFixture(t)
				descriptor, e := transport.DecodeDirectChannelDescriptorV2(v.Descriptor)
				if e != nil {
					t.Fatal(e)
				}
				targetBinding := source.binding
				targetBinding.metadata.TenantID = domain.ID(descriptor.P.TenantID)
				targetBinding.metadata.PrincipalID = domain.ID(descriptor.P.PrincipalID)
				targetBinding.metadata.EndpointID = domain.ID(descriptor.P.EndpointID)
				targetBinding.metadata.CredentialID = domain.ID(descriptor.P.CredentialID)
				targetBinding.metadata.Role = "P"
				targetBinding.issueDigest = enrollmentHash([]byte("target issue"))
				target := source.owner.add(targetBinding)
				if target == nil {
					t.Fatal("target subscription unavailable")
				}
				peerBinding, e := enrollmentBinding(target, managedDirectCredentialProtocolV1, v.Descriptor, sourceBinding.PeerFingerprint, sourceBinding.LocalFingerprint)
				if e != nil {
					t.Fatal(e)
				}
				first, next := source, target
				firstBinding, nextBinding := sourceBinding, peerBinding
				if firstRole == "P" {
					first, next = target, source
					firstBinding, nextBinding = peerBinding, sourceBinding
				}
				if firstBinding.Channel != nextBinding.Channel || firstBinding.Installation != nextBinding.Installation {
					t.Fatal("fixture changed journal identity")
				}
				if _, e = j.reserve(first, firstBinding); e != nil {
					t.Fatal(e)
				}
				grant, e := enrollmentLegacyStart(j, first, firstBinding)
				if e != nil {
					t.Fatal(e)
				}
				if phase == "material" {
					if _, e = grant.material(first, v.EpochKey, v.Publication); e != nil {
						t.Fatal(e)
					}
				}
				if _, e = j.registry.db.Exec(`DELETE FROM native_direct_enrollment_v1`); e != nil {
					t.Fatal(e)
				}
				r, e := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				reopened, e := newDirectEnrollmentJournal(r)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = reopened.reserve(next, nextBinding); e == nil {
					t.Fatal("opposite role recreated deleted journal row")
				}
				if _, e = enrollmentLegacyStart(reopened, next, nextBinding); e == nil {
					t.Fatal("opposite role minted second creation grant")
				}
				var rows, fences int
				if e = r.db.QueryRow(`SELECT COUNT(*) FROM native_direct_enrollment_v1`).Scan(&rows); e != nil {
					t.Fatal(e)
				}
				if e = r.db.QueryRow(`SELECT COUNT(*) FROM native_direct_enrollment_v1_fences`).Scan(&fences); e != nil {
					t.Fatal(e)
				}
				if rows != 0 || fences != 1 {
					t.Fatalf("rows %d fences %d", rows, fences)
				}
			})
		}
	}
}

func TestDirectEnrollmentCommitOutcomeRecovery(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprint(committed), func(t *testing.T) {
			j, s, b, v := enrollmentFixture(t)
			if _, e := j.reserve(s, b); e != nil {
				t.Fatal(e)
			}
			// Inject a lost COMMIT acknowledgement after writing the same authenticated
			// material that apply writes; alternatively confirm rollback before error.
			e := j.locked(func(c *sql.Conn, key []byte) error {
				row := directEnrollmentRecord{Version: 1, Binding: b, State: "material", Root: bytes.Clone(v.EpochKey), Publication: bytes.Clone(v.Publication), PublicationHash: enrollmentHash(v.Publication)}
				raw, err := json.Marshal(row)
				if err != nil {
					return err
				}
				if _, err = c.ExecContext(context.Background(), `UPDATE native_direct_enrollment_v1 SET payload=?,mac=?`, raw, enrollmentMAC(key, b, raw)); err != nil {
					return err
				}
				operation := "ROLLBACK"
				if committed {
					operation = "COMMIT"
				}
				_, err = c.ExecContext(context.Background(), operation)
				return err
			})
			if e == nil {
				t.Fatal("uncertain commit accepted")
			}
			if _, e = j.reserve(s, b); e == nil {
				t.Fatal("poisoned handle usable")
			}
			reopened, e := newDirectEnrollmentJournal(j.registry)
			if e != nil {
				t.Fatal(e)
			}
			generated := 0
			row, e := reopened.material(s, b, func() ([]byte, []byte, error) { generated++; return bytes.Clone(v.EpochKey), v.Publication, nil })
			if e != nil {
				t.Fatal(e)
			}
			want := 1
			if committed {
				want = 0
			}
			if generated != want || !bytes.Equal(row.Root, v.EpochKey) {
				t.Fatal("commit recovery replaced material")
			}
		})
	}
}
func TestDirectEnrollmentObservations(t *testing.T) {
	j, s, b, v := enrollmentFixture(t)
	if _, e := j.reserve(s, b); e != nil {
		t.Fatal(e)
	}
	row, e := j.material(s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), v.Publication, nil })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = j.observePublication(s, b, enrollmentHash([]byte("wrong"))); e == nil {
		t.Fatal("wrong publication accepted")
	}
	if _, e = j.observePublication(s, b, row.PublicationHash); e != nil {
		t.Fatal(e)
	}
	if _, e = j.markDispatch(s, b, "publication"); e == nil {
		t.Fatal("observed publication replayed")
	}
	if _, e = j.markDispatch(s, b, "challenge"); e != nil {
		t.Fatal(e)
	}
	if _, e = j.observeAbsent(s, b, "challenge"); e != nil {
		t.Fatal(e)
	}
	if _, e = j.markDispatch(s, b, "challenge"); e != nil {
		t.Fatal(e)
	}
	if _, e = j.observeChallenge(s, b, v.Challenges[0]); e != nil {
		t.Fatal(e)
	}
	if _, e = j.bindProof(s, b, v.Challenges[0], v.Proofs[0]); e != nil {
		t.Fatal(e)
	}
	if _, e = j.observeChallenge(s, b, []byte("changed")); e == nil {
		t.Fatal("changed challenge accepted")
	}
	c, e := transport.DecodeDirectChannelReadinessChallengeV2(v.Challenges[0])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = j.observeProof(s, b, enrollmentHash([]byte("wrong")), c.ExpiresAt); e == nil {
		t.Fatal("wrong proof accepted")
	}
	if _, e = j.observeProof(s, b, enrollmentHash(v.Proofs[0]), c.ExpiresAt); e != nil {
		t.Fatal(e)
	}
	if _, e = j.markDispatch(s, b, "activation"); e != nil {
		t.Fatal(e)
	}
	if _, e = j.markDispatch(s, b, "activation"); e == nil {
		t.Fatal("activation unknown outcome replayed")
	}
	if _, e = j.observeAbsent(s, b, "activation"); e != nil {
		t.Fatal(e)
	}
	if _, e = j.markDispatch(s, b, "activation"); e != nil {
		t.Fatal(e)
	}
	d, e := transport.DecodeDirectChannelDescriptorV2(v.Descriptor)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = j.observeActivation(s, b, "wrong", c.ExpiresAt, d.ExpiresAt); e == nil {
		t.Fatal("wrong activation accepted")
	}
	activated, e := j.observeActivation(s, b, b.Channel, c.ExpiresAt, d.ExpiresAt)
	if e != nil {
		t.Fatal(e)
	}
	if len(activated.Activation) == 0 || !bytes.Equal(activated.ActivationHash, enrollmentDigest(activated.Activation)) {
		t.Fatal("activation not retained")
	}
	if _, e = j.observeActivation(s, b, b.Channel, "2999-01-01T00:00:00Z", d.ExpiresAt); e == nil {
		t.Fatal("activation outside descriptor accepted")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, activated); got != "directEnrollmentRecord{private}" {
			t.Fatal("record formatting exposed private fields")
		}
	}
}

func TestDirectEnrollmentConfirmedRollback(t *testing.T) {
	j, s, b, v := enrollmentFixture(t)
	if _, e := j.material(s, b, func() ([]byte, []byte, error) { t.Fatal("missing row generated candidate"); return nil, nil, nil }); e == nil {
		t.Fatal("missing reservation accepted")
	}
	if _, e := j.reserve(s, b); e != nil {
		t.Fatal(e)
	}
	if _, e := j.material(s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), []byte("invalid publication"), nil }); e == nil {
		t.Fatal("invalid candidate accepted")
	}
	row, e := j.reserve(s, b)
	if e != nil || row.State != "reserved" {
		t.Fatal("confirmed rollback changed reservation")
	}
	if _, e = j.material(s, b, func() ([]byte, []byte, error) { return bytes.Clone(v.EpochKey), v.Publication, nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = j.material(s, b, func() ([]byte, []byte, error) { t.Fatal("committed root regenerated"); return nil, nil, nil }); e != nil {
		t.Fatal(e)
	}
}
