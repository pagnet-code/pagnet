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
	otherRegistry, err := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
	if err != nil {
		t.Fatal(err)
	}
	defer otherRegistry.Close()
	otherJournal, err := newDirectEnrollmentJournal(otherRegistry)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var grant *directEnrollmentGrant
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			active := j
			if i%2 == 0 {
				active = otherJournal
			}
			g, e := active.start(s, b)
			if e == nil {
				wins.Add(1)
				mu.Lock()
				grant = g
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("grants %d", wins.Load())
	}
	if _, e := j.reserve(s, b); e == nil {
		t.Fatal("started replay accepted")
	}
	if _, e := grant.material(s, v.EpochKey, v.Publication); e != nil {
		t.Fatal(e)
	}
	if _, e := grant.material(s, v.EpochKey, v.Publication); e == nil {
		t.Fatal("grant reused")
	}
	r, e := j.bindProof(s, b, v.Challenges[0], v.Proofs[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"publication", "challenge", "proof"} {
		if _, e = j.markDispatch(s, b, kind); e != nil {
			t.Fatal(e)
		}
		if _, e = j.markDispatch(s, b, kind); e == nil {
			t.Fatal("dispatch reused")
		}
	}
	reopened, e := OpenNativeWorkerRegistry(filepath.Dir(j.registry.root))
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	other, e := newDirectEnrollmentJournal(reopened)
	if e != nil {
		t.Fatal(e)
	}
	replay, e := other.reserve(s, b)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(replay.Publication, v.Publication) || !bytes.Equal(replay.Root, v.EpochKey) || !bytes.Equal(replay.Proof, r.Proof) {
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
			if phase != "reserved" {
				g, e := j.start(s, b)
				if e != nil {
					t.Fatal(e)
				}
				if phase == "material" {
					if _, e = g.material(s, v.EpochKey, v.Publication); e != nil {
						t.Fatal(e)
					}
				}
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
			row, e := other.reserve(s, b)
			if phase == "started" {
				if e == nil {
					t.Fatal("crashed start recovered")
				}
			} else if e != nil || row.State != phase {
				t.Fatalf("state %s error %v", row.State, e)
			}
		})
	}
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
			if _, e := c.ExecContext(context.Background(), `INSERT INTO native_direct_enrollment_v1_fences VALUES(?,?,?,?,?,?)`, b.Installation, b.Server, fmt.Sprint(i), b.Role, []byte("occupied"), []byte("occupied")); e != nil {
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
			g, e := j.start(s, b)
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
			if _, e = other.start(s, b); e == nil {
				t.Fatal("second creation grant")
			}
			if _, e = r.db.Exec(`DELETE FROM native_direct_enrollment_v1_fences`); e == nil {
				t.Fatal("immutable fence deleted")
			}
		})
	}
}
