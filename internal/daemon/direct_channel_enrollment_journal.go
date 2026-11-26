//go:build linux || darwin

package daemon

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

const directEnrollmentNamespace = "direct-channel-enrollment-v1"
const directEnrollmentMaxBytes = 65536
const directEnrollmentMaxRecords = 1024

var errDirectEnrollment = errors.New("direct channel enrollment journal unavailable, unsafe or conflicting")

// This journal is storage only. Records never authorize traffic or restore a lease.
// Lock order: registry.mu, custody flock, namespace flock, BEGIN IMMEDIATE, subscription leaf.
type directEnrollmentJournal struct {
	registry *NativeWorkerRegistry
	poisoned bool
}
type directEnrollmentBinding struct {
	Installation, Server, Channel, Role                            string
	Protocol                                                       directManagedSourceCredentialProtocolVariant
	Credential, Instance, Generation, NativeGeneration             string
	IssueDigest, DescriptorHash, LocalFingerprint, PeerFingerprint [32]byte
	Descriptor                                                     []byte
}
type directEnrollmentRecord struct {
	Version                                            int
	Binding                                            directEnrollmentBinding
	State                                              string
	Root                                               []byte
	Publication                                        []byte
	PublicationHash                                    [32]byte
	Challenge, Proof                                   []byte
	PublicationStarted, ChallengeStarted, ProofStarted bool                               // Legacy authenticated dispatch fences.
	Attempts                                           map[string]directEnrollmentAttempt `json:",omitempty"`
	PublicationObserved                                bool                               `json:",omitempty"`
	ProofReceivedAt                                    string                             `json:",omitempty"`
	Activation                                         []byte                             `json:",omitempty"`
	ActivationHash                                     []byte                             `json:",omitempty"`
}

func (directEnrollmentRecord) Format(s fmt.State, verb rune) {
	_, _ = io.WriteString(s, "directEnrollmentRecord{private}")
}

// Attempts count durable dispatch authorizations. Recovered records which attempts
// have been reconciled by an authoritative absence; absence never permits new bytes.
type directEnrollmentAttempt struct {
	Count     uint64
	Recovered uint64
}

func newDirectEnrollmentJournal(r *NativeWorkerRegistry) (*directEnrollmentJournal, error) {
	if r == nil {
		return nil, errDirectEnrollment
	}
	j := &directEnrollmentJournal{registry: r}
	err := j.locked(func(c *sql.Conn, key []byte) error { return nil })
	if err != nil {
		return nil, errDirectEnrollment
	}
	return j, nil
}
func enrollmentHash(b []byte) [32]byte { return sha256.Sum256(b) }
func enrollmentDigest(b []byte) []byte { h := enrollmentHash(b); return h[:] }
func enrollmentBinding(s *DirectEndpointSubscription, protocol directManagedSourceCredentialProtocolVariant, descriptor []byte, local, peer [32]byte) (directEnrollmentBinding, error) {
	if s == nil {
		return directEnrollmentBinding{}, errDirectEnrollment
	}
	d, err := transport.DecodeDirectChannelDescriptorV2(descriptor)
	if err != nil {
		return directEnrollmentBinding{}, errDirectEnrollment
	}
	channel, _ := transport.DirectChannelIDV2(d)
	b := s.binding
	out := directEnrollmentBinding{Installation: string(b.metadata.InstallationID), Server: b.metadata.ServerOrigin, Channel: channel, Role: b.metadata.Role, Protocol: protocol, Credential: string(b.metadata.CredentialID), Instance: string(b.subject.InstanceID), Generation: b.subject.OwnershipGeneration, NativeGeneration: b.subject.NativeGeneration, IssueDigest: b.issueDigest, DescriptorHash: enrollmentHash(descriptor), LocalFingerprint: local, PeerFingerprint: peer, Descriptor: bytes.Clone(descriptor)}
	if out.validate() != nil || !enrollmentSubscriptionParty(s, out) {
		return directEnrollmentBinding{}, errDirectEnrollment
	}
	return out, nil
}
func (b directEnrollmentBinding) validate() error {
	d, e := transport.DecodeDirectChannelDescriptorV2(b.Descriptor)
	if e != nil || len(b.Descriptor) > transport.DirectChannelDescriptorMaxBytesV2 || b.Installation == "" || b.Instance == "" || b.Generation == "" || b.NativeGeneration == "" || b.Server == "" || len(b.Server) > 2048 || managedPrepareServerOrigin(b.Server) != b.Server || b.DescriptorHash != enrollmentHash(b.Descriptor) || b.IssueDigest == ([32]byte{}) || b.LocalFingerprint == ([32]byte{}) || b.PeerFingerprint == ([32]byte{}) {
		return errDirectEnrollment
	}
	party := d.S
	if b.Role == "P" {
		party = d.P
		if b.Protocol != managedDirectCredentialProtocolV1 {
			return errDirectEnrollment
		}
	} else if b.Role != "S" || b.Protocol != directManagedSourceCredentialProtocolV2 {
		return errDirectEnrollment
	}
	channel, _ := transport.DirectChannelIDV2(d)
	if b.Channel != channel || b.Credential != party.CredentialID {
		return errDirectEnrollment
	}
	return nil
}
func (r directEnrollmentRecord) validate() error {
	if r.Version != 1 || r.Binding.validate() != nil {
		return errDirectEnrollment
	}
	for kind, a := range r.Attempts {
		if (kind != "publication" && kind != "challenge" && kind != "proof" && kind != "activation") || a.Recovered > a.Count {
			return errDirectEnrollment
		}
	}
	if (r.Attempts["proof"].Count > 0 || r.Attempts["activation"].Count > 0) && len(r.Proof) == 0 {
		return errDirectEnrollment
	}
	if r.ProofReceivedAt != "" && (len(r.Proof) == 0 || !enrollmentObservedTime(r.ProofReceivedAt, r.Binding)) {
		return errDirectEnrollment
	}
	if len(r.Activation) > 0 {
		var activation directEnrollmentActivation
		if json.Unmarshal(r.Activation, &activation) != nil || activation.ChannelID != r.Binding.Channel || !enrollmentObservedTime(activation.ActivatedAt, r.Binding) || !enrollmentObservedTime(activation.ExpiresAt, r.Binding) || !bytes.Equal(r.ActivationHash, enrollmentDigest(r.Activation)) || len(r.Proof) == 0 {
			return errDirectEnrollment
		}
		raw, _ := json.Marshal(activation)
		start, _ := time.Parse(time.RFC3339Nano, activation.ActivatedAt)
		end, _ := time.Parse(time.RFC3339Nano, activation.ExpiresAt)
		if !bytes.Equal(raw, r.Activation) || !start.Before(end) {
			return errDirectEnrollment
		}
	} else if len(r.ActivationHash) != 0 {
		return errDirectEnrollment
	}
	if r.State == "reserved" || r.State == "started" {
		if len(r.Attempts) > 0 || r.PublicationObserved || r.ProofReceivedAt != "" || len(r.Activation) > 0 || len(r.Root) != 0 || len(r.Publication) != 0 || r.PublicationHash != ([32]byte{}) || len(r.Challenge) != 0 || len(r.Proof) != 0 || r.PublicationStarted || r.ChallengeStarted || r.ProofStarted {
			return errDirectEnrollment
		}
		return nil
	}
	if r.State != "material" || len(r.Root) != 32 || enrollmentHash(r.Publication) != r.PublicationHash {
		return errDirectEnrollment
	}
	p, err := transport.DecodeDirectChannelPublicationV2(r.Publication)
	if err != nil {
		return errDirectEnrollment
	}
	descriptor, _ := p.Descriptor.CanonicalBytes()
	if !bytes.Equal(descriptor, r.Binding.Descriptor) {
		return errDirectEnrollment
	}
	if len(r.Challenge) == 0 {
		if len(r.Proof) != 0 || r.ProofStarted {
			return errDirectEnrollment
		}
		return nil
	}
	c, err := transport.DecodeDirectChannelReadinessChallengeV2(r.Challenge)
	if err != nil {
		return errDirectEnrollment
	}
	d := p.Descriptor
	party := d.S
	if r.Binding.Role == "P" {
		party = d.P
	}
	dh, _ := transport.DescriptorHashV2(d)
	ph, _ := transport.PublicationHashV2(p)
	if c.Role != r.Binding.Role || c.PrincipalID != party.PrincipalID || c.EndpointID != party.EndpointID || c.CredentialID != party.CredentialID || c.ChannelID != r.Binding.Channel || c.DescriptorHash != dh || c.PublicationHash != ph || c.ParentGrantID != d.ParentGrantID || c.GrantGeneration != d.GrantGeneration || c.ChannelGeneration != d.ChannelGeneration || c.DirectIntentID != d.DirectIntentID || c.EpochID != d.EpochID {
		return errDirectEnrollment
	}
	expiry, _ := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	dexp, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if expiry.After(dexp) {
		return errDirectEnrollment
	}
	if len(r.Proof) > 0 {
		proof, e := transport.DecodeDirectChannelReadinessProofV2(r.Proof)
		hash := enrollmentHash(r.Challenge)
		if e != nil || proof.ChallengeID != c.ChallengeID || proof.TranscriptHash != base64.RawURLEncoding.EncodeToString(hash[:]) {
			return errDirectEnrollment
		}
	} else if r.ProofStarted {
		return errDirectEnrollment
	}
	return nil
}
func (j *directEnrollmentJournal) locked(fn func(*sql.Conn, []byte) error) error {
	if j == nil || j.registry == nil {
		return errDirectEnrollment
	}
	r := j.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if j.poisoned {
		return errDirectEnrollment
	}
	root, e := nativeRegistryProtectedDirectory(r.root)
	if e != nil {
		return e
	}
	defer root.Close()
	if e = nativeShareHolderPrivate(root, true); e != nil {
		return e
	}
	custody, e := nativeRegistryCustodyLock(root)
	if e != nil {
		return e
	}
	defer custody.Close()
	if _, e = nativeRegistryInspectFiles(root, r.custodyIdentity, false); e != nil {
		return e
	}
	dir, e := nativeShareHolderChild(root, directEnrollmentNamespace)
	if e != nil {
		return e
	}
	defer dir.Close()
	lock, e := nativeShareHolderLock(dir)
	if e != nil {
		return e
	}
	defer lock.Close()
	ctx := context.Background()
	c, e := r.db.Conn(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return e
	}
	committed := false
	defer func() {
		if !committed {
			if _, e := c.ExecContext(ctx, "ROLLBACK"); e != nil {
				_ = c.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
	}()
	if _, e = nativeRegistryInspectFiles(root, r.custodyIdentity, false); e != nil {
		return e
	}
	if _, e = c.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS native_direct_enrollment_v1(installation TEXT NOT NULL,server TEXT NOT NULL,channel TEXT NOT NULL,payload BLOB NOT NULL,mac BLOB NOT NULL,PRIMARY KEY(installation,server,channel))`); e != nil {
		return e
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS native_direct_enrollment_v1_fences(installation TEXT NOT NULL,server TEXT NOT NULL,channel TEXT NOT NULL,binding BLOB NOT NULL,mac BLOB NOT NULL,PRIMARY KEY(installation,server,channel))`,
		`CREATE TRIGGER IF NOT EXISTS native_direct_enrollment_v1_fences_no_update BEFORE UPDATE ON native_direct_enrollment_v1_fences BEGIN SELECT RAISE(ABORT,'immutable enrollment fence'); END`,
		`CREATE TRIGGER IF NOT EXISTS native_direct_enrollment_v1_fences_no_delete BEFORE DELETE ON native_direct_enrollment_v1_fences BEGIN SELECT RAISE(ABORT,'immutable enrollment fence'); END`,
	} {
		if _, e = c.ExecContext(ctx, q); e != nil {
			return e
		}
	}
	var initialized int
	if e = c.QueryRowContext(ctx, `SELECT COUNT(*) FROM native_registry_metadata WHERE name='direct_enrollment_mac_initialized'`).Scan(&initialized); e != nil {
		return e
	}
	keyfile, e := nativeShareHolderOpen(dir, "journal.mac", false)
	if errors.Is(e, os.ErrNotExist) {
		var count int
		if e = c.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM native_direct_enrollment_v1)+(SELECT COUNT(*) FROM native_direct_enrollment_v1_fences)`).Scan(&count); e != nil || count != 0 || initialized != 0 {
			return errDirectEnrollment
		}
		key := make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return e
		}
		keyfile, e = nativeShareHolderOpen(dir, "journal.mac", true)
		if e != nil {
			return e
		}
		if _, e = keyfile.Write(key); e == nil {
			e = keyfile.Sync()
		}
		keyfile.Close()
		if e != nil {
			return e
		}
		if e = dir.Sync(); e != nil {
			return e
		}
		keyfile, e = nativeShareHolderOpen(dir, "journal.mac", false)
	}
	if e != nil {
		return e
	}
	key, e := io.ReadAll(io.LimitReader(keyfile, 33))
	keyfile.Close()
	if e != nil || len(key) != 32 {
		return errDirectEnrollment
	}
	defer clear(key)
	if _, e = c.ExecContext(ctx, `INSERT OR IGNORE INTO native_registry_metadata(name,value) VALUES('direct_enrollment_mac_initialized','1')`); e != nil {
		return e
	}
	if e = fn(c, key); e != nil {
		return e
	}
	_, e = c.ExecContext(ctx, "COMMIT")
	committed = e == nil
	if e != nil {
		j.poisoned = true
	}
	return e
}
func enrollmentMAC(key []byte, b directEnrollmentBinding, raw []byte) []byte {
	h := hmac.New(sha256.New, key)
	identity, _ := json.Marshal([]string{"pagnet/direct-enrollment/storage/v1", b.Installation, b.Server, b.Channel})
	h.Write(identity)
	h.Write([]byte{0})
	h.Write(raw)
	return h.Sum(nil)
}

// Immutable fences use exactly the mutable row identity; role remains bound by
// the authenticated binding. They detect deletion of an individual journal row.
// They do not detect rollback or replacement of an entire database snapshot.
func enrollmentFenceMAC(key []byte, b directEnrollmentBinding, raw []byte) []byte {
	return enrollmentMAC(key, b, append([]byte("creation-fence/v1\x00"), raw...))
}
func (j *directEnrollmentJournal) apply(s *DirectEndpointSubscription, b directEnrollmentBinding, change func(*directEnrollmentRecord, bool) error) (directEnrollmentRecord, error) {
	var result directEnrollmentRecord
	if b.validate() != nil || s == nil {
		return result, errDirectEnrollment
	}
	err := j.locked(func(c *sql.Conn, key []byte) error {
		var installation string
		if e := c.QueryRowContext(context.Background(), `SELECT value FROM native_registry_metadata WHERE name='installation_id'`).Scan(&installation); e != nil || installation != b.Installation {
			return errDirectEnrollment
		}
		var recordCount int
		if e := c.QueryRowContext(context.Background(), `SELECT MAX((SELECT COUNT(*) FROM native_direct_enrollment_v1 WHERE installation=?),(SELECT COUNT(*) FROM native_direct_enrollment_v1_fences WHERE installation=?))`, b.Installation, b.Installation).Scan(&recordCount); e != nil || recordCount > directEnrollmentMaxRecords {
			return errDirectEnrollment
		}
		var raw, mac []byte
		e := c.QueryRowContext(context.Background(), `SELECT CASE WHEN length(payload)<=65536 THEN payload ELSE NULL END,CASE WHEN length(mac)=32 THEN mac ELSE NULL END FROM native_direct_enrollment_v1 WHERE installation=? AND server=? AND channel=?`, b.Installation, b.Server, b.Channel).Scan(&raw, &mac)
		exists := e == nil
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		expectedBinding, _ := json.Marshal(b)
		var fence, fenceMAC []byte
		fenceErr := c.QueryRowContext(context.Background(), `SELECT CASE WHEN length(binding)<=65536 THEN binding ELSE NULL END,CASE WHEN length(mac)=32 THEN mac ELSE NULL END FROM native_direct_enrollment_v1_fences WHERE installation=? AND server=? AND channel=?`, b.Installation, b.Server, b.Channel).Scan(&fence, &fenceMAC)
		if fenceErr != nil && !errors.Is(fenceErr, sql.ErrNoRows) {
			return fenceErr
		}
		hasFence := fenceErr == nil
		if hasFence != exists || (hasFence && (!bytes.Equal(fence, expectedBinding) || !hmac.Equal(fenceMAC, enrollmentFenceMAC(key, b, fence)))) {
			return errDirectEnrollment
		}
		var row directEnrollmentRecord
		if exists {
			if len(raw) > directEnrollmentMaxBytes || !hmac.Equal(mac, enrollmentMAC(key, b, raw)) || json.Unmarshal(raw, &row) != nil {
				return errDirectEnrollment
			}
			canonical, _ := json.Marshal(row)
			binding, _ := json.Marshal(row.Binding)
			expected, _ := json.Marshal(b)
			if !bytes.Equal(raw, canonical) || !bytes.Equal(binding, expected) || row.validate() != nil {
				return errDirectEnrollment
			}
		} else {
			if recordCount >= directEnrollmentMaxRecords {
				return errDirectEnrollment
			}
			row = directEnrollmentRecord{Version: 1, Binding: b, State: "reserved"}
		}
		if !j.matches(s, b) {
			return errDirectEnrollment
		}
		if e = change(&row, exists); e != nil {
			return e
		}
		if row.validate() != nil {
			return errDirectEnrollment
		}
		raw, e = json.Marshal(row)
		if e != nil || len(raw) > directEnrollmentMaxBytes {
			return errDirectEnrollment
		}
		if !hasFence {
			if _, e = c.ExecContext(context.Background(), `INSERT INTO native_direct_enrollment_v1_fences VALUES(?,?,?,?,?)`, b.Installation, b.Server, b.Channel, expectedBinding, enrollmentFenceMAC(key, b, expectedBinding)); e != nil {
				return e
			}
		}
		if _, e = c.ExecContext(context.Background(), `INSERT INTO native_direct_enrollment_v1 VALUES(?,?,?,?,?) ON CONFLICT(installation,server,channel) DO UPDATE SET payload=excluded.payload,mac=excluded.mac`, b.Installation, b.Server, b.Channel, raw, enrollmentMAC(key, b, raw)); e != nil {
			return e
		}
		if !j.matches(s, b) {
			return errDirectEnrollment
		}
		result = row
		return nil
	})
	if err != nil {
		return directEnrollmentRecord{}, errDirectEnrollment
	}
	return result, nil
}
func (j *directEnrollmentJournal) matches(s *DirectEndpointSubscription, b directEnrollmentBinding) bool {
	m := s.binding.metadata
	return s.Valid() && enrollmentSubscriptionParty(s, b) && string(m.InstallationID) == b.Installation && m.ServerOrigin == b.Server && string(m.CredentialID) == b.Credential && m.Role == b.Role && s.binding.issueDigest == b.IssueDigest && string(s.binding.subject.InstanceID) == b.Instance && s.binding.subject.OwnershipGeneration == b.Generation && s.binding.subject.NativeGeneration == b.NativeGeneration
}

func enrollmentSubscriptionParty(s *DirectEndpointSubscription, b directEnrollmentBinding) bool {
	d, e := transport.DecodeDirectChannelDescriptorV2(b.Descriptor)
	if e != nil {
		return false
	}
	party := d.S
	if b.Role == "P" {
		party = d.P
	}
	m := s.binding.metadata
	return string(m.TenantID) == party.TenantID && string(m.PrincipalID) == party.PrincipalID && string(m.EndpointID) == party.EndpointID && string(m.IntentID) == d.DirectIntentID
}

func (j *directEnrollmentJournal) reserve(s *DirectEndpointSubscription, b directEnrollmentBinding) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error { return nil })
}

// material atomically installs one candidate before any dispatch is possible.
// generate is private synchronous local cryptography only: it must never perform
// HTTP, IPC, custody operations, or retain the candidate. A failed COMMIT poisons
// this handle; callers must reopen and read the durable row before trying again.
func (j *directEnrollmentJournal) material(s *DirectEndpointSubscription, b directEnrollmentBinding, generate func() ([]byte, []byte, error)) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists {
			return errDirectEnrollment
		}
		if r.State == "material" {
			return nil
		}
		if (r.State != "reserved" && r.State != "started") || generate == nil {
			return errDirectEnrollment
		}
		root, publication, err := generate()
		defer clear(root)
		if err != nil {
			return errDirectEnrollment
		}
		r.State = "material"
		r.Root = bytes.Clone(root)
		r.Publication = bytes.Clone(publication)
		r.PublicationHash = enrollmentHash(publication)
		return nil
	})
}

// bindProof retains one immutable server challenge and exact local proof. No cryptography or dispatch occurs here.
func (j *directEnrollmentJournal) bindProof(s *DirectEndpointSubscription, b directEnrollmentBinding, challenge, proof []byte) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "material" || len(proof) == 0 {
			return errDirectEnrollment
		}
		if (len(r.Challenge) > 0 && !bytes.Equal(challenge, r.Challenge)) || (len(r.Proof) > 0 && !bytes.Equal(proof, r.Proof)) {
			return errDirectEnrollment
		}
		r.Challenge = bytes.Clone(challenge)
		r.Proof = bytes.Clone(proof)
		return nil
	})
}

// markDispatch persists each attempt before traffic. A previous unknown outcome
// requires authoritative absence before exact immutable bytes may be replayed.
func (j *directEnrollmentJournal) markDispatch(s *DirectEndpointSubscription, b directEnrollmentBinding, kind string) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "material" || !r.dispatchKind(kind) {
			return errDirectEnrollment
		}
		r.importLegacyAttempts()
		a := r.Attempts[kind]
		if a.Count != a.Recovered || a.Count == ^uint64(0) {
			return errDirectEnrollment
		}
		a.Count++
		r.Attempts[kind] = a
		return nil
	})
}
func (r directEnrollmentRecord) dispatchKind(kind string) bool {
	switch kind {
	case "publication":
		return !r.PublicationObserved
	case "challenge":
		return len(r.Challenge) == 0
	case "proof":
		return len(r.Proof) > 0 && r.ProofReceivedAt == ""
	case "activation":
		return len(r.Proof) > 0 && len(r.Activation) == 0
	}
	return false
}
func (r *directEnrollmentRecord) importLegacyAttempts() {
	if r.Attempts == nil {
		r.Attempts = make(map[string]directEnrollmentAttempt)
	}
	for kind, started := range map[string]bool{"publication": r.PublicationStarted, "challenge": r.ChallengeStarted, "proof": r.ProofStarted} {
		if started && r.Attempts[kind].Count == 0 {
			r.Attempts[kind] = directEnrollmentAttempt{Count: 1}
		}
	}
}

// observeAbsent records only authoritative GET absence. It does not assert an
// earlier request cannot still commit, so subsequent attempts reuse stored bytes.
func (j *directEnrollmentJournal) observeAbsent(s *DirectEndpointSubscription, b directEnrollmentBinding, kind string) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "material" || !r.dispatchKind(kind) {
			return errDirectEnrollment
		}
		r.importLegacyAttempts()
		a := r.Attempts[kind]
		a.Recovered = a.Count
		r.Attempts[kind] = a
		return nil
	})
}
func (j *directEnrollmentJournal) observePublication(s *DirectEndpointSubscription, b directEnrollmentBinding, hash [32]byte) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "material" || hash != r.PublicationHash {
			return errDirectEnrollment
		}
		r.PublicationObserved = true
		return nil
	})
}
func (j *directEnrollmentJournal) observeChallenge(s *DirectEndpointSubscription, b directEnrollmentBinding, challenge []byte) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "material" || len(challenge) == 0 || (len(r.Challenge) > 0 && !bytes.Equal(challenge, r.Challenge)) {
			return errDirectEnrollment
		}
		r.Challenge = bytes.Clone(challenge)
		return nil
	})
}
func enrollmentObservedTime(value string, b directEnrollmentBinding) bool {
	t, err := time.Parse(time.RFC3339Nano, value)
	d, e := transport.DecodeDirectChannelDescriptorV2(b.Descriptor)
	expiry, ex := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	return err == nil && e == nil && ex == nil && !t.IsZero() && !t.After(expiry)
}
func (j *directEnrollmentJournal) observeProof(s *DirectEndpointSubscription, b directEnrollmentBinding, digest [32]byte, receivedAt string) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "material" || len(r.Proof) == 0 || digest != enrollmentHash(r.Proof) || !enrollmentObservedTime(receivedAt, b) || (r.ProofReceivedAt != "" && r.ProofReceivedAt != receivedAt) {
			return errDirectEnrollment
		}
		r.ProofReceivedAt = receivedAt
		return nil
	})
}

type directEnrollmentActivation struct{ ChannelID, ActivatedAt, ExpiresAt string }

func (j *directEnrollmentJournal) observeActivation(s *DirectEndpointSubscription, b directEnrollmentBinding, channelID, activatedAt, expiresAt string) (directEnrollmentRecord, error) {
	return j.apply(s, b, func(r *directEnrollmentRecord, exists bool) error {
		if !exists || r.State != "material" || len(r.Proof) == 0 || channelID != b.Channel || !enrollmentObservedTime(activatedAt, b) || !enrollmentObservedTime(expiresAt, b) {
			return errDirectEnrollment
		}
		start, _ := time.Parse(time.RFC3339Nano, activatedAt)
		end, _ := time.Parse(time.RFC3339Nano, expiresAt)
		if !start.Before(end) {
			return errDirectEnrollment
		}
		raw, _ := json.Marshal(directEnrollmentActivation{channelID, activatedAt, expiresAt})
		if len(r.Activation) > 0 && !bytes.Equal(raw, r.Activation) {
			return errDirectEnrollment
		}
		r.Activation = raw
		r.ActivationHash = enrollmentDigest(raw)
		return nil
	})
}
