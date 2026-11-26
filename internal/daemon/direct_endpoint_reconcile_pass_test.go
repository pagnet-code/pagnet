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
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/directchannelcrypto"
	"github.com/pagnet-code/pagnet/internal/directhttp"
	"github.com/pagnet-code/pagnet/transport"
)

type reconcilePassFixture struct {
	f       *reconcileOperationFixture
	binding directEndpointReconcileBinding
	client  *reconcilePassFakeClient
	run     directEndpointReconcilePass
}
type reconcilePassFakeClient struct {
	*reconcileObservationReader
	fixture            *reconcilePassFixture
	accept             bool
	publishErr         error
	badResponse        bool
	onPublish          func(context.Context)
	publications       [][]byte
	verifiers          []string
	challenges         [][]byte
	challengeErr       error
	rejectChallenge    bool
	challengeResponse  func(transport.DirectChannelReadinessChallengeV2) transport.DirectChannelReadinessChallengeV2
	onChallenge        func(context.Context)
	proofs             [][]byte
	proveErr           error
	rejectProof        bool
	proofResponse      func(transport.DirectChannelReadinessProofV2) transport.DirectChannelReadinessProofV2
	onProve            func(context.Context)
	activations        []directhttp.Activation
	activationErr      error
	rejectActivation   bool
	activationResponse func(directhttp.Activation) directhttp.Activation
	onActivate         func(context.Context)
}

func (c *reconcilePassFakeClient) Publish(ctx context.Context, credential, intent string, p transport.DirectChannelPublicationV2, verifier string) (transport.DirectChannelPublicationV2, error) {
	if err := c.record("publish", credential, intent); err != nil {
		return transport.DirectChannelPublicationV2{}, err
	}
	wire, err := p.CanonicalBytes()
	if err != nil {
		return transport.DirectChannelPublicationV2{}, err
	}
	c.publications = append(c.publications, bytes.Clone(wire))
	c.verifiers = append(c.verifiers, verifier)
	row, err := readPassJournal(c.fixture.f.d.nativeRegistry)
	if err != nil {
		c.t.Error("publication dispatched without readable journal")
		return transport.DirectChannelPublicationV2{}, err
	}
	defer clear(row.Root)
	attempt := row.Attempts["publication"]
	if attempt.Count == 0 || attempt.Count != attempt.Recovered+1 || row.PublicationObserved || !bytes.Equal(row.Publication, wire) {
		c.t.Error("publication dispatched without committed exact authorization")
	}
	material := &directchannelcrypto.Material{Hash: c.fixture.binding.DescriptorHash}
	copy(material.Key[:], row.Root)
	readiness, err := material.ReadinessKey()
	material.Clear()
	if err != nil {
		return transport.DirectChannelPublicationV2{}, err
	}
	if verifier != base64.RawURLEncoding.EncodeToString(readiness) {
		c.t.Error("publication verifier did not match retained root")
	}
	clear(readiness)
	if err := checkPassHTTPUnlocked(ctx, c.fixture.f); err != nil {
		c.t.Error("publication held local custody or journal locks")
		return transport.DirectChannelPublicationV2{}, err
	}
	if c.onPublish != nil {
		c.onPublish(ctx)
	}
	if c.accept {
		c.publication = p
		c.enrollment = publishedEnrollment(c.enrollment, wire)
	}
	if c.publishErr != nil {
		return transport.DirectChannelPublicationV2{}, c.publishErr
	}
	if c.badResponse {
		p.Enc = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	}
	return p, nil
}
func readPassJournal(registry *NativeWorkerRegistry) (directEnrollmentRecord, error) {
	var raw []byte
	if err := registry.db.QueryRow(`SELECT payload FROM native_direct_enrollment_v1`).Scan(&raw); err != nil {
		return directEnrollmentRecord{}, err
	}
	defer clear(raw)
	var row directEnrollmentRecord
	err := json.Unmarshal(raw, &row)
	return row, err
}
func checkPassHTTPUnlocked(ctx context.Context, f *reconcileOperationFixture) error {
	registry := f.d.nativeRegistry
	if !registry.mu.TryLock() {
		return errDirectEndpointLocalBusy
	}
	registry.mu.Unlock()
	namespace := nativeDirectManagedSourceKeyNamespaceV2
	if f.role == "P" {
		namespace = nativeManagedEndpointKeyNamespace
	}
	for _, name := range []string{"registry.custody.lock", filepath.Join(namespace, "holder.lock"), filepath.Join(directEnrollmentNamespace, "holder.lock")} {
		file, err := os.OpenFile(filepath.Join(registry.root, name), os.O_RDWR, 0)
		if err != nil {
			return err
		}
		release, err := directEndpointTryFlock(ctx, file)
		if err != nil {
			file.Close()
			return err
		}
		release()
		file.Close()
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := registry.db.Conn(bounded)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(bounded, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	_, err = conn.ExecContext(bounded, "ROLLBACK")
	return err
}
func newReconcilePassFixture(t *testing.T, role string) *reconcilePassFixture {
	t.Helper()
	var f *reconcileOperationFixture
	var b directEndpointReconcileBinding
	var e directhttp.Enrollment
	if role == "S" {
		f = newReconcileOperationFixture(t, role)
		b, e, _ = reconcileSourceOperationBinding(t, f)
	} else {
		f, b, e = newReconcileObservationTargetFixture(t)
	}
	e.ObservedAt = e.ObservedAt.UTC()
	out := &reconcilePassFixture{f: f, binding: b}
	out.client = &reconcilePassFakeClient{reconcileObservationReader: observationReader(t, f.s, b, e), fixture: out, accept: true}
	var err error
	if role == "S" {
		out.run, err = newDirectSourceReconcilePassWithClient(f.d, f.captured, f.s, f.source, out.client, time.Now)
	} else {
		out.run, err = newDirectTargetReconcilePassWithClient(f.d, f.captured, f.s, f.target, out.client, time.Now)
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func passJournalTableCount(t *testing.T, registry *NativeWorkerRegistry) int {
	t.Helper()
	var count int
	if err := registry.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='native_direct_enrollment_v1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
func TestDirectReconcilePassSourcePublicationAndRecovery(t *testing.T) {
	f := newReconcilePassFixture(t, "S")
	state, err := f.run(t.Context())
	if err != nil || state != directReconcilePublicationPublished {
		t.Fatalf("source pass: %s %v", state, err)
	}
	if !reflect.DeepEqual(f.client.calls, []string{"descriptor", "enrollment", "publish"}) || len(f.client.publications) != 1 {
		t.Fatal("source pass did not end after one PUT")
	}
	row, err := readPassJournal(f.f.d.nativeRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(row.Root)
	if row.PublicationObserved || row.Attempts["publication"].Count != 1 {
		t.Fatal("PUT response was treated as fresh GET evidence")
	}
	f.client.calls = nil
	state, err = f.run(t.Context())
	if err != nil || state != directReconcileChallengeRequested {
		t.Fatalf("source recovery: %s %v", state, err)
	}
	if !reflect.DeepEqual(f.client.calls, []string{"descriptor", "enrollment", "publication", "challenge"}) || len(f.client.publications) != 1 {
		t.Fatal("source recovery repeated PUT")
	}
	recovered, err := readPassJournal(f.f.d.nativeRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recovered.Root)
	if !recovered.PublicationObserved || !bytes.Equal(row.Root, recovered.Root) || !bytes.Equal(row.Publication, recovered.Publication) {
		t.Fatal("source recovery changed committed material")
	}
}
func TestDirectReconcilePassTarget(t *testing.T) {
	f := newReconcilePassFixture(t, "P")
	tables := passJournalTableCount(t, f.f.d.nativeRegistry)
	state, err := f.run(t.Context())
	if err != nil || state != directReconcileAwaitingPublication {
		t.Fatalf("target awaiting: %s %v", state, err)
	}
	if passJournalTableCount(t, f.f.d.nativeRegistry) != tables || len(f.client.publications) != 0 {
		t.Fatal("target absence mutated journal or remote state")
	}
	raw, err := os.ReadFile("../directchannelcrypto/testdata/sdk-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct{ SourcePrivate []byte }
	if json.Unmarshal(raw, &vector) != nil {
		t.Fatal("vector")
	}
	defer clear(vector.SourcePrivate)
	source, wire, err := directchannelcrypto.Prepare(f.binding.DescriptorBytes, f.binding.Descriptor, vector.SourcePrivate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer source.Clear()
	f.client.publication, err = transport.DecodeDirectChannelPublicationV2(wire)
	if err != nil {
		t.Fatal(err)
	}
	f.client.enrollment = publishedEnrollment(f.client.enrollment, wire)
	state, err = f.run(t.Context())
	if err != nil || state != directReconcileChallengeRequested {
		t.Fatalf("target accept: %s %v", state, err)
	}
	row, err := readPassJournal(f.f.d.nativeRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(row.Root)
	if !row.PublicationObserved || !bytes.Equal(row.Root, source.Key[:]) || !bytes.Equal(row.Publication, wire) || len(f.client.publications) != 0 {
		t.Fatal("target did not retain exact accepted material locally")
	}
}
func TestDirectReconcilePassReadErrorsAreNotAbsence(t *testing.T) {
	for _, role := range []string{"S", "P"} {
		t.Run(role, func(t *testing.T) {
			f := newReconcilePassFixture(t, role)
			for _, status := range []int{404, 409} {
				f.client.fail = "enrollment"
				f.client.reconcileObservationReader.failure = &directhttp.Error{Kind: directhttp.Unavailable, Status: status}
				state, err := f.run(t.Context())
				if err == nil || state != "" || len(f.client.publications) != 0 || passJournalTableCount(t, f.f.d.nativeRegistry) != 0 {
					t.Fatal("GET error was treated as authenticated absence")
				}
			}
		})
	}
}
func TestDirectReconcilePassSourceMissingRoot(t *testing.T) {
	f := newReconcilePassFixture(t, "S")
	f.client.publication = observationPublication(t, f.binding)
	wire, _ := f.client.publication.CanonicalBytes()
	f.client.enrollment = publishedEnrollment(f.client.enrollment, wire)
	for attempt := 0; attempt < 2; attempt++ {
		state, err := f.run(t.Context())
		if err != errDirectEndpointReconcileSourceRootMissing || state != "" || len(f.client.publications) != 0 {
			t.Fatalf("missing root disposition: %s %v", state, err)
		}
		row, err := readPassJournal(f.f.d.nativeRegistry)
		if err != nil {
			t.Fatal(err)
		}
		clear(row.Root)
		if row.State != "reserved" || len(row.Publication) != 0 {
			t.Fatal("source regenerated material for remote publication")
		}
	}
}
func TestDirectReconcilePassUnknownPublish(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "not accepted", true: "accepted"}[committed], func(t *testing.T) {
			f := newReconcilePassFixture(t, "S")
			f.client.accept = committed
			f.client.publishErr = &directhttp.Error{Kind: directhttp.Transport, Status: 503, UnknownCommit: true}
			state, err := f.run(t.Context())
			var wireErr *directhttp.Error
			if state != "" || !errors.As(err, &wireErr) || !wireErr.UnknownCommit || len(f.client.publications) != 1 {
				t.Fatal("mutation uncertainty was lost")
			}
			first, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(first.Root)
			f.client.publishErr = nil
			f.client.accept = true
			f.client.calls = nil
			state, err = f.run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if committed {
				if state != directReconcileChallengeRequested || len(f.client.publications) != 1 {
					t.Fatal("accepted publication was retried")
				}
			} else {
				if state != directReconcilePublicationPublished || len(f.client.publications) != 2 || !bytes.Equal(f.client.publications[0], f.client.publications[1]) || f.client.verifiers[0] != f.client.verifiers[1] {
					t.Fatal("unknown publication retry changed immutable bytes")
				}
			}
			recovered, err := readPassJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(recovered.Root)
			if !bytes.Equal(first.Root, recovered.Root) || !bytes.Equal(first.Publication, recovered.Publication) {
				t.Fatal("unknown outcome regenerated root or publication")
			}
		})
	}
}
func TestDirectReconcilePassUnknownDispatchCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
			f := newReconcilePassFixture(t, "S")
			journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
			if err != nil {
				t.Fatal(err)
			}
			connector := enrollmentContextWrap(t, journal)
			pending, injected := false, false
			var retained []byte
			connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
				if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") {
					var row directEnrollmentRecord
					if json.Unmarshal(args[3].Value.([]byte), &row) == nil {
						pending = row.Attempts["publication"].Count > row.Attempts["publication"].Recovered
						if pending {
							retained = bytes.Clone(row.Publication)
						}
					}
					clear(row.Root)
				}
				if query == "COMMIT" && pending && !injected {
					injected = true
					if committed {
						if _, err := next.ExecContext(ctx, query, args); err != nil {
							return nil, err
						}
					}
					return nil, errors.New("lost dispatch acknowledgement")
				}
				return next.ExecContext(ctx, query, args)
			}
			state, err := f.run(t.Context())
			connector.exec = nil
			if err == nil || errors.Is(err, errDirectEndpointReconcileSourceRootMissing) || state != "" || !injected || len(f.client.publications) != 0 {
				t.Fatal("uncertain dispatch COMMIT reached HTTP or became missing-root terminal")
			}
			state, err = f.run(t.Context())
			if err != nil || state != directReconcilePublicationPublished || len(f.client.publications) != 1 || !bytes.Equal(retained, f.client.publications[0]) {
				t.Fatal("fresh pass did not reuse exact durable material")
			}
		})
	}
}
func TestDirectReconcilePassPublishErrorPrecedence(t *testing.T) {
	for _, kind := range []string{"known rollback", "unknown injected", "bad response", "cancel", "abort"} {
		t.Run(kind, func(t *testing.T) {
			f := newReconcilePassFixture(t, "S")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.client.accept = false
			f.client.publishErr = &directhttp.Error{Kind: directhttp.Conflict, Status: 409, UnknownCommit: false}
			switch kind {
			case "unknown injected":
				f.client.publishErr = errors.New("untrusted writer details")
			case "bad response":
				f.client.publishErr = nil
				f.client.badResponse = true
			case "cancel":
				f.client.onPublish = func(context.Context) { cancel() }
			case "abort":
				f.client.onPublish = func(context.Context) { f.f.token.proxy.abort() }
			}
			state, err := f.run(ctx)
			if state != "" || len(f.client.publications) != 1 {
				t.Fatal("mutation error did not end pass")
			}
			var wireErr *directhttp.Error
			switch kind {
			case "known rollback":
				if !errors.As(err, &wireErr) || wireErr.UnknownCommit || wireErr.Status != 409 {
					t.Fatal("accepted lease lost known rollback classification")
				}
			case "bad response":
				if !errors.As(err, &wireErr) || !wireErr.UnknownCommit || wireErr.Kind != directhttp.Protocol {
					t.Fatal("bad response was accepted")
				}
			default:
				if err != errDirectEndpointOperationUnknown || errors.As(err, &wireErr) {
					t.Fatal("uncertain operation exposed a known rollback")
				}
			}
		})
	}
}
func TestDirectReconcilePassConcurrencyAndCancel(t *testing.T) {
	f := newReconcilePassFixture(t, "S")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if state, err := f.run(cancelled); state != "" || err != context.Canceled || len(f.client.calls) != 0 {
		t.Fatal("cancelled pass reached observer")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var reentrantErr error
	f.client.onPublish = func(ctx context.Context) { _, reentrantErr = f.run(ctx); close(entered); <-release }
	type passResult struct {
		state directEndpointReconcilePassState
		err   error
	}
	finished := make(chan passResult, 1)
	go func() { state, err := f.run(t.Context()); finished <- passResult{state, err} }()
	<-entered
	if state, err := f.run(t.Context()); state != "" || err != errDirectEndpointLocalBusy {
		t.Error("concurrent pass bypassed gate")
	}
	close(release)
	result := <-finished
	if result.err != nil || result.state != directReconcilePublicationPublished || reentrantErr != errDirectEndpointLocalBusy || len(f.client.publications) != 1 {
		t.Fatal("pass gate or single mutation contract failed")
	}
}

func TestDirectReconcilePassDescriptorDeadline(t *testing.T) {
	f := newReconcilePassFixture(t, "S")
	descriptor := f.binding.Descriptor
	deadline := time.Now().UTC().Add(30 * time.Second)
	descriptor.ExpiresAt = deadline.Format(time.RFC3339Nano)
	enrollment := reconcileEnrollment(t, descriptor, time.Now())
	binding, err := validateDirectSourceReconcileBindingV2Context(t.Context(), f.f.s, f.f.captured, f.f.source, descriptor, enrollment, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.binding = binding
	f.client.descriptor = descriptor
	f.client.enrollment = enrollment
	f.client.onPublish = func(ctx context.Context) {
		if actual, ok := ctx.Deadline(); !ok || !actual.Equal(deadline) || !actual.Before(f.f.s.binding.metadata.Deadline) {
			t.Error("PUT context did not use descriptor deadline")
		}
	}
	if state, err := f.run(t.Context()); err != nil || state != directReconcilePublicationPublished {
		t.Fatalf("bounded publication: %s %v", state, err)
	}
}

func TestDirectReconcilePassExpiryDuringDispatchCommit(t *testing.T) {
	f := newReconcilePassFixture(t, "S")
	expires, _ := time.Parse(time.RFC3339Nano, f.binding.Descriptor.ExpiresAt)
	var expired atomic.Bool
	now := func() time.Time {
		if expired.Load() {
			return expires.Add(time.Nanosecond)
		}
		return time.Now()
	}
	var err error
	f.run, err = newDirectSourceReconcilePassWithClient(f.f.d, f.f.captured, f.f.s, f.f.source, f.client, now)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := newDirectEnrollmentJournal(f.f.d.nativeRegistry)
	if err != nil {
		t.Fatal(err)
	}
	connector := enrollmentContextWrap(t, journal)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	pending, blocked := false, false
	connector.exec = func(ctx context.Context, query string, args []driver.NamedValue, next driver.ExecerContext) (driver.Result, error) {
		if strings.HasPrefix(query, "INSERT INTO native_direct_enrollment_v1 VALUES") {
			var row directEnrollmentRecord
			if json.Unmarshal(args[3].Value.([]byte), &row) == nil {
				pending = row.Attempts["publication"].Count > row.Attempts["publication"].Recovered
			}
			clear(row.Root)
		}
		if query == "COMMIT" && pending && !blocked {
			blocked = true
			close(entered)
			<-release
		}
		return next.ExecContext(ctx, query, args)
	}
	type passResult struct {
		state directEndpointReconcilePassState
		err   error
	}
	finished := make(chan passResult, 1)
	go func() { state, err := f.run(t.Context()); finished <- passResult{state, err} }()
	select {
	case <-entered:
	case result := <-finished:
		connector.exec = nil
		t.Fatalf("pass ended before dispatch fence: %s %v", result.state, result.err)
	case <-time.After(10 * time.Second):
		t.Fatal("dispatch fence not reached")
	}
	expired.Store(true)
	unblock()
	result := <-finished
	connector.exec = nil
	if result.err == nil || result.state != "" || len(f.client.publications) != 0 {
		t.Fatal("expired descriptor reached PUT")
	}
	row, err := readPassJournal(f.f.d.nativeRegistry)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(row.Root)
	if row.Attempts["publication"].Count != 1 || row.Attempts["publication"].Recovered != 0 || len(row.Root) != 32 || row.PublicationObserved {
		t.Fatal("expiry did not retain exact durable dispatch attempt")
	}
}

func passReadinessChallenge(b directEndpointReconcileBinding, publication []byte, role string, issued time.Time) transport.DirectChannelReadinessChallengeV2 {
	local := b.Descriptor.S
	if role == "P" {
		local = b.Descriptor.P
	}
	channel, _ := transport.DirectChannelIDV2(b.Descriptor)
	publicationHash := sha256.Sum256(publication)
	expires := issued.Add(30 * time.Second)
	descriptorExpiry, _ := time.Parse(time.RFC3339Nano, b.Descriptor.ExpiresAt)
	if expires.After(descriptorExpiry) {
		expires = descriptorExpiry
	}
	return transport.DirectChannelReadinessChallengeV2{Domain: transport.DirectChannelDomainV2 + "/proof", ChallengeID: string(domain.NewID()), Role: role, PrincipalID: local.PrincipalID, EndpointID: local.EndpointID, CredentialID: local.CredentialID, ChannelID: channel, ParentGrantID: b.Descriptor.ParentGrantID, GrantGeneration: b.Descriptor.GrantGeneration, ChannelGeneration: b.Descriptor.ChannelGeneration, DirectIntentID: b.Descriptor.DirectIntentID, DescriptorHash: base64.RawURLEncoding.EncodeToString(b.DescriptorHash[:]), PublicationHash: base64.RawURLEncoding.EncodeToString(publicationHash[:]), EpochID: b.Descriptor.EpochID, Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)), IssuedAt: issued.UTC().Format(time.RFC3339Nano), ExpiresAt: expires.UTC().Format(time.RFC3339Nano)}
}
func (c *reconcilePassFakeClient) Challenge(ctx context.Context, credential, intent string) (transport.DirectChannelReadinessChallengeV2, error) {
	if err := c.record("challenge", credential, intent); err != nil {
		return transport.DirectChannelReadinessChallengeV2{}, err
	}
	row, err := readPassJournal(c.fixture.f.d.nativeRegistry)
	if err != nil {
		return transport.DirectChannelReadinessChallengeV2{}, err
	}
	defer clear(row.Root)
	attempt := row.Attempts["challenge"]
	if !row.PublicationObserved || attempt.Count != attempt.Recovered+1 || len(row.Challenge) != 0 || len(row.Proof) != 0 || row.ProofReceivedAt != "" {
		c.t.Error("challenge dispatched without committed absence authorization")
	}
	if err := checkPassHTTPUnlocked(ctx, c.fixture.f); err != nil {
		c.t.Error("challenge held local locks")
		return transport.DirectChannelReadinessChallengeV2{}, err
	}
	challenge := passReadinessChallenge(c.fixture.binding, row.Publication, c.role, time.Now())
	if c.challengeResponse != nil {
		challenge = c.challengeResponse(challenge)
	}
	raw, _ := challenge.CanonicalBytes()
	c.challenges = append(c.challenges, bytes.Clone(raw))
	if c.onChallenge != nil {
		c.onChallenge(ctx)
	}
	if !c.rejectChallenge {
		hash := sha256.Sum256(raw)
		c.enrollment.Challenge = &directhttp.EnrollmentChallenge{Challenge: challenge, TranscriptHash: base64.RawURLEncoding.EncodeToString(hash[:])}
		c.enrollment.ObservedAt = time.Now().UTC()
	}
	if c.challengeErr != nil {
		return transport.DirectChannelReadinessChallengeV2{}, c.challengeErr
	}
	return challenge, nil
}

func (c *reconcilePassFakeClient) Prove(ctx context.Context, credential, intent string, proof transport.DirectChannelReadinessProofV2) (transport.DirectChannelReadinessProofV2, error) {
	if err := c.record("prove", credential, intent); err != nil {
		return transport.DirectChannelReadinessProofV2{}, err
	}
	raw, err := proof.CanonicalBytes()
	if err != nil {
		return transport.DirectChannelReadinessProofV2{}, err
	}
	c.proofs = append(c.proofs, bytes.Clone(raw))
	row, err := readPassJournal(c.fixture.f.d.nativeRegistry)
	if err != nil {
		return transport.DirectChannelReadinessProofV2{}, err
	}
	defer clear(row.Root)
	attempt := row.Attempts["proof"]
	if !row.PublicationObserved || len(row.Challenge) == 0 || !bytes.Equal(row.Proof, raw) || row.ProofReceivedAt != "" || attempt.Count != attempt.Recovered+1 {
		c.t.Error("proof dispatched without committed exact authorization")
	}
	publication, err := transport.DecodeDirectChannelPublicationV2(row.Publication)
	if err != nil {
		return transport.DirectChannelReadinessProofV2{}, err
	}
	challenge, err := transport.DecodeDirectChannelReadinessChallengeV2(row.Challenge)
	if err != nil {
		return transport.DirectChannelReadinessProofV2{}, err
	}
	material := &directchannelcrypto.Material{Hash: c.fixture.binding.DescriptorHash}
	copy(material.Key[:], row.Root)
	readiness, err := material.ReadinessKey()
	material.Clear()
	if err != nil {
		return transport.DirectChannelReadinessProofV2{}, err
	}
	verifyErr := transport.VerifyDirectChannelReadinessProofV2(publication, challenge, proof, readiness, time.Now())
	clear(readiness)
	if verifyErr != nil {
		c.t.Error("proof did not match retained readiness key")
		return transport.DirectChannelReadinessProofV2{}, verifyErr
	}
	if err := checkPassHTTPUnlocked(ctx, c.fixture.f); err != nil {
		c.t.Error("proof held local locks")
		return transport.DirectChannelReadinessProofV2{}, err
	}
	if deadline, ok := ctx.Deadline(); !ok {
		c.t.Error("proof missing challenge deadline")
	} else {
		expiry, _ := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
		if deadline.After(expiry) {
			c.t.Error("proof deadline exceeds challenge expiry")
		}
	}
	if c.onProve != nil {
		c.onProve(ctx)
	}
	if !c.rejectProof {
		digest := sha256.Sum256(raw)
		received := time.Now().UTC()
		c.enrollment.Proof = &directhttp.EnrollmentProof{Digest: base64.RawURLEncoding.EncodeToString(digest[:]), ReceivedAt: received}
		c.enrollment.ObservedAt = received
	}
	if c.proveErr != nil {
		return transport.DirectChannelReadinessProofV2{}, c.proveErr
	}
	if c.proofResponse != nil {
		proof = c.proofResponse(proof)
	}
	return proof, nil
}

func (c *reconcilePassFakeClient) Activate(ctx context.Context, credential, intent string) (directhttp.Activation, error) {
	if err := c.record("activate", credential, intent); err != nil {
		return directhttp.Activation{}, err
	}
	row, err := readPassJournal(c.fixture.f.d.nativeRegistry)
	if err != nil {
		return directhttp.Activation{}, err
	}
	defer clear(row.Root)
	attempt := row.Attempts["activation"]
	if !row.PublicationObserved || len(row.Proof) == 0 || row.ProofReceivedAt == "" || len(row.Activation) != 0 || attempt.Count != attempt.Recovered+1 {
		c.t.Error("activation dispatched without committed proof receipt and authorization")
	}
	if c.enrollment.Proof == nil || row.ProofReceivedAt != c.enrollment.Proof.ReceivedAt.UTC().Format(time.RFC3339Nano) {
		c.t.Error("activation did not use authenticated original proof receipt")
	}
	publication, err := transport.DecodeDirectChannelPublicationV2(row.Publication)
	if err != nil {
		return directhttp.Activation{}, err
	}
	challenge, err := transport.DecodeDirectChannelReadinessChallengeV2(row.Challenge)
	if err != nil {
		return directhttp.Activation{}, err
	}
	proof, err := transport.DecodeDirectChannelReadinessProofV2(row.Proof)
	if err != nil {
		return directhttp.Activation{}, err
	}
	received, err := time.Parse(time.RFC3339Nano, row.ProofReceivedAt)
	if err != nil {
		return directhttp.Activation{}, err
	}
	material := &directchannelcrypto.Material{Hash: c.fixture.binding.DescriptorHash}
	copy(material.Key[:], row.Root)
	readiness, err := material.ReadinessKey()
	material.Clear()
	if err != nil {
		return directhttp.Activation{}, err
	}
	verifyErr := transport.VerifyDirectChannelReadinessProofV2(publication, challenge, proof, readiness, received)
	clear(readiness)
	if verifyErr != nil {
		c.t.Error("activation used invalid historical proof")
		return directhttp.Activation{}, verifyErr
	}
	if err := checkPassHTTPUnlocked(ctx, c.fixture.f); err != nil {
		c.t.Error("activation held local locks")
		return directhttp.Activation{}, err
	}
	expiry, _ := time.Parse(time.RFC3339Nano, c.fixture.binding.Descriptor.ExpiresAt)
	if deadline, ok := ctx.Deadline(); !ok || deadline.After(expiry) {
		c.t.Error("activation deadline exceeds descriptor authority")
	}
	value := directhttp.Activation{ChannelID: c.enrollment.Authority.ChannelID, ActivatedAt: time.Now().UTC(), ExpiresAt: expiry}
	if c.activationResponse != nil {
		value = c.activationResponse(value)
	}
	c.activations = append(c.activations, value)
	if c.onActivate != nil {
		c.onActivate(ctx)
	}
	if !c.rejectActivation {
		c.enrollment.Activation = &directhttp.EnrollmentActivation{ActivatedAt: value.ActivatedAt, ExpiresAt: value.ExpiresAt}
		c.enrollment.ObservedAt = time.Now().UTC()
	}
	if c.activationErr != nil {
		return directhttp.Activation{}, c.activationErr
	}
	return value, nil
}
