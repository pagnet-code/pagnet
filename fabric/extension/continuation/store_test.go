package continuation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
)

var ctx = context.Background()
var original = fabric.Principal{Ref: "agent:one", Kind: "test.agent", Issuer: "issuer:agents"}
var human = fabric.Principal{Ref: "human:one", Kind: "test.human", Issuer: "issuer:humans"}

func ident(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func auth(t *testing.T, p fabric.Principal, audience string, raw []byte) fabric.ExecutionContext {
	t.Helper()
	c, e := fabric.NewAuthenticatedContext(p, audience, raw)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func fixture(t *testing.T) (*Store, string, Snapshot, fabric.ExecutionContext, fabric.ExecutionContext, time.Time) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	s, e := Bootstrap(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "invocation", Operation: fabric.OperationDiscover, Principal: original, Source: original.Ref, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"value":1}`), Context: fabric.EnvelopeContext{Origin: original.Ref}}
	raw, e := json.Marshal(env)
	if e != nil {
		t.Fatal(e)
	}
	pipeline := []byte("{\n \"stage\": 1, \"text\":\"<>&\"\n}")
	v := Snapshot{Format: 1, DeferralID: ident("deferral"), OriginalEnvelope: raw, OriginalPrincipal: original, AllowedResumePrincipals: []fabric.Principal{human}, PlanRevision: "plan:1", PlanVersion: "1", PlanDigest: identBytes(pipeline), Pipeline: pipeline, State: []byte("{ \"transformed\": true }")}
	return s, dir, v, auth(t, original, "test:audience", raw), auth(t, human, "test:audience", []byte("private verified claim")), time.Now().UTC().Add(time.Hour)
}
func identBytes(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func issue(t *testing.T, s *Store, c fabric.ExecutionContext, v Snapshot, expiry time.Time) Issued {
	t.Helper()
	x, e := s.Create(ctx, c, v, expiry)
	if e != nil || !x.Created || x.Capability.Token() == "" {
		t.Fatalf("issue: %+v %v", x, e)
	}
	return x
}
func TestExactDedupClaimRestartSettlement(t *testing.T) {
	s, dir, v, c, h, expiry := fixture(t)
	x := issue(t, s, c, v, expiry)
	retry, e := s.Create(ctx, c, v, expiry)
	if e != nil || retry.Created || retry.Capability.Token() != "" || retry.ID != x.ID {
		t.Fatalf("dedup %v %v", retry, e)
	}
	changed := v
	changed.State = []byte(`{"transformed":false}`)
	if _, e = s.Create(ctx, c, changed, expiry); e == nil {
		t.Fatal("changed source accepted")
	}
	if _, e = s.Create(ctx, c, v, expiry.Add(time.Second)); e == nil {
		t.Fatal("changed expiry accepted")
	}
	first, e := s.Claim(ctx, h, x.Capability.Token(), ident("claim"))
	if e != nil || !first.Fresh || first.State != Claimed {
		t.Fatal(first, e)
	}
	if !bytes.Equal(first.Snapshot.OriginalEnvelope, v.OriginalEnvelope) || !bytes.Equal(first.Snapshot.Pipeline, v.Pipeline) || !bytes.Equal(first.Snapshot.State, v.State) {
		t.Fatal("exact caller/plan bytes changed")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, e := s.Claim(ctx, h, x.Capability.Token(), ident("claim"))
	if e != nil || again.Fresh || again.Receipt != first.Receipt || again.State != Claimed {
		t.Fatal("claim replay", again, e)
	}
	if _, e = s.Claim(ctx, h, x.Capability.Token(), ident("competing")); e == nil {
		t.Fatal("second execution claim")
	}
	if _, e = s.RotatePendingCapability(ctx, h, x.ID, 1); e == nil {
		t.Fatal("claimed capability rotated")
	}
	out := Outcome{Effect: fabric.EffectUnknown, Data: []byte(`{"settlement":"uncertain"}`)}
	got, e := s.Complete(ctx, h, first.Receipt, out)
	if e != nil || !bytes.Equal(got.Data, out.Data) {
		t.Fatal(e)
	}
	if _, e = s.Complete(ctx, h, first.Receipt, out); e != nil {
		t.Fatal(e)
	}
	out.Effect = fabric.EffectCompleted
	if _, e = s.Complete(ctx, h, first.Receipt, out); e == nil {
		t.Fatal("changed completion overwrote outcome")
	}
	again, e = s.Claim(ctx, h, x.Capability.Token(), ident("claim"))
	if e != nil || again.Fresh || again.State != Complete || again.Outcome == nil || again.Outcome.Effect != fabric.EffectUnknown {
		t.Fatal(again, e)
	}
}
func TestAuthenticationAndRotation(t *testing.T) {
	s, _, v, c, h, expiry := fixture(t)
	x := issue(t, s, c, v, expiry)
	for _, bad := range []fabric.ExecutionContext{{}, auth(t, human, "wrong:audience", []byte("claim")), auth(t, fabric.Principal{Ref: human.Ref, Kind: human.Kind, Issuer: "forged:issuer"}, "test:audience", []byte("claim")), auth(t, original, "test:audience", []byte("claim"))} {
		if _, e := s.Claim(ctx, bad, x.Capability.Token(), ident("claim")); e == nil {
			t.Fatal("unauthorized claim")
		}
		if _, e := s.RotatePendingCapability(ctx, bad, x.ID, 1); e == nil {
			t.Fatal("unauthorized rotation")
		}
	}
	if _, e := s.Create(ctx, h, v, expiry); e == nil {
		t.Fatal("human relabeled original")
	}
	fake := v
	fake.OriginalEnvelope = append([]byte(" "), v.OriginalEnvelope...)
	if _, e := s.Create(ctx, c, fake, expiry); e == nil {
		t.Fatal("changed original authenticated bytes")
	}
	rotated, e := s.RotatePendingCapability(ctx, h, x.ID, 1)
	if e != nil || rotated.CapabilityRevision != 2 {
		t.Fatal(rotated, e)
	}
	if _, e = s.RotatePendingCapability(ctx, h, x.ID, 1); e == nil {
		t.Fatal("stale rotation")
	}
	if _, e = s.Claim(ctx, h, x.Capability.Token(), ident("claim")); e == nil {
		t.Fatal("old capability survived")
	}
	first, e := s.Claim(ctx, h, rotated.Capability.Token(), ident("claim"))
	if e != nil || !first.Fresh {
		t.Fatal(first, e)
	}
	bad := auth(t, fabric.Principal{Ref: human.Ref, Kind: human.Kind, Issuer: "forged:issuer"}, "test:audience", []byte("claim"))
	if _, e = s.Complete(ctx, bad, first.Receipt, Outcome{fabric.EffectNotStarted, []byte(`null`)}); e == nil {
		t.Fatal("wrong issuer completed")
	}
	raw, _ := json.Marshal(x)
	if strings.Contains(string(raw), x.Capability.Token()) || strings.Contains(fmt.Sprintf("%+v %#v", x, x), x.Capability.Token()) {
		t.Fatal("private token leaked")
	}
	if _, e = json.Marshal(x.Capability); e == nil {
		t.Fatal("secret marshaled")
	}
}
func TestConcurrentClaimsAndRotation(t *testing.T) {
	s, _, v, c, h, expiry := fixture(t)
	x := issue(t, s, c, v, expiry)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, e := s.Claim(ctx, h, x.Capability.Token(), ident(fmt.Sprint(i)))
			if e == nil {
				if !r.Fresh {
					t.Error("unexpected repeated claim")
				}
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d executable claims", wins)
	}
	v.DeferralID = ident("rotation-race")
	x = issue(t, s, c, v, expiry)
	start := make(chan struct{})
	var rotation Issued
	var re, ce error
	var claim ClaimResult
	wg.Add(2)
	go func() { defer wg.Done(); <-start; rotation, re = s.RotatePendingCapability(ctx, h, x.ID, 1) }()
	go func() { defer wg.Done(); <-start; claim, ce = s.Claim(ctx, h, x.Capability.Token(), ident("racing")) }()
	close(start)
	wg.Wait()
	if (re == nil) == (ce == nil) {
		t.Fatalf("both/neither CAS won: %v %v", re, ce)
	}
	if ce == nil && !claim.Fresh {
		t.Fatal("claim not fresh")
	}
	if re == nil {
		if _, e := s.Claim(ctx, h, x.Capability.Token(), ident("old")); e == nil {
			t.Fatal("rotated token claimed")
		}
		if _, e := s.Claim(ctx, h, rotation.Capability.Token(), ident("new")); e != nil {
			t.Fatal(e)
		}
	}
}
func TestTransactionalRollbackExpiryAndBounds(t *testing.T) {
	s, dir, v, c, h, expiry := fixture(t)
	if _, e := s.db.Exec("CREATE TRIGGER reject_create BEFORE INSERT ON continuations BEGIN SELECT RAISE(ABORT,'test'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Create(ctx, c, v, expiry); e == nil {
		t.Fatal("trigger ignored")
	}
	var rows, used int64
	s.db.QueryRow("SELECT records,bytes FROM budget").Scan(&rows, &used)
	if rows != 0 || used != 0 {
		t.Fatal("failed creation reserved quota")
	}
	s.db.Exec("DROP TRIGGER reject_create")
	x := issue(t, s, c, v, expiry)
	if _, e := s.db.Exec("CREATE TRIGGER reject_claim BEFORE UPDATE ON continuations BEGIN SELECT RAISE(ABORT,'test'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Claim(ctx, h, x.Capability.Token(), ident("claim")); e == nil {
		t.Fatal("trigger ignored")
	}
	s.db.QueryRow("SELECT records,bytes FROM budget").Scan(&rows, &used)
	b, _ := json.Marshal(v)
	if used != int64(len(b)+28) {
		t.Fatal("failed claim reserved quota")
	}
	s.db.Exec("DROP TRIGGER reject_claim")
	s.db.Exec("UPDATE continuations SET expires=?", time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano))
	if _, e := s.Claim(ctx, h, x.Capability.Token(), ident("claim")); e == nil {
		t.Fatal("expired claim accepted")
	}
	if _, e := s.RotatePendingCapability(ctx, h, x.ID, 1); e == nil {
		t.Fatal("expired rotation accepted")
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(ctx, dir, Scope{"wrong"}, DefaultOptions(), testProtector(t)); e == nil {
		t.Fatal("foreign audience opened")
	}
	o := DefaultOptions()
	o.MaxRecords = 0
	if _, e := Open(ctx, dir, Scope{"test:audience"}, o, testProtector(t)); e == nil {
		t.Fatal("invalid limits")
	}
	o = DefaultOptions()
	o.MaxRecords = 1
	s, e := Open(ctx, dir, Scope{"test:audience"}, o, testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	v.DeferralID = ident("second")
	if _, e = s.Create(ctx, c, v, expiry); e == nil {
		t.Fatal("configured record bound exceeded")
	}
}
func TestCrashAfterClaimNoReexecution(t *testing.T) {
	if os.Getenv("PAGNET_CONTINUATION_CRASH_CHILD") == "1" {
		dir := os.Getenv("PAGNET_CONTINUATION_DIR")
		s, e := Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
		if e != nil {
			os.Exit(31)
		}
		h, _ := fabric.NewAuthenticatedContext(human, "test:audience", []byte("claim"))
		r, e := s.Claim(ctx, h, os.Getenv("PAGNET_CONTINUATION_TOKEN"), ident("crash"))
		if e != nil || !r.Fresh {
			os.Exit(32)
		}
		os.Exit(37)
	}
	s, dir, v, c, h, expiry := fixture(t)
	x := issue(t, s, c, v, expiry)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashAfterClaimNoReexecution$")
	cmd.Env = append(os.Environ(), "PAGNET_CONTINUATION_CRASH_CHILD=1", "PAGNET_CONTINUATION_DIR="+dir, "PAGNET_CONTINUATION_TOKEN="+x.Capability.Token())
	e := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 37 {
		t.Fatal("child did not crash after durable claim", e)
	}
	s, e = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	r, e := s.Claim(ctx, h, x.Capability.Token(), ident("crash"))
	if e != nil || r.Fresh || r.State != Claimed {
		t.Fatal("crash repeated executable effects", r, e)
	}
}

func TestCapabilityHashOnlyAndPendingReopenRotation(t *testing.T) {
	s, dir, v, c, h, expiry := fixture(t)
	x := issue(t, s, c, v, expiry)
	token := x.Capability.Token()
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(filepath.Join(dir, "continuations.sqlite"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte(token)) || bytes.Contains(data, []byte(token[65:])) {
		t.Fatal("private capability persisted")
	}
	s, e = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	retry, e := s.Create(ctx, c, v, expiry)
	if e != nil || retry.Created || retry.Capability.Token() != "" {
		t.Fatal("ambiguous create reissued secret", retry, e)
	}
	r, e := s.RotatePendingCapability(ctx, h, x.ID, retry.CapabilityRevision)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.Claim(ctx, h, token, ident("old")); e == nil {
		t.Fatal("old persisted capability active")
	}
	if _, e = s.Claim(ctx, h, r.Capability.Token(), ident("new")); e != nil {
		t.Fatal(e)
	}
}
func TestReceiptTamperingAndCompleteAfterExpiry(t *testing.T) {
	s, dir, v, c, h, expiry := fixture(t)
	x := issue(t, s, c, v, expiry)
	r, e := s.Claim(ctx, h, x.Capability.Token(), ident("claim"))
	if e != nil {
		t.Fatal(e)
	}
	out := Outcome{fabric.EffectNotStarted, []byte(`{"settled":true}`)}
	for _, mutate := range []func(*Receipt){func(r *Receipt) { r.PlanDigest = ident("other") }, func(r *Receipt) { r.SnapshotDigest = ident("other") }, func(r *Receipt) { r.CapabilityRevision++ }, func(r *Receipt) { r.ClaimID = ident("other") }} {
		bad := r.Receipt
		mutate(&bad)
		if _, e = s.Complete(ctx, h, bad, out); e == nil {
			t.Fatal("tampered receipt settled")
		}
	}
	// Expiry is not extended: wait with a test-controlled stored timestamp later
	// than original claim but earlier than now, preserving startup invariants.
	short := r.Receipt.ClaimedAt.Add(time.Millisecond)
	if wait := time.Until(short); wait > 0 {
		time.Sleep(wait)
	}
	if _, e = s.db.Exec("UPDATE continuations SET expires=?", short.Format(time.RFC3339Nano)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Complete(ctx, h, r.Receipt, out); e != nil {
		t.Fatal("truthful expired settlement denied", e)
	}
	s.Close()
	s, e = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	replay, e := s.Claim(ctx, h, x.Capability.Token(), ident("claim"))
	if e != nil || replay.Fresh || replay.State != Complete {
		t.Fatal(replay, e)
	}
}
func TestMissingCorruptStateFailsClosed(t *testing.T) {
	s, dir, v, c, _, expiry := fixture(t)
	issue(t, s, c, v, expiry)
	if _, e := Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t)); e == nil {
		t.Fatal("second writer")
	}
	s.db.Exec("UPDATE continuations SET snapshot_digest=?", ident("corrupted"))
	s.Close()
	if _, e := Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t)); e == nil {
		t.Fatal("corrupt commitment reopened")
	}
	if e := os.Remove(filepath.Join(dir, "continuations.sqlite")); e != nil {
		t.Fatal(e)
	}
	if _, e := Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t)); e == nil {
		t.Fatal("missing database regenerated")
	}
}
func FuzzCapabilityCanonical(f *testing.F) {
	f.Add(ident("id") + "." + strings.Repeat("A", 43))
	f.Add("")
	f.Add(ident("id") + "." + strings.Repeat("A", 42) + "B")
	f.Fuzz(func(t *testing.T, token string) {
		id, hash, e := parseToken(token)
		if e == nil && (len(token) != 108 || len(hash) != 32 || !hexID(id)) {
			t.Fatal("noncanonical token accepted")
		}
	})
}

func TestDefaultCapacityMaxEnvelopeStateAnd500StagePipeline(t *testing.T) {
	s, dir, v, _, h, expiry := fixture(t)
	// A near-wire-limit original and transformed state are individually ~1MiB.
	// Five hundred exact 4KiB references and stage objects exceed 4096 JSON members;
	// base64 snapshot encoding must be admitted and verified within selected bounds.
	env := fabric.Envelope{ProtocolVersion: fabric.CurrentProtocolVersion, ID: "large-original", Operation: fabric.OperationDiscover, Principal: original, Source: original.Ref, CreatedAt: time.Now().UTC(), Payload: json.RawMessage(`{"text":"` + strings.Repeat("x", (1<<20)-2048) + `"}`), Context: fabric.EnvelopeContext{Origin: original.Ref}}
	raw, e := json.Marshal(env)
	if e != nil || len(raw) > (1<<20) || len(raw) < (1<<20)-4096 {
		t.Fatal("invalid max-envelope fixture", len(raw), e)
	}
	stages := make([]map[string]any, 500)
	for i := range stages {
		stages[i] = map[string]any{"ref": fmt.Sprintf("stage:%03d:", i) + strings.Repeat("r", 4086), "revision": "revision:1", "phase": "before", "operation": "invoke", "type": "extension.interceptor", "version": "1", "position": i, "admission": "private"}
	}
	v.Pipeline, e = json.Marshal(map[string]any{"stages": stages})
	if e != nil {
		t.Fatal(e)
	}
	v.PlanDigest = identBytes(v.Pipeline)
	v.State = append([]byte(`{"transformed":"`), bytes.Repeat([]byte("y"), (1<<20)-2048)...)
	v.State = append(v.State, []byte(`"}`)...)
	v.OriginalEnvelope = raw
	c := auth(t, original, "test:audience", raw)
	encoded, e := json.Marshal(v)
	if e != nil || len(encoded) <= 1<<20 || len(encoded) > s.options.MaxSnapshotBytes {
		t.Fatal("snapshot sizing proof", len(encoded), e)
	}
	t.Logf("bounded maximum fixture: original=%d state=%d pipeline=%d encoded=%d", len(raw), len(v.State), len(v.Pipeline), len(encoded))
	x := issue(t, s, c, v, expiry)
	claim, e := s.Claim(ctx, h, x.Capability.Token(), ident("large-claim"))
	if e != nil || !claim.Fresh || !bytes.Equal(claim.Snapshot.Pipeline, v.Pipeline) || !bytes.Equal(claim.Snapshot.State, v.State) || !bytes.Equal(claim.Snapshot.OriginalEnvelope, raw) {
		t.Fatal("full evidence changed", e)
	}
	s.Close()
	s, e = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, e := s.Claim(ctx, h, x.Capability.Token(), ident("large-claim"))
	if e != nil || again.Fresh || !bytes.Equal(again.Snapshot.Pipeline, v.Pipeline) {
		t.Fatal("large restart evidence", e)
	}
}

func TestSelectedOutcomeGrammarSurvivesRestart(t *testing.T) {
	s, dir, v, c, h, expiry := fixture(t)
	x := issue(t, s, c, v, expiry)
	r, e := s.Claim(ctx, h, x.Capability.Token(), ident("grammar"))
	if e != nil {
		t.Fatal(e)
	}
	members := make(map[string]int, 5000)
	for i := 0; i < 5000; i++ {
		members[fmt.Sprint("key", i)] = i
	}
	raw, e := json.Marshal(members)
	if e != nil {
		t.Fatal(e)
	}
	out := Outcome{fabric.EffectCompleted, raw}
	if _, e = s.Complete(ctx, h, r.Receipt, out); e != nil {
		t.Fatal("selected grammar rejected", e)
	}
	s.Close()
	s, e = Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal("completion readback grammar changed", e)
	}
	defer s.Close()
	again, e := s.Claim(ctx, h, x.Capability.Token(), ident("grammar"))
	if e != nil || again.Fresh || again.Outcome == nil || !bytes.Equal(again.Outcome.Data, raw) {
		t.Fatal("outcome mismatch", e)
	}
}

func testProtector(t *testing.T) durable.DataProtector {
	t.Helper()
	p, e := durable.NewAESGCM(durable.KeyReference{ID: "test-continuation-private", Version: "1"}, bytes.Repeat([]byte{91}, 32))
	if e != nil {
		t.Fatal(e)
	}
	return p
}
