package sender

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pagnet-code/pagnet/sdk"
)

var ctx = context.Background()

func binding() Binding {
	return Binding{ServiceOrigin: "https://example.com", PrincipalID: "11111111-1111-4111-8111-111111111111"}
}

const project = "22222222-2222-4222-8222-222222222222"
const recipient = "33333333-3333-4333-8333-333333333333"

// canonicalTempDir resolves system temporary-directory symlinks before tests
// construct store paths or add the symlinks they intend to exercise.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(canonicalTempDir(t), "private")
	s, err := Open(dir, binding())
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}
func reserveTest(t *testing.T, s *Store) Operation {
	t.Helper()
	o, err := s.Reserve(ctx, project, recipient, "sensitive prompt 🦊")
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func preparedFor(o Operation) sdk.PreparedSharingProjectMessage {
	return sdk.PreparedSharingProjectMessage{ID: o.AskID, Wire: []byte("durable SDK ciphertext")}
}
func replyFor(o Operation) Reply {
	id, _ := uuid.NewV7()
	return Reply{ProjectID: o.ProjectID, AskID: o.AskID, ReplyID: id.String(), WireDigest: digest([]byte("reply wire")), SenderID: recipient, RecipientID: binding().PrincipalID, Text: "answer"}
}

func TestReservedRecoveryKeepsIdentityAndProtectedInput(t *testing.T) {
	s, dir := openTest(t)
	o := reserveTest(t, s)
	if id, err := uuid.Parse(o.AskID); err != nil || id.Version() != 7 || o.Phase != Reserved {
		t.Fatalf("bad reservation: %+v", o)
	}
	for _, name := range []string{"key", "state"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private file %s: %v", name, err)
		}
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0700 {
		t.Fatal("directory not private")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "state"))
	if bytes.Contains(raw, []byte("sensitive prompt")) || bytes.Contains(raw, []byte(recipient)) {
		t.Fatal("state contains cleartext")
	}
	s.Close()
	reopened, err := Open(dir, Binding{ServiceOrigin: "https://EXAMPLE.com:443/", PrincipalID: binding().PrincipalID})
	if err != nil {
		t.Fatal(err)
	}
	all, err := reopened.List(ctx, Reserved)
	if err != nil || len(all) != 1 || all[0].AskID != o.AskID || all[0].Phase != Reserved {
		t.Fatalf("unresolved operation lost: %+v, %v", all, err)
	}
	prompt, err := reopened.RecoverPrompt(ctx, project, o.AskID)
	if err != nil || prompt != "sensitive prompt 🦊" || o.PromptDigest != digest([]byte(prompt)) {
		t.Fatalf("input recovery failed: %v", err)
	}
}

func TestReconcilePreparedAndAdmitted(t *testing.T) {
	s, dir := openTest(t)
	o := reserveTest(t, s)
	if _, err := s.MarkPrepared(ctx, project, o.AskID, preparedFor(o)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("preparation entry was bypassed: %v", err)
	}
	o, err := s.MarkPreparing(ctx, project, o.AskID)
	if err != nil || o.Phase != Preparing {
		t.Fatalf("preparation entry: %+v %v", o, err)
	}
	// Simulate a crash after SDK preparation but before the sender transition.
	prepared := preparedFor(o)
	s, _ = Open(dir, binding())
	if _, err := s.MarkAdmitted(ctx, project, o.AskID, sdk.SharingProjectMessageReceipt{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("admitted reserved state: %v", err)
	}
	o, err = s.MarkPrepared(ctx, project, o.AskID, prepared)
	if err != nil || o.Phase != Prepared || o.WireDigest != digest(prepared.Wire) {
		t.Fatalf("prepare: %+v %v", o, err)
	}
	if _, err = s.MarkPrepared(ctx, project, o.AskID, prepared); err != nil {
		t.Fatal(err)
	}
	conflict := prepared
	conflict.Wire = []byte("other ciphertext")
	if _, err = s.MarkPrepared(ctx, project, o.AskID, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("ciphertext replacement: %v", err)
	}
	d, _ := hex.DecodeString(o.WireDigest)
	r := sdk.SharingProjectMessageReceipt{MessageID: o.AskID, RequestDigest: d, AdmissionSeq: 1, CreatedAt: time.Now().UTC(), Status: "pending"}
	bad := r
	bad.RequestDigest = make([]byte, 32)
	if _, err = s.MarkAdmitted(ctx, project, o.AskID, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbound receipt: %v", err)
	}
	o, err = s.MarkAdmitted(ctx, project, o.AskID, r)
	if err != nil || o.Phase != Admitted {
		t.Fatalf("admit: %+v %v", o, err)
	}
	r.RequestDigest[0] ^= 1 // Returned/caller slices must not mutate the store.
	o.Receipt.RequestDigest[0] ^= 1
	s, err = Open(dir, binding())
	if err != nil {
		t.Fatal(err)
	}
	o, err = s.Get(ctx, project, o.AskID)
	if err != nil || !validReceipt(o, *o.Receipt) {
		t.Fatalf("receipt persistence: %v", err)
	}
	r = *o.Receipt
	r.AdmissionSeq++
	if _, err = s.MarkAdmitted(ctx, project, o.AskID, r); !errors.Is(err, ErrConflict) {
		t.Fatalf("receipt conflict: %v", err)
	}
}

func TestPreparingSurvivesCrashBeforeSDKCallWithoutReentry(t *testing.T) {
	s, dir := openTest(t)
	o := reserveTest(t, s)
	if _, err := s.MarkPreparing(ctx, project, o.AskID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err := Open(dir, binding())
	if err != nil {
		t.Fatal(err)
	}
	unresolved, err := s.List(ctx, Preparing)
	if err != nil || len(unresolved) != 1 || unresolved[0].AskID != o.AskID {
		t.Fatalf("ambiguous preparation lost: %+v %v", unresolved, err)
	}
	if _, err := s.MarkPreparing(ctx, project, o.AskID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reentered preparation: %v", err)
	}
	if _, err := s.MarkAdmitted(ctx, project, o.AskID, sdk.SharingProjectMessageReceipt{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("admitted unprepared operation: %v", err)
	}
}

func TestReplyDurabilityDuplicatesAndConflicts(t *testing.T) {
	s, dir := openTest(t)
	o := reserveTest(t, s)
	r := replyFor(o)
	if _, err := s.RecordReply(ctx, r); err != nil {
		t.Fatal(err)
	}
	s, _ = Open(dir, binding())
	if _, err := s.RecordReply(ctx, r); err != nil {
		t.Fatalf("duplicate: %v", err)
	}
	for _, change := range []func(*Reply){
		func(r *Reply) { r.Text = "other" },
		func(r *Reply) { r.WireDigest = digest([]byte("other")) },
		func(r *Reply) { id, _ := uuid.NewV7(); r.ReplyID = id.String() },
	} {
		bad := r
		change(&bad)
		if _, err := s.RecordReply(ctx, bad); !errors.Is(err, ErrConflict) {
			t.Fatalf("reply conflict: %v", err)
		}
	}
	for _, change := range []func(*Reply){
		func(r *Reply) { r.SenderID = binding().PrincipalID },
		func(r *Reply) { r.RecipientID = recipient },
		func(r *Reply) { r.Text = strings.Repeat("a", MaxReplyChars+1) },
		func(r *Reply) { r.ReplyID = "not-a-uuid" },
	} {
		bad := r
		change(&bad)
		if _, err := s.RecordReply(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid reply: %v", err)
		}
	}
	id, _ := uuid.NewV7()
	bad := r
	bad.AskID = id.String()
	if _, err := s.RecordReply(ctx, bad); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown ASK: %v", err)
	}
	o, _ = s.Get(ctx, project, o.AskID)
	o.Reply.Text = "caller mutation"
	o, _ = s.Get(ctx, project, o.AskID)
	if o.Reply.Text != r.Text {
		t.Fatal("reply aliased")
	}
}

func TestReopenRequiresDirectorySyncBeforeReplayAcknowledgement(t *testing.T) {
	s, dir := openTest(t)
	o := reserveTest(t, s)
	reply := replyFor(o)
	if _, err := s.RecordReply(ctx, reply); err != nil {
		t.Fatal(err)
	}
	s.Close()
	seen := map[string]int{}
	syncFailure := errors.New("directory sync failed")
	_, err := openWithSync(dir, binding(), func(path string) error {
		seen[path]++
		if path == dir {
			return syncFailure
		}
		return nil
	})
	if !errors.Is(err, syncFailure) || seen[dir] != 1 || seen[filepath.Dir(dir)] == 0 {
		t.Fatalf("reopen accepted unsynced reply: %v, sync calls: %v", err, seen)
	}
	reopened, err := Open(dir, binding())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.RecordReply(ctx, reply); err != nil {
		t.Fatalf("durable duplicate must be idempotent: %v", err)
	}
}

func TestMissingCorruptAndBindingMismatchFailClosed(t *testing.T) {
	for _, name := range []string{"missing key", "missing state", "corrupt key", "corrupt state", "tampered ciphertext", "permissions", "binding", "origin"} {
		t.Run(name, func(t *testing.T) {
			s, dir := openTest(t)
			o := reserveTest(t, s)
			b := binding()
			switch name {
			case "missing key":
				os.Remove(filepath.Join(dir, "key"))
			case "missing state":
				os.Remove(filepath.Join(dir, "state"))
			case "corrupt key":
				os.WriteFile(filepath.Join(dir, "key"), make([]byte, 32), 0600)
			case "corrupt state":
				os.WriteFile(filepath.Join(dir, "state"), []byte("broken"), 0600)
			case "tampered ciphertext":
				path := filepath.Join(dir, "state")
				raw, _ := os.ReadFile(path)
				raw[len(raw)-1] ^= 1
				os.WriteFile(path, raw, 0600)
			case "permissions":
				os.Chmod(filepath.Join(dir, "state"), 0644)
			case "binding":
				b.PrincipalID = recipient
			case "origin":
				b.ServiceOrigin = "https://other.example.com"
			}
			if _, err := Open(dir, b); err == nil {
				t.Fatal("reopen silently accepted damaged or mismatched store")
			}
			if name != "binding" && name != "origin" {
				if _, err := s.Get(ctx, project, o.AskID); err == nil {
					t.Fatal("open handle ignored damaged state")
				}
			}
		})
	}
}

func TestAuthenticatedStateStillRequiresValidTransitions(t *testing.T) {
	s, dir := openTest(t)
	o := reserveTest(t, s)
	stored := s.state.Operations[operationKey(project, o.AskID)]
	stored.Operation.Phase = Admitted // A receipt is required even in authenticated state.
	s.state.Operations[operationKey(project, o.AskID)] = stored
	if err := s.persist(s.state); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, binding()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted invalid authenticated state: %v", err)
	}
}

func TestSymlinksRefused(t *testing.T) {
	t.Run("ancestor", func(t *testing.T) {
		root := canonicalTempDir(t)
		real := filepath.Join(root, "real")
		os.Mkdir(real, 0700)
		link := filepath.Join(root, "link")
		os.Symlink(real, link)
		if _, err := Open(filepath.Join(link, "sender"), binding()); err == nil {
			t.Fatal("accepted symlink ancestor")
		}
	})
	for _, name := range []string{"key", "state"} {
		t.Run(name, func(t *testing.T) {
			s, dir := openTest(t)
			reserveTest(t, s)
			path := filepath.Join(dir, name)
			target := filepath.Join(canonicalTempDir(t), name)
			os.Rename(path, target)
			os.Symlink(target, path)
			if _, err := Open(dir, binding()); err == nil {
				t.Fatal("accepted symlink file")
			}
		})
	}
}

func TestPromptAndIdentityLimits(t *testing.T) {
	s, _ := openTest(t)
	for _, prompt := range []string{"", " \n", string([]byte{0xff}), strings.Repeat("🦊", MaxPromptChars+1)} {
		if _, err := s.Reserve(ctx, project, recipient, prompt); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid prompt accepted: %v", err)
		}
	}
	if _, err := s.Reserve(ctx, "../project", recipient, "prompt"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := s.Reserve(ctx, project, "not-a-uuid", "prompt"); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := s.Reserve(ctx, project, recipient, strings.Repeat("🦊", MaxPromptChars)); err != nil {
		t.Fatal(err)
	}
	all, err := s.List(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("invalid reservations persisted: %v", err)
	}
}

func TestCanceledOperationDoesNotReserve(t *testing.T) {
	s, _ := openTest(t)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Reserve(canceled, project, recipient, "prompt"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	all, _ := s.List(ctx)
	if len(all) != 0 {
		t.Fatal("canceled reservation persisted")
	}
}
