package continuation

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestPrivateOutboxRotationAtomicAndNoPublicCapability(t *testing.T) {
	s, _, v, c, h, expiry := fixture(t)
	issued := issue(t, s, c, v, expiry)
	delivery, e := s.PrivateNotification(ctx, h, issued.ID)
	if e != nil || delivery.Revision != 1 || delivery.Capability().Token() != issued.Capability.Token() {
		t.Fatal("created capability lacked durable private delivery", e)
	}
	if _, e = json.Marshal(delivery); e == nil {
		t.Fatal("private delivery serialized")
	}
	if _, e = s.PrivateNotification(ctx, c, issued.ID); e == nil {
		t.Fatal("original agent read other recipient's capability")
	}
	if e = s.AcknowledgePrivateNotification(ctx, h, issued.Capability.Token(), 1); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("CREATE TRIGGER fail_notify BEFORE UPDATE ON private_notifications BEGIN SELECT RAISE(ABORT,'notification failure'); END"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RotatePendingCapability(ctx, h, issued.ID, 1); e == nil {
		t.Fatal("failed outbox rotation accepted")
	}
	intact, e := s.PrivateNotification(ctx, h, issued.ID)
	if e != nil || intact.Revision != 1 || intact.Capability().Token() != issued.Capability.Token() || !intact.Published {
		t.Fatal("outbox failure leaked new capability revision", e)
	}
	if _, e = s.db.Exec("DROP TRIGGER fail_notify"); e != nil {
		t.Fatal(e)
	}
	rotated, e := s.RotatePendingCapability(ctx, h, issued.ID, 1)
	if e != nil {
		t.Fatal(e)
	}
	current, e := s.PrivateNotification(ctx, h, issued.ID)
	if e != nil || current.Revision != 2 || current.Published || current.Capability().Token() != rotated.Capability.Token() {
		t.Fatal("rotation did not publish exact new private notification", e)
	}
	if e = s.AcknowledgePrivateNotification(ctx, h, issued.Capability.Token(), 1); e == nil {
		t.Fatal("old external publication acknowledged new revision")
	}
	if _, e = s.Claim(ctx, h, issued.Capability.Token(), ident("stale")); e == nil {
		t.Fatal("old private notification resumed work")
	}
	claim, e := s.Claim(ctx, h, current.Capability().Token(), ident("current"))
	if e != nil || !claim.Fresh {
		t.Fatal(e)
	}
	if _, e = s.PrivateNotification(ctx, h, issued.ID); e == nil {
		t.Fatal("claimed work reissued secret")
	}
}
func TestPrivateOutboxCrashBeforeExternalPublication(t *testing.T) {
	if os.Getenv("PAGNET_TEST_NOTIFY_CRASH") == "1" {
		s, e := Open(ctx, os.Getenv("PAGNET_TEST_NOTIFY_DIR"), Scope{"test:audience"}, DefaultOptions(), testProtector(t))
		if e != nil {
			os.Exit(41)
		}
		h := auth(t, human, "test:audience", []byte("private recipient"))
		if _, e = s.RotatePendingCapability(ctx, h, os.Getenv("PAGNET_TEST_NOTIFY_ID"), 1); e != nil {
			os.Exit(42)
		}
		// FULL capability+notification commit happened; external publication did not.
		os.Exit(0)
	}
	s, dir, v, c, h, expiry := fixture(t)
	issued := issue(t, s, c, v, expiry)
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPrivateOutboxCrashBeforeExternalPublication$")
	command.Env = append(os.Environ(), "PAGNET_TEST_NOTIFY_CRASH=1", "PAGNET_TEST_NOTIFY_DIR="+dir, "PAGNET_TEST_NOTIFY_ID="+issued.ID)
	if _, e := command.CombinedOutput(); e != nil {
		t.Fatal("actual child crashed before durable rotation", e)
	}
	reopened, e := Open(ctx, dir, Scope{"test:audience"}, DefaultOptions(), testProtector(t))
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	delivery, e := reopened.PrivateNotification(ctx, h, issued.ID)
	if e != nil || delivery.Revision != 2 || delivery.Published {
		t.Fatal("publication loss stranded committed private capability", e)
	}
	if _, e = reopened.Claim(ctx, h, issued.Capability.Token(), ident("old")); e == nil {
		t.Fatal("old publication retained authority after crash")
	}
	claim, e := reopened.Claim(ctx, h, delivery.Capability().Token(), ident("recovered"))
	if e != nil || !claim.Fresh {
		t.Fatal("actual retained notification could not be claimed", e)
	}
}
