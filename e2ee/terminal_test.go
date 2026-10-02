package e2ee

import "testing"

func TestTerminalObjectBindingSeparatesSourceDirectionSnapshotAndSequence(t *testing.T) {
	instance := "11111111-1111-4111-8111-111111111111"
	session := "22222222-2222-4222-8222-222222222222"
	key := "33333333-3333-4333-8333-333333333333"
	live, err := TerminalFrameObjectID(instance, session, "original-source", key, "output", false, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want := "terminal-frame:v1:" + instance + ":" + session + ":original-source:" + key + ":output-live:4096"
	if live != want {
		t.Fatal("canonical terminal object binding changed")
	}
	snapshot, _ := TerminalFrameObjectID(instance, session, "original-source", key, "output", true, 4096)
	input, _ := TerminalFrameObjectID(instance, session, "original-source", key, "input", false, 4096)
	next, _ := TerminalFrameObjectID(instance, session, "original-source", key, "output", false, 4097)
	if live == snapshot || live == input || live == next {
		t.Fatal("terminal authorities alias")
	}
	for _, test := range []struct {
		gen, direction string
		snapshot       bool
		seq            uint64
	}{{"source:injected", "output", false, 1}, {"original-source", "input", true, 1}, {"original-source", "input", false, 0}, {"original-source", "unknown", false, 1}, {"original-source", "output", false, TerminalMaxSafeSequence + 1}} {
		if _, err := TerminalFrameObjectID(instance, session, test.gen, key, test.direction, test.snapshot, test.seq); err == nil {
			t.Fatal("invalid terminal authority accepted")
		}
	}
}
