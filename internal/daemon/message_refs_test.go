package daemon

import (
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pagnet-code/pagnet/transport"
)

func TestMessageReferencesPersistAndRemainOwnerScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	state, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	row := &InstanceRow{InstanceID: "instance-a", AgentPrincipalID: "principal-a"}
	d := &Daemon{state: state}
	input, err := d.compactDeliveryInput(row, transport.NetworkEventPayload{Kind: "ask", FromAgent: "atlas", ThreadID: "canonical-thread", MessageID: "canonical-message", Body: "hello <world>"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(input, "canonical-") || !strings.Contains(input, "thread#") {
		t.Fatalf("uncompacted prompt: %s", input)
	}
	var document struct {
		XMLName xml.Name `xml:"pagnet-delivery"`
	}
	if err := xml.Unmarshal([]byte(input), &document); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	reference, err := state.shortReference(referenceOwner(row), "thread", "canonical-thread")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.db.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	d.state = state
	// A replacement instance of the same principal keeps its history references.
	row.InstanceID = "instance-b"
	raw, _ := json.Marshal(map[string]string{"threadId": reference, "body": "answer"})
	resolved, msg := d.resolveToolReferences(row, "network_reply", raw)
	if msg != "" || !strings.Contains(string(resolved), "canonical-thread") {
		t.Fatalf("restart resolution: %s %s", resolved, msg)
	}
	foreign := &InstanceRow{InstanceID: "instance-c", AgentPrincipalID: "principal-b"}
	if _, msg := d.resolveToolReferences(foreign, "network_reply", raw); msg == "" {
		t.Fatal("foreign principal reference accepted")
	}
	// Existing UUID transcripts and free-form bodies retain their original meaning.
	old := json.RawMessage(`{"threadId":"legacy-uuid","body":"thread#123 is quoted data"}`)
	resolved, msg = d.resolveToolReferences(row, "network_reply", old)
	if msg != "" || !strings.Contains(string(resolved), "legacy-uuid") || !strings.Contains(string(resolved), "thread#123") {
		t.Fatalf("legacy/body rewritten: %s %s", resolved, msg)
	}
}

func TestMessageReferencesConcurrentDeliveryAndNoReplyLoop(t *testing.T) {
	state, err := OpenState(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.db.Close()
	var wg sync.WaitGroup
	refs := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref, err := state.shortReference("owner", "thread", "same-thread")
			if err != nil {
				t.Error(err)
				return
			}
			refs <- ref
		}()
	}
	wg.Wait()
	close(refs)
	first := ""
	for ref := range refs {
		if first == "" {
			first = ref
		}
		if ref != first {
			t.Fatalf("reference changed: %s != %s", ref, first)
		}
	}
	input := deliveryInput(&InstanceRow{}, transport.NetworkEventPayload{Kind: "reply", ThreadID: "thread#1", Body: "done"})
	var document struct {
		XMLName xml.Name `xml:"pagnet-delivery"`
	}
	if err := xml.Unmarshal([]byte(input), &document); err != nil {
		t.Fatalf("invalid reply XML: %v", err)
	}
	if strings.Contains(input, "Answer it, then") || !strings.Contains(input, "do not reply merely to acknowledge") {
		t.Fatalf("reply loop instruction: %s", input)
	}
}
