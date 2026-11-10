package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/internal/sessionworker"
	"github.com/pagnet-code/pagnet/transport"
)

func TestNativeWorkerAccountPersistence(t *testing.T) {
	raw, err := os.ReadFile("../../transport/testdata/account_message_source_reply_html_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ SourceCanonical string }
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	var source transport.NativeAccountMessageSource
	if err = json.Unmarshal([]byte(fixture.SourceCanonical), &source); err != nil {
		t.Fatal(err)
	}
	proof := transport.NativeDispatchProof{AccountMessageSource: &source}
	deletion := transport.NativeOwnershipDeletionProof{StopProof: proof}
	ownership := transport.NativeWorkerOwnership{DeletionProof: &deletion}
	for _, record := range []any{NativeWorkerRecord{Ownership: &ownership}, nativeWorkerGC{Ownership: ownership, DeletionProof: &deletion}, ownership} {
		encoded, err := marshalNativeWorkerRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		target := reflect.New(reflect.TypeOf(record)).Interface()
		if err = json.Unmarshal(encoded, target); err != nil {
			t.Fatal("daemon record cannot recover", err)
		}
		if !bytes.Contains(encoded, []byte("<>&")) {
			t.Fatal("daemon record escaped account source")
		}
	}
	// Proxy operation and its private request remain canonical across both layers.
	operation := sessionworker.Operation{SourceAccountMessage: &source, InputKind: "account_message"}
	payload, err := sessionworker.MarshalNativeJSON(operation)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := sessionworker.MarshalNativeJSON(sessionworker.Request{Type: "dispatch", Payload: payload, NativeDispatch: &proof})
	if err != nil {
		t.Fatal(err)
	}
	var request sessionworker.Request
	if err = json.Unmarshal(frame, &request); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(request.Payload, &operation); err != nil {
		t.Fatal("proxy payload lost source", err)
	}
}

func TestNativeWorkerLegacyPersistenceBytes(t *testing.T) {
	ownership := transport.NativeWorkerOwnership{ID: "legacy <>&"}
	for _, record := range []any{NativeWorkerRecord{Ownership: &ownership}, nativeWorkerGC{Ownership: ownership}, ownership} {
		expected, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := marshalNativeWorkerRecord(record)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("legacy daemon bytes changed", err)
		}
	}
}
