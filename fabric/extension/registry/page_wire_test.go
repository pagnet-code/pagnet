package registry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPageWireExactGenerationAndPaginationNames(t *testing.T) {
	page := Page{Generation: 9007199254740993, Entries: []Reference{{ID: "operator.guard", Revision: 9007199254740995, Digest: "owned"}}, NextCursor: "exact opaque next"}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"generation":"9007199254740993"`) || !strings.Contains(string(encoded), `"entries":[`) || !strings.Contains(string(encoded), `"nextCursor":"exact opaque next"`) || strings.Contains(string(encoded), `"Generation"`) {
		t.Fatal(string(encoded))
	}
	var decoded Page
	if err = json.Unmarshal(encoded, &decoded); err != nil || decoded.Generation != page.Generation || decoded.NextCursor != page.NextCursor || len(decoded.Entries) != 1 || decoded.Entries[0] != page.Entries[0] {
		t.Fatal("lost exact paginated revision", err)
	}
	if err = json.Unmarshal([]byte(`{"generation":9007199254740993,"entries":[]}`), &decoded); err == nil {
		t.Fatal("unsafe numeric generation accepted")
	}
}
