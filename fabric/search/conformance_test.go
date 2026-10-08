package search_test

import (
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/search"
	"github.com/pagnet-code/pagnet/fabric/search/conformance"
)

// TestSearchBackendConformance is the swappability gate for the reference
// lexical backend: every fresh search.Backend must pass the full
// fabric.SearchBackend conformance suite. A replacement backend runs the same
// gate by passing its factory to conformance.RunConformance.
func TestSearchBackendConformance(t *testing.T) {
	conformance.RunConformance(t, func() fabric.SearchBackend {
		b, err := search.New(search.Config{})
		if err != nil {
			t.Fatal(err)
		}
		return b
	})
}
