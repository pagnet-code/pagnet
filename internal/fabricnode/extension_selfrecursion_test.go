package fabricnode

import (
	"reflect"
	"testing"

	"github.com/pagnet-code/pagnet/fabric"
)

func TestExtensionExecutingAssociationRequiresUnambiguousClaim(t *testing.T) {
	association := extensionExecutingAssociation(map[string]map[string]struct{}{
		"spiffe://local/extension/one":   {"acme.security": {}},
		"spiffe://local/extension/two":   {"acme.security": {}, "other.audit": {}},
		"spiffe://local/extension/three": {"other.audit": {}},
	})
	if !reflect.DeepEqual(association, map[string]string{
		"spiffe://local/extension/one":   "acme.security",
		"spiffe://local/extension/three": "other.audit",
	}) {
		t.Fatal(association)
	}
	if got := extensionExecutingAssociation(nil); got != nil {
		t.Fatal("no claims must mint no association", got)
	}
	if got := extensionExecutingAssociation(map[string]map[string]struct{}{"spiffe://local/extension/two": {"acme.security": {}, "other.audit": {}}}); got != nil {
		t.Fatal("an ambiguous claim must mint no association", got)
	}
}
func TestBundleExecutingExtensionsIsVerifiedCallerOnly(t *testing.T) {
	caller, err := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "spiffe://local/extension/one", Kind: "service.mcp", Issuer: "local"}, "local:domain", []byte(`{"original":true}`))
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := fabric.NewAuthenticatedContext(fabric.Principal{Ref: "spiffe://local/foreign", Kind: "actor.agent", Issuer: "local"}, "local:domain", []byte(`{"original":true}`))
	if err != nil {
		t.Fatal(err)
	}
	bundle := &extensionRuntimeBundle{executing: map[string]string{"spiffe://local/extension/one": "acme.security"}}
	if got := bundle.executingExtensions(caller); !reflect.DeepEqual(got, []string{"acme.security"}) {
		t.Fatal(got)
	}
	// A caller without a node-verified association yields no evidence: every
	// matching interceptor still executes.
	if got := bundle.executingExtensions(unknown); got != nil {
		t.Fatal(got)
	}
	if got := (&extensionRuntimeBundle{}).executingExtensions(caller); got != nil {
		t.Fatal("a bundle without an association must mint no evidence", got)
	}
}
