package fabrichost

import (
	"bytes"
	"github.com/pagnet-code/pagnet/fabric"
	"testing"
)

func TestEnvironmentPartialManagedCredentialsNeverBecomeOwner(t *testing.T) {
	endpoint, _ := fabric.NewEndpointRef(bytes.Repeat([]byte{9}, 32))
	complete := map[string]string{EndpointEnvironment: endpoint.String(), WorkerEnvironment: "physical-worker", GenerationEnvironment: "native-generation", NonceEnvironment: "private-activation-nonce"}
	for omitted := range complete {
		incomplete := map[string]string{}
		for key, value := range complete {
			if key != omitted {
				incomplete[key] = value
			}
		}
		if _, err := FromEnvironment(func(key string) string { return incomplete[key] }); err == nil {
			t.Fatalf("missing %s granted owner", omitted)
		}
	}
	managed, err := FromEnvironment(func(key string) string { return complete[key] })
	if err != nil || managed.Mode != "managed" {
		t.Fatal("complete actual managed selection rejected", err)
	}
	owner, err := FromEnvironment(func(string) string { return "" })
	if err != nil || owner.Mode != "owner" {
		t.Fatal("explicit owner profile failed", err)
	}
}
func FuzzStrictAuthentication(f *testing.F) {
	for _, seed := range []string{`{"type":"fabric.auth","mode":"owner"}`, `{"type":"fabric.auth","Mode":"owner"}`, `{"type":"fabric.auth","mode":"owner","mode":"managed"}`, `{} {}`, "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16384 {
			return
		}
		auth, err := parseAuth([]byte(raw), 16384)
		if err == nil && auth.Validate() != nil {
			t.Fatal("invalid authentication accepted")
		}
	})
}
