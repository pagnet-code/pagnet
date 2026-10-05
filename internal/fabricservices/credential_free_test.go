package fabricservices

import (
	"context"
	"testing"
)

func TestCredentialFreeExplicitSelectorIgnoresEnvironment(t *testing.T) {
	t.Setenv("MCP_TOKEN", "ambient-secret")
	t.Setenv("OPENAI_API_KEY", "ambient-secret")
	p := CredentialFreeProvider{}
	c, e := p.Resolve(t.Context(), "none")
	if e != nil || len(c.MCP.Headers) != 0 || c.BindingDigest == [32]byte{} || c.BindingDigest != CredentialFreeAccountDigest() {
		t.Fatal(c, e)
	}
	if _, e = p.Resolve(t.Context(), "private"); e == nil {
		t.Fatal("unknown selector accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = p.Resolve(ctx, "none"); e == nil {
		t.Fatal("cancelled credential resolution")
	}
}
