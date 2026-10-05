package fabricnode

import (
	"context"
	"testing"
)

type extensionCredentialProbe struct{ calls int }

func (p *extensionCredentialProbe) Authorization(context.Context, string) (string, error) {
	p.calls++
	return "Bearer private", nil
}

func TestExtensionCredentialSelectionNeverFallsBack(t *testing.T) {
	ctx := context.Background()
	probe := &extensionCredentialProbe{}
	for _, provider := range []extensionSelectedCredential{
		{binding: "exact", selector: "credentials.none"},
		{provider: probe, binding: "exact", selector: "credentials.none"},
	} {
		value, err := provider.Authorization(ctx, "exact")
		if err != nil || value != "" {
			t.Fatalf("explicit credential-free profile: %q %v", value, err)
		}
		if _, err := provider.Authorization(ctx, "other"); err == nil {
			t.Fatal("credential selector escaped its exact binding")
		}
	}
	if probe.calls != 0 {
		t.Fatal("credential-free profile consulted a secret provider")
	}
	missing := extensionSelectedCredential{binding: "exact", selector: "credentials.private"}
	if _, err := missing.Authorization(ctx, "exact"); err == nil {
		t.Fatal("missing named provider silently became anonymous")
	}
	selected := extensionSelectedCredential{provider: probe, binding: "exact", selector: "credentials.private"}
	value, err := selected.Authorization(ctx, "exact")
	if err != nil || value != "Bearer private" || probe.calls != 1 {
		t.Fatal("explicit named provider not selected")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = selected.Authorization(canceled, "exact"); err == nil || probe.calls != 1 {
		t.Fatal("revoked request consulted private credentials")
	}
}
