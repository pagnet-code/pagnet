package sessionworker

import (
	"github.com/pagnet-code/pagnet/domain"
	"testing"
)

func TestLocalProfileCredentialRotationCannotChangeExecutableProfile(t *testing.T) {
	base := NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: "/operator/bin/runtime", MCPExecutable: "/operator/bin/pagnet", CredentialEnvKeys: []string{"OPENAI_API_KEY"}, Env: []string{"PATH=/operator/bin:/usr/bin", "HOME=/operator/home", "XDG_CONFIG_HOME=/operator/profile", "OPENAI_BASE_URL=https://provider.example"}}
	original := LocalNativeProfileFingerprint(base)
	credential := base
	credential.Env = append(append([]string(nil), base.Env...), "OPENAI_API_KEY=original-private-key")
	if validateLocalEnvironment(credential, false) != nil || LocalNativeProfileFingerprint(credential) != original {
		t.Fatal("operational credential changed physical binding")
	}
	rotated := base
	rotated.Env = append(append([]string(nil), base.Env...), "OPENAI_API_KEY=rotated-private-key")
	if LocalNativeProfileFingerprint(rotated) != original {
		t.Fatal("credential rotation changed binding")
	}
	if validateLocalEnvironment(rotated, true) == nil {
		t.Fatal("provider credential persisted in bootstrap")
	}
	for _, override := range []string{"PATH=/foreign/bin", "HOME=/foreign", "XDG_CONFIG_HOME=/foreign", "OPENAI_BASE_URL=https://foreign.example"} {
		changed := base
		changed.Env = append([]string{override}, base.Env[1:]...)
		if LocalNativeProfileFingerprint(changed) == original {
			t.Fatal("executable/profile override omitted", override)
		}
		if _, e := mergeLocalRuntimeEnvironment(base, []string{override}); e == nil {
			t.Fatal("unbound inherited override accepted", override)
		}
	}
	merged, e := mergeLocalRuntimeEnvironment(base, []string{"PATH=/operator/bin:/usr/bin", "OPENAI_API_KEY=rotated-private-key"})
	if e != nil {
		t.Fatal(e)
	}
	copy := base
	copy.Env = merged
	if LocalNativeProfileFingerprint(copy) != original {
		t.Fatal("trusted inherited credential changed profile")
	}
	relative := base
	relative.Binary = "runtime"
	if validateLocalEnvironment(relative, false) == nil {
		t.Fatal("unbound PATH binary selection accepted")
	}
	if _, e = mergeLocalRuntimeEnvironment(base, []string{"NODE_OPTIONS=--require=/foreign.js"}); e == nil {
		t.Fatal("unbound interpreter injection accepted")
	}
}

func TestLocalCustomCredentialSlotsStayPrivateAndCannotReplaceSelectors(t *testing.T) {
	base := NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: "/operator/bin/custom", MCPExecutable: "/operator/bin/pagnet", CredentialEnvKeys: []string{"ACME_SESSION_CREDENTIAL", "OTHER_SERVICE_TOKEN"}, Env: []string{"PATH=/operator/bin:/usr/bin", "HOME=/operator/home"}}
	digest := LocalNativeProfileFingerprint(base)
	merged, e := mergeLocalRuntimeEnvironment(base, []string{"ACME_SESSION_CREDENTIAL=original-secret"})
	if e != nil {
		t.Fatal(e)
	}
	private := base
	private.Env = merged
	if LocalNativeProfileFingerprint(private) != digest || validateLocalEnvironment(private, true) == nil {
		t.Fatal("custom credential changed profile or persisted its value")
	}
	rotated, e := mergeLocalRuntimeEnvironment(base, []string{"ACME_SESSION_CREDENTIAL=rotated-secret"})
	if e != nil {
		t.Fatal(e)
	}
	private.Env = rotated
	if LocalNativeProfileFingerprint(private) != digest {
		t.Fatal("custom credential rotation changed physical binding")
	}
	if _, e = mergeLocalRuntimeEnvironment(base, []string{"OPENAI_API_KEY=undeclared-secret"}); e == nil {
		t.Fatal("undeclared provider bypassed explicit credential slots")
	}
	reordered := base
	reordered.CredentialEnvKeys = []string{"OTHER_SERVICE_TOKEN", "ACME_SESSION_CREDENTIAL"}
	if LocalNativeProfileFingerprint(reordered) != digest {
		t.Fatal("equivalent declared slot order changed profile")
	}
	for _, name := range []string{"PATH", "HOME", "XDG_CONFIG_HOME", "LD_PRELOAD", "NODE_OPTIONS", "OPENAI_BASE_URL", "PAGNET_TOKEN", "DATABASE_URL", "ACME_SESSION_CREDENTIAL=secret", "9INVALID"} {
		changed := base
		changed.CredentialEnvKeys = []string{name}
		if validateLocalEnvironment(changed, true) == nil {
			t.Fatal("credential slot replaced executable/profile settings", name)
		}
	}
	duplicate := base
	duplicate.CredentialEnvKeys = append(append([]string(nil), base.CredentialEnvKeys...), "ACME_SESSION_CREDENTIAL")
	if validateLocalEnvironment(duplicate, true) == nil {
		t.Fatal("duplicate credential slots accepted")
	}
}

func TestLocalInputBindingProfileIsPartOfPhysicalFingerprint(t *testing.T) {
	base := NativeSpec{Kind: "local"}
	prompt := base
	prompt.InputBindingProfile = "pagnet.native.input.prompt.v1"
	if LocalNativeProfileFingerprint(base) != LocalNativeProfileFingerprint(prompt) {
		t.Fatal("default local prompt profile is not canonical")
	}
	structured := base
	structured.InputBindingProfile = "pagnet.native.input.json.v1"
	if LocalNativeProfileFingerprint(base) == LocalNativeProfileFingerprint(structured) {
		t.Fatal("structured input format is not bound to actual worker profile")
	}
}
