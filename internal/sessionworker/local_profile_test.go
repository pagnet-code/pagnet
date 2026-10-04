package sessionworker

import (
	"github.com/pagnet-code/pagnet/domain"
	"testing"
)

func TestLocalProfileCredentialRotationCannotChangeExecutableProfile(t *testing.T) {
	base := NativeSpec{Kind: "local", Runtime: domain.RuntimeFakePersistent, Binary: "/operator/bin/runtime", MCPExecutable: "/operator/bin/pagnet", Env: []string{"PATH=/operator/bin:/usr/bin", "HOME=/operator/home", "XDG_CONFIG_HOME=/operator/profile", "OPENAI_BASE_URL=https://provider.example"}}
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
		if _, e := mergeLocalRuntimeEnvironment(base.Env, []string{override}); e == nil {
			t.Fatal("unbound inherited override accepted", override)
		}
	}
	merged, e := mergeLocalRuntimeEnvironment(base.Env, []string{"PATH=/operator/bin:/usr/bin", "OPENAI_API_KEY=rotated-private-key"})
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
	if _, e = mergeLocalRuntimeEnvironment(base.Env, []string{"NODE_OPTIONS=--require=/foreign.js"}); e == nil {
		t.Fatal("unbound interpreter injection accepted")
	}
}
