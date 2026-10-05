package sessionworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pagnet-code/pagnet/internal/nativeauthority"
	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
)

// Credential slots are explicit provider configuration, not a closed provider
// taxonomy or an inference from names. Executable/profile selectors stay bound.
func localProviderCredential(spec NativeSpec, key string) bool {
	for _, declared := range spec.CredentialEnvKeys {
		if key == declared {
			return true
		}
	}
	return false
}
func validCredentialSlot(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for i, c := range []byte(key) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	switch key {
	case "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "ENV", "BASH_ENV", "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONHOME", "RUBYOPT", "PERL5OPT", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH":
		return false
	}
	return !strings.HasPrefix(key, "PAGNET_") && !strings.HasPrefix(key, "XDG_") && !strings.HasPrefix(key, "LD_") && !strings.HasPrefix(key, "DYLD_") && !strings.HasSuffix(key, "_BASE_URL") && agentruntime.ValidateExtraEnv([]string{key + "="}) == nil
}
func LocalNativeProfileFingerprint(spec NativeSpec) string {
	copy := spec
	copy.InputBindingProfile = nativeauthority.EffectiveInputBindingProfile(spec.InputBindingProfile)
	copy.CredentialEnvKeys = append([]string(nil), spec.CredentialEnvKeys...)
	sort.Strings(copy.CredentialEnvKeys)
	copy.Env = nil
	for _, pair := range spec.Env {
		key, _, _ := strings.Cut(pair, "=")
		if !localProviderCredential(spec, key) {
			copy.Env = append(copy.Env, pair)
		}
	}
	raw, _ := json.Marshal(struct {
		Purpose            string
		Spec               NativeSpec
		ProfileEnvironment []string
	}{"pagnet.local-native-profile.v1", copy, copy.Env})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
func validateLocalEnvironment(spec NativeSpec, persisted bool) error {
	if _, err := nativeauthority.NewInputBinder(spec.InputBindingProfile, [32]byte{}); err != nil {
		return err
	}
	if !filepath.IsAbs(spec.Binary) || !filepath.IsAbs(spec.MCPExecutable) || agentruntime.ValidateExtraEnv(spec.Env) != nil {
		return errors.New("local native executable/profile environment invalid")
	}
	seen := map[string]bool{}
	if len(spec.CredentialEnvKeys) > 64 {
		return errors.New("local credential slot capacity exceeded")
	}
	for _, key := range spec.CredentialEnvKeys {
		if !validCredentialSlot(key) || seen[key] {
			return errors.New("local credential slot changes executable/profile selectors")
		}
		seen[key] = true
	}
	seen = map[string]bool{}
	for _, pair := range spec.Env {
		key, _, ok := strings.Cut(pair, "=")
		if !ok || key == "" || seen[key] || strings.ContainsRune(pair, 0) || (persisted && localProviderCredential(spec, key)) {
			return errors.New("local native environment duplicates or persists provider credentials")
		}
		seen[key] = true
	}
	return nil
}

// ValidateLocalRuntimeEnvironment checks the same environment boundary used by
// the real worker before a launcher commits its one-attempt spawn claim. It
// neither returns credential values nor changes the signed bootstrap profile.
func ValidateLocalRuntimeEnvironment(spec NativeSpec, inherited []string) error {
	_, err := mergeLocalRuntimeEnvironment(spec, inherited)
	return err
}

// The inherited memory-only pipe cannot replace executable/profile settings.
// Every noncredential pair must match a previously signed bootstrap pair.
func mergeLocalRuntimeEnvironment(spec NativeSpec, inherited []string) ([]string, error) {
	declared := spec.Env
	if validateLocalEnvironment(spec, true) != nil {
		return nil, errors.New("invalid persisted local runtime profile")
	}
	original := map[string]string{}
	for _, p := range declared {
		key, _, _ := strings.Cut(p, "=")
		original[key] = p
	}
	out := append([]string(nil), declared...)
	seen := map[string]bool{}
	for _, p := range inherited {
		key, _, ok := strings.Cut(p, "=")
		if !ok || key == "" || seen[key] || strings.ContainsRune(p, 0) {
			return nil, errors.New("invalid local inherited environment")
		}
		seen[key] = true
		if localProviderCredential(spec, key) {
			out = append(out, p)
			continue
		}
		if original[key] != p {
			return nil, errors.New("local inherited environment changes signed executable profile")
		}
	}
	return out, nil
}
