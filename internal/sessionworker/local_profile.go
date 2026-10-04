package sessionworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	agentruntime "github.com/pagnet-code/pagnet/internal/runtime"
)

// Only explicit provider credentials are operational memory, not executable
// profile identity. PATH/HOME/config directories/provider URLs and all other
// operator overrides stay in the signed profile. Cloud hashing is unchanged.
func localProviderCredential(key string) bool {
	switch key {
	case "ANTHROPIC_API_KEY", "DASHSCOPE_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY", "TOGETHER_API_KEY", "FIREWORKS_API_KEY", "PERPLEXITY_API_KEY", "DEEPSEEK_API_KEY":
		return true
	}
	return false
}
func LocalNativeProfileFingerprint(spec NativeSpec) string {
	copy := spec
	copy.Env = nil
	for _, pair := range spec.Env {
		key, _, _ := strings.Cut(pair, "=")
		if !localProviderCredential(key) {
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
	if !filepath.IsAbs(spec.Binary) || !filepath.IsAbs(spec.MCPExecutable) || agentruntime.ValidateExtraEnv(spec.Env) != nil {
		return errors.New("local native executable/profile environment invalid")
	}
	seen := map[string]bool{}
	for _, pair := range spec.Env {
		key, _, ok := strings.Cut(pair, "=")
		if !ok || key == "" || seen[key] || strings.ContainsRune(pair, 0) || (persisted && localProviderCredential(key)) {
			return errors.New("local native environment duplicates or persists provider credentials")
		}
		seen[key] = true
	}
	return nil
}

// The inherited memory-only pipe cannot replace executable/profile settings.
// Every noncredential pair must match a previously signed bootstrap pair.
func mergeLocalRuntimeEnvironment(declared, inherited []string) ([]string, error) {
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
		if localProviderCredential(key) {
			out = append(out, p)
			continue
		}
		if original[key] != p {
			return nil, errors.New("local inherited environment changes signed executable profile")
		}
	}
	return out, nil
}
