package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// OpenCode's documented ACP entrypoint owns a private server until stdin closes.
// It never attaches to a shared service or launches a replacement TUI. See
// https://opencode.ai/v2/docs/cli/acp/ and https://dev.opencode.ai/docs/acp/.
func NewOpenCodePersistent(binary string) *ACPDriver {
	return &ACPDriver{PlanSource: "opencode", Binary: binary, BinaryName: "opencode", Runtime: domain.RuntimeOpenCode, NativeHomeEnv: "XDG_DATA_HOME",
		Arguments: func(*session.RuntimeSession) []string { return []string{"acp"} },
		PrepareLaunch: func(s *session.RuntimeSession, env []string, state string) ([]string, error) {
			home := ""
			for _, kv := range env {
				if value, ok := strings.CutPrefix(kv, "XDG_DATA_HOME="); ok {
					home = value
				}
			}
			for _, path := range []string{filepath.Join(home, "config"), filepath.Join(home, "cache")} {
				if err := os.MkdirAll(path, 0700); err != nil {
					return nil, err
				}
			}
			config, err := writeOpenCodeConfig(state, "", s.StandingInstructions)
			if err != nil {
				return nil, err
			}
			cfg := map[string]any{}
			if config != "" {
				raw, err := os.ReadFile(config)
				if err != nil {
					return nil, err
				}
				if err = json.Unmarshal(raw, &cfg); err != nil {
					return nil, err
				}
			}
			if s.Model != "" {
				cfg["model"] = s.Model
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				return nil, err
			}
			config = filepath.Join(state, "opencode.json")
			if err = AtomicWriteFile(config, raw, 0600); err != nil {
				return nil, err
			}
			return ChildEnv(env, []string{"XDG_CONFIG_HOME=" + filepath.Join(home, "config"), "XDG_CACHE_HOME=" + filepath.Join(home, "cache"), "OPENCODE_CONFIG=" + config}), nil
		},
	}
}
