package runtime

import (
	"errors"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/session"
)

// Grok uses xAI's documented native ACP endpoint, not an API model masquerading
// as a CLI. Its machine endpoint has no second native TUI attachment.
func NewGrok(binary string) *ACPDriver {
	return &ACPDriver{Binary: binary, BinaryName: "grok", Runtime: domain.RuntimeGrok, NativeHomeEnv: "GROK_HOME", Arguments: func(s *session.RuntimeSession) []string {
		args := []string{"--no-auto-update"}
		if s.Model != "" {
			args = append(args, "--model", s.Model)
		}
		if s.StandingInstructions != "" {
			args = append(args, "--rules", s.StandingInstructions)
		}
		return append(args, "agent", "stdio")
	}, Authenticate: func(methods []string, env []string) (string, error) {
		apiKey := ""
		for _, entry := range env {
			if value, ok := strings.CutPrefix(entry, "XAI_API_KEY="); ok {
				apiKey = value
			}
		}
		if apiKey != "" {
			for _, method := range methods {
				if method == "xai.api_key" {
					return method, nil
				}
			}
		}
		for _, method := range methods {
			if method == "cached_token" {
				return method, nil
			}
		}
		if len(methods) == 0 {
			return "", nil
		}
		return "", errors.New("Grok authentication unavailable: provide XAI_API_KEY in the runtime profile or run grok login with that profile's GROK_HOME")
	}}
}
