package proc

import (
	"os/exec"
	"strings"
)

// defaultPTYEnv advertises the terminal viewer's capabilities without forcing
// color. Explicit child values win, including empty values and NO_COLOR.
func defaultPTYEnv(cmd *exec.Cmd) {
	env := cmd.Environ()
	if cmd.Env == nil {
		// Implicit inheritance describes the daemon's terminal, not the viewer.
		childEnv := env[:0]
		for _, pair := range env {
			key, _, _ := strings.Cut(pair, "=")
			if key != "TERM" && key != "COLORTERM" && key != "NO_COLOR" {
				childEnv = append(childEnv, pair)
			}
		}
		env = childEnv
	}
	values := make(map[string]string, 3)
	for _, pair := range env {
		key, value, ok := strings.Cut(pair, "=")
		if ok {
			values[key] = value
		}
	}
	if _, present := values["TERM"]; !present {
		env = append(env, "TERM=xterm-256color")
		values["TERM"] = "xterm-256color"
	}
	if _, present := values["COLORTERM"]; !present && values["TERM"] != "" && values["TERM"] != "dumb" {
		env = append(env, "COLORTERM=truecolor")
	}
	cmd.Env = env
}
