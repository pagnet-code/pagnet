package proc

import (
	"os"
	"os/exec"
	"strings"
)

// defaultPTYEnv advertises the terminal viewer's capabilities without forcing
// color. Explicit child values win, including empty values and NO_COLOR.
func defaultPTYEnv(cmd *exec.Cmd) {
	env := cmd.Environ()
	values := make(map[string]string, 3)
	for _, pair := range env {
		key, value, ok := strings.Cut(pair, "=")
		if ok {
			values[key] = value
		}
	}
	// Runtime environment filtering may have removed these inherited settings.
	// Restore only terminal capability/color preferences on PTY launches.
	for _, key := range []string{"TERM", "COLORTERM", "NO_COLOR"} {
		if _, present := values[key]; present {
			continue
		}
		if value, present := os.LookupEnv(key); present {
			env = append(env, key+"="+value)
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
