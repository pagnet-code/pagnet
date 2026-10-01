package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/runtimeprofile"
	"github.com/pagnet-code/pagnet/transport"
	"github.com/spf13/cobra"
)

func runtimeProfilesCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{Use: "runtime-profile", Short: "Configure named host-local runtime executables and environments"}
	cmd.PersistentFlags().StringVar(&dir, "state-dir", "", "daemon state dir (default ~/.pagnet)")
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, Short: "List profile names and local availability, without environment values", RunE: func(cmd *cobra.Command, _ []string) error {
		file, err := runtimeprofile.Load(filepath.Join(machineStateDir(dir), runtimeprofile.Filename))
		if err != nil {
			return err
		}
		rows := make([]transport.RuntimeProfileInstallation, 0, len(file.Profiles))
		for _, p := range file.Profiles {
			_, available := p.ResolvedExecutable()
			rows = append(rows, transport.RuntimeProfileInstallation{Name: p.Name, Runtime: string(p.Runtime), Available: available})
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(rows)
	}}
	var runtime, executable string
	var env, args, nativeDirs []string
	add := &cobra.Command{Use: "add NAME", Args: cobra.ExactArgs(1), Short: "Add a profile; reload the daemon before launching with it", RunE: func(cmd *cobra.Command, names []string) error {
		path := filepath.Join(machineStateDir(dir), runtimeprofile.Filename)
		file, err := runtimeprofile.Load(path)
		if err != nil {
			return err
		}
		for _, p := range file.Profiles {
			if p.Name == names[0] {
				return fmt.Errorf("profile %q already exists; changing an existing profile requires a fresh agent instance", names[0])
			}
		}
		p := runtimeprofile.Profile{Name: names[0], Runtime: domain.CanonicalRuntime(runtime), Executable: executable, Args: args, NativeDirs: nativeDirs, Env: map[string]string{}}
		for _, pair := range env {
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				return fmt.Errorf("--env requires KEY=VALUE")
			}
			if _, duplicate := p.Env[key]; duplicate {
				return fmt.Errorf("duplicate environment key")
			}
			p.Env[key] = value
		}
		file.Profiles = append(file.Profiles, p)
		if err := runtimeprofile.Save(path, file); err != nil {
			return err
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Added runtime profile %s. Reload your Pagnet daemon to publish and use it.\n", p.Name)
		return err
	}}
	add.Flags().StringVar(&runtime, "runtime", "", "base runtime: claude-code, qwen-code, codex, opencode")
	add.Flags().StringVar(&executable, "executable", "", "absolute native CLI or compatible wrapper path (default: native CLI from PATH)")
	add.Flags().StringArrayVar(&env, "env", nil, "host-local non-secret KEY=VALUE (repeatable; keep secrets in the private JSON file)")
	add.Flags().StringArrayVar(&args, "arg", nil, "structured argument before native managed-mode arguments (repeatable, no shell evaluation)")
	add.Flags().StringArrayVar(&nativeDirs, "native-dir", nil, "explicit native state directory for the runtime sandbox (repeatable)")
	_ = add.MarkFlagRequired("runtime")
	cmd.AddCommand(list, add)
	return cmd
}
