package main

// `pagnet unenroll` — remove THIS host from the control plane and clear
// the local host state (the inverse of `pagnet enroll`).
//
// What happens:
//  1. The control plane stops the agents running on this host and deletes
//     the host (credential, roots, workspaces, instances).
//  2. A daemon/worker running on this machine receives host.unenrolled
//     and stops itself with a message (one that was down will 401 on its
//     next dial and stop the same way).
//  3. The local credential + identity are cleared; the user login token
//     and the server URL are kept.
//
// The machine can join again later with a new enrollment token.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func unenrollCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "unenroll",
		Short: "Remove this host from the control plane and clear local state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newCLI(stateDir)
			if err != nil {
				return err
			}
			if c.cfg.Credential == "" || c.cfg.HostID == "" {
				return errors.New("no pagnet host config found; this machine is not enrolled (nothing to unenroll)")
			}
			hostGone := false
			if h, err := c.hostDetail(c.cfg.HostID); err != nil {
				hostGone = true
				fmt.Fprintln(os.Stderr, "note: this host no longer exists on the control plane; clearing local state only")
			} else {
				fmt.Printf("removing host %s from the control plane (running agents are stopped)...\n", h.Name)
			}
			if !hostGone {
				if err := c.del("/api/v1/hosts/" + c.cfg.HostID); err != nil {
					return fmt.Errorf("unenroll: %w", err)
				}
			}
			if err := clearHostState(c.stateDir, c.account); err != nil {
				return err
			}
			fmt.Println("done. local credential + identity cleared (user login kept)")
			fmt.Println("a daemon/worker running on this machine stops itself with a message")
			fmt.Println("to join again: create a new enrollment token and run `pagnet enroll`")
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "daemon state dir to clear (default ~/.pagnet; auto-detected inside a worker directory)")
	return cmd
}

// clearHostState removes the host credential + identity from the state
// files the enrollment wrote, keeping everything else (the user login
// token, the server URL, the current network). The account model stores
// the identity in the ACTIVE ACCOUNT's config; the machine-wide flat
// config.yaml is swept too when it still carries identity (an orphaned
// pre-accounts file). A worker dir (account "") uses its flat config.
func clearHostState(root, account string) error {
	// accountConfigDir returns the account's directory (the state dir
	// itself for a worker); the config file lives inside it.
	paths := []string{filepath.Join(accountConfigDir(root, account), "config.yaml")}
	if account != "" {
		paths = append(paths, filepath.Join(root, "config.yaml"))
	}
	for _, path := range paths {
		if err := clearHostFields(path); err != nil {
			return err
		}
	}
	return nil
}

// clearHostFields deletes the host identity keys from one config file,
// rewriting it only when something was present.
func clearHostFields(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var fc map[string]any
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return fmt.Errorf("existing %s is not a mapping: %w", path, err)
	}
	if fc == nil {
		return nil
	}
	changed := false
	for _, k := range []string{"credential", "hostId", "hostName", "allowedRoots", "rootsMode"} {
		if _, ok := fc[k]; ok {
			delete(fc, k)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	b, err = yaml.Marshal(fc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
