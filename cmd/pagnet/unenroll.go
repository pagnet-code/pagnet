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
			if err := clearHostState(c.stateDir); err != nil {
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
// file, keeping everything else (the user login token, the server URL).
func clearHostState(stateDir string) error {
	path := filepath.Join(stateDir, "config.yaml")
	var fc map[string]any
	if b, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(b, &fc); err != nil {
			return fmt.Errorf("existing %s is not a mapping: %w", path, err)
		}
	}
	if fc == nil {
		return nil // nothing to clear
	}
	delete(fc, "credential")
	delete(fc, "hostId")
	b, err := yaml.Marshal(fc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
