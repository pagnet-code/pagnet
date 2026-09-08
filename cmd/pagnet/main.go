// Command pagnet is the user CLI: login, run (local + remote launch),
// network, workspaces, list, status, send, delegate, task, artifact,
// attach, chat. Command surface per spec §55 + the local/remote launch
// addendum.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var serverURL string

// userToken is the user/admin bearer token for REST calls (--token or
// $PAGNET_TOKEN); when both are empty the token stored by `pagnet login`
// applies. Host credentials from `pagnet enroll` authenticate the daemon
// over WSS only — the REST API is user-scoped and rejects host identities
// (403 host_identity).
var userToken string

// root is package-level so shared plumbing (newCLI) can check whether the
// user explicitly set --server (flag.Changed) before applying the saved
// config's server URL.
var root *cobra.Command

func main() {
	root = &cobra.Command{
		Use:           "pagnet",
		Short:         "pagnet CLI — control plane for AI coding agent networks",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:18080", "control plane URL")
	root.PersistentFlags().StringVar(&userToken, "token", os.Getenv("PAGNET_TOKEN"), "user/admin bearer token for REST calls (falls back to `pagnet login`)")

	root.AddCommand(
		loginCmd(),
		enrollCmd(),
		workerCmd(),
		runCmd(),
		networkCmd(),
		workspacesCmd(),
		listCmd(),
		statusCmd(),
		sendCmd(),
		delegateCmd(),
		taskCmd(),
		artifactCmd(),
		attachCmd(),
		chatCmd(),
		demoCmd(),
		// spec §55 command surface
		agentsCmd(),
		hostsCmd(),
		networksCmd(),
		tasksCmd(),
		inboxCmd(),
		stopCmd(),
		restartCmd(),
		openCmd(),
		initCmd(),
		doctorCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// enrollCmd implements `pagnet enroll` (formerly `pagnet login`): consumes
// a one-time enrollment token against the control plane and stores the host
// credential + identity in the daemon state dir (config.yaml, mode 0600).
// User sign-in lives in `pagnet login`.
func enrollCmd() *cobra.Command {
	var token, name, stateDir string
	var roots []string
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Connect this host: consume an enrollment token, store the credential",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if stateDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				stateDir = filepath.Join(home, ".pagnet")
			}
			if err := doEnroll(serverURL, token, name, roots, stateDir); err != nil {
				return err
			}
			fmt.Println("run `pagnetd` to connect this host")
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "one-time enrollment token (required)")
	cmd.Flags().StringVar(&name, "name", "", "host name (default: machine hostname)")
	cmd.Flags().StringArrayVar(&roots, "roots", nil, "allowed workspace root (repeatable; server-side token roots win)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "daemon state dir (default ~/.pagnet)")
	return cmd
}

// doEnroll consumes a one-time enrollment token against the control plane
// and stores the host credential + identity in stateDir (config.yaml,
// mode 0600). Shared by `pagnet enroll` and `pagnet worker` (first run).
func doEnroll(server, token, name string, roots []string, stateDir string) error {
	if token == "" {
		return errors.New("--token is required (create one in the web UI: Hosts → Add a worker)")
	}
	if name == "" {
		name, _ = os.Hostname()
		if name == "" {
			name = "pagnet-host"
		}
	}

	var resp struct {
		Host struct {
			ID string `json:"ID"`
		} `json:"host"`
		Credential   string   `json:"credential"`
		AllowedRoots []string `json:"allowedRoots"`
	}
	if err := apiPostJSON(server+"/api/v1/hosts/enroll", map[string]any{
		"token":         token,
		"hostName":      name,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"daemonVersion": "pagnet-cli/dev",
	}, &resp); err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	if resp.Host.ID == "" || resp.Credential == "" {
		return errors.New("enroll: server response missing host id or credential")
	}
	savedRoots := resp.AllowedRoots
	if len(savedRoots) == 0 {
		savedRoots = roots
	}

	if err := mergeConfigFile(stateDir, map[string]any{
		"serverUrl":    strings.TrimSuffix(server, "/"),
		"credential":   resp.Credential,
		"hostId":       resp.Host.ID,
		"hostName":     name,
		"allowedRoots": savedRoots,
	}); err != nil {
		return err
	}
	fmt.Printf("host %s registered (%s)\n", name, resp.Host.ID)
	fmt.Printf("credential stored in %s (mode 0600)\n", filepath.Join(stateDir, "config.yaml"))
	if len(savedRoots) > 0 {
		fmt.Printf("allowed roots: %v\n", savedRoots)
	}
	return nil
}

// apiPostJSON posts a JSON body and decodes the response into out.
func apiPostJSON(url string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(raw))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}
