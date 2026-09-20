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

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/accounts"
)

var serverURL string

// version is stamped at release-build time (-X main.version=$(VERSION));
// it rides on the enroll payload so the Hosts page shows a real build
// identity from the first heartbeat.
var version = "dev"

// defaultServerURL is the build-time default control plane (ldflags,
// -X main.defaultServerURL=...). The STANDARD PRODUCTION BUILD DEFAULT is
// https://app.pagnet.dev (stamped by the release build); development builds
// stamp a different default only when explicitly configured (empty = no
// default, the CLI requires --server / $PAGNET_SERVER / stored config). It
// is the LAST resort in the server URL precedence (after --server,
// $PAGNET_SERVER, and the stored account config).
var defaultServerURL = ""

// accountFlag is the --account global flag: an explicit account-context
// override for this invocation (scripts). Empty = the current account.
var accountFlag string

// silent is the --silent global flag: no banners/progress/success prose;
// errors still go to stderr and the exit status stays meaningful.
var silent bool

// nonInteractive is the --non-interactive global flag: never prompt, never
// open a browser, never wait for a human; fail immediately when required
// information is missing. It is distinct from --silent (which only quiets
// success output).
var nonInteractive bool

// jsonOut is the --json global flag: emit machine-readable JSON for
// commands that return useful data (list/status/account ops) instead of
// the human table/prose.
var jsonOut bool

// userToken is the user/admin bearer token for REST calls (--token or
// $PAGNET_TOKEN); when both are empty the token stored by `pagnet login`
// applies. Host credentials from `pagnet enroll` authenticate the daemon
// over WSS only — the REST API is user-scoped and rejects host identities
// (403 host_identity).
var userToken string

// insecureRemoteHTTP is the --insecure-remote-http flag: it opts into
// plain HTTP for a non-loopback control plane / release URL (development
// only). Off by default; ORed with the PAGNET_INSECURE_REMOTE_HTTP env by
// the netpolicy check. A non-loopback remote must otherwise be HTTPS.
var insecureRemoteHTTP bool

// root is package-level so shared plumbing (newCLI) can check whether the
// user explicitly set --server (flag.Changed) before applying the saved
// config's server URL.
var root *cobra.Command

// envOrDefault is the CLI's env-var contract: a flag default that reads
// the environment first, so zero-flag runs work (e.g. PAGNET_SERVER,
// PAGNET_ENROLL_TOKEN, PAGNET_TOKEN).
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	root = &cobra.Command{
		Use:           "pagnet",
		Short:         "pagnet CLI — control plane for AI coding agent networks",
		SilenceUsage:  true,
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if detach {
				return runDetach(cmd)
			}
			// Bare `pagnet` on a TTY: a tiny contextual status (fresh /
			// stopped / running). Non-TTY: no decorative UI (a hint only).
			return runBareStatus(cmd)
		},
	}
	// --server is the EXPLICIT control-plane flag only (precedence 1). Its
	// default is empty: $PAGNET_SERVER (precedence 2) and the stored account
	// config (precedence 3) are applied by resolveServerURL, NOT folded into
	// the flag default — folding them made the stored config silently
	// override $PAGNET_SERVER (the stale-dev-control-plane bug).
	root.PersistentFlags().StringVar(&serverURL, "server", "",
		"control plane URL (precedence: --server > $PAGNET_SERVER > stored account config > build default)")
	root.PersistentFlags().StringVar(&userToken, "token", os.Getenv("PAGNET_TOKEN"), "user/admin bearer token for REST calls (falls back to \"pagnet login\")")
	// --account selects the account context for this invocation (scripts);
	// empty = the current account.
	root.PersistentFlags().StringVar(&accountFlag, "account", "", "account context for this invocation (default: the current account)")
	// --silent: no banners/progress/success prose; errors still go to stderr
	// and the exit status stays meaningful.
	root.PersistentFlags().BoolVar(&silent, "silent", false, "no banners/progress/success prose (errors and exit status unchanged)")
	// --non-interactive: never prompt, never open a browser, never wait for a
	// human; fail immediately when required information is missing.
	root.PersistentFlags().BoolVar(&nonInteractive, "non-interactive", false, "never prompt or open a browser; fail fast when input is missing")
	// --json: machine-readable output for commands that return useful data.
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "emit JSON instead of the human-readable output (where supported)")
	// --insecure-remote-http opts into plain HTTP for a non-loopback
	// control plane / release URL (development only). Off by default; a
	// non-loopback remote must otherwise be HTTPS. The PAGNET_INSECURE_
	// REMOTE_HTTP=1 env is an equivalent opt-in (checked by netpolicy).
	root.PersistentFlags().BoolVar(&insecureRemoteHTTP, "insecure-remote-http", false,
		"allow plain HTTP for a non-loopback control plane / release URL (development only; also PAGNET_INSECURE_REMOTE_HTTP=1)")
	// -d/--detach is a ROOT-level launcher (re-exec `pagnet serve`
	// detached); the daemon flag set is registered locally so
	// `pagnet -d --state-dir ...` parses. Deliberately NOT persistent:
	// subcommands keep their own flag surfaces.
	root.Flags().BoolVarP(&detach, "detach", "d", false,
		"start the pagnet service detached (log to <state-dir>/pagnetd.log, print the pid)")
	registerDaemonFlags(root)

	root.AddCommand(
		loginCmd(),
		accountCmd(),
		enrollCmd(),
		unenrollCmd(),
		workerCmd(),
		daemonCmd(),
		updateCmd(),
		versionCmd(),
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
		agentCmd(),
		hostsCmd(),
		hostCmd(),
		networksCmd(),
		tasksCmd(),
		inboxCmd(),
		stopCmd(),
		restartCmd(),
		openCmd(),
		initCmd(),
		doctorCmd(),
		// V2 cutover command surface (plan D10): participants, capabilities,
		// events. (agentsCmd is the V2 list: agents + live endpoints.)
		servicesCmd(),
		serviceCmd(),
		searchCmd(),
		invokeCmd(),
		eventCmd(),
		subscribeCmd(),
		subscriptionsCmd(),
		unsubscribeCmd(),
		recipeCmd(),
		// internal (hidden): daemon-spawned MCP bridge entrypoints
		mcpCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// versionCmd prints the build version stamped at release-build time
// (-X main.version=$(VERSION)). The unified binary carries the version
// for ALL modes (packaging migration): one `pagnet version` answers for
// the CLI, the daemon, and the MCP bridges.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the pagnet version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "pagnet", version)
		},
	}
}

// enrollCmd implements `pagnet enroll` (formerly `pagnet login`): consumes
// a one-time enrollment token against the control plane and stores the host
// credential + identity in the active account's config (mode 0600).
// User sign-in lives in `pagnet login`.
func enrollCmd() *cobra.Command {
	var token, name, stateDir, rootsMode string
	var roots []string
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Connect this host: signs you in (first run) and consumes an enrollment token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root := machineStateDir(stateDir)
			if _, err := accounts.MigrateLegacy(root); err != nil {
				return err
			}
			account := accounts.ActiveAccount(root, accountFlag)
			if token == "" {
				// No enrollment token: token-first sign-in (the hidden
				// paste), mint a one-time token for this host, and enroll
				// with it. With --token the scripted/CI path is unchanged
				// (no sign-in at all).
				if err := enrollHostForeground(root, account, name, roots, rootsMode); err != nil {
					return err
				}
			} else {
				cfg, _, _ := loadAccountConfig(root)
				server := resolveServerURL(cfg)
				if server == "" {
					return errors.New("no control plane URL — set --server / $PAGNET_SERVER")
				}
				if err := doEnroll(server, token, name, roots, rootsMode, accountConfigDir(root, account)); err != nil {
					return err
				}
			}
			if !silent {
				fmt.Println("run `pagnet -d` to connect this host")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", os.Getenv("PAGNET_ENROLL_TOKEN"), "one-time enrollment token ($PAGNET_ENROLL_TOKEN; without it, enroll signs you in and mints one for this host)")
	cmd.Flags().StringVar(&name, "name", "", "host name (default: machine hostname)")
	cmd.Flags().StringArrayVar(&roots, "roots", nil, "allowed workspace root (repeatable; server-side token roots win)")
	cmd.Flags().StringVar(&rootsMode, "roots-mode", "", "roots enforcement: allow_all (default, any path) or allow_list (confine to --roots)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "daemon state dir (default ~/.pagnet)")
	return cmd
}

// doEnroll consumes a one-time enrollment token against the control plane
// and stores the host credential + identity in accDir (the account's
// config.yaml, mode 0600). Shared by `pagnet enroll` and `pagnet worker`
// (first run).
func doEnroll(server, token, name string, roots []string, rootsMode string, accDir string) error {
	if server == "" {
		return errors.New("no control plane URL — set --server / $PAGNET_SERVER")
	}
	if token == "" {
		return errors.New("--token is required (create one in the web UI: Hosts → Connect host)")
	}
	if name == "" {
		name, _ = os.Hostname()
		if name == "" {
			name = "pagnet-host"
		}
	}
	// Roots mode: an explicit mode wins; explicit roots imply allow_list;
	// otherwise the default allow_all (open host).
	mode := rootsMode
	if mode == "" && len(roots) > 0 {
		mode = domain.RootsModeAllowList
	}
	if mode == "" {
		mode = domain.RootsModeAllowAll
	}

	var resp struct {
		Host struct {
			ID string `json:"ID"`
		} `json:"host"`
		Credential   string   `json:"credential"`
		AllowedRoots []string `json:"allowedRoots"`
		RootsMode    string   `json:"rootsMode"`
	}
	if err := apiPostJSON(server+"/api/v1/hosts/enroll", map[string]any{
		"token":         token,
		"hostName":      name,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"daemonVersion": version,
		// Explicit --roots win over the token's roots (the browser
		// default); the server responds with what it actually applied.
		"allowedRoots": roots,
		"rootsMode":    mode,
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
	savedMode := resp.RootsMode
	if savedMode == "" {
		savedMode = mode
	}

	if err := mergeConfigFile(accDir, map[string]any{
		"serverUrl":    strings.TrimSuffix(server, "/"),
		"credential":   resp.Credential,
		"hostId":       resp.Host.ID,
		"hostName":     name,
		"allowedRoots": savedRoots,
		"rootsMode":    savedMode,
	}); err != nil {
		return err
	}
	if !silent {
		fmt.Printf("host %s registered (%s)\n", name, resp.Host.ID)
		fmt.Printf("credential stored in %s (mode 0600)\n", filepath.Join(accDir, "config.yaml"))
		fmt.Printf("roots mode: %s\n", savedMode)
		if len(savedRoots) > 0 {
			fmt.Printf("allowed roots: %v\n", savedRoots)
		}
	}
	return nil
}

// mintEnrollmentToken mints a one-time host enrollment token for hostName
// with the user's bearer (the same API the web console's "Connect host"
// uses) and returns its plaintext (shown exactly once).
//
// A non-201 is returned as an *httpFailure carrying the status and the
// server's error CODE, so the caller can translate a known auth failure into
// product text. The body travels with it for the non-auth path only and is
// never rendered to a human by that caller (plan §7).
func mintEnrollmentToken(base, userTok, hostName string, roots []string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"name":         hostName,
		"allowedRoots": roots,
	})
	req, err := http.NewRequest(http.MethodPost, base+"api/v1/hosts/enrollment-tokens", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userTok)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create enrollment token: %w",
			&httpFailure{status: resp.StatusCode, code: apiErrorCode(raw), body: string(raw)})
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", errors.New("create enrollment token: unexpected response")
	}
	return out.Token, nil
}

// resolveEnrollServer resolves the control-plane URL for the first-run
// enroll flow: the full precedence (--server > $PAGNET_SERVER > stored
// account config > build default, via resolveServerURL), then an interactive
// prompt (a dev build has no default), then a clean error (non-interactive).
func resolveEnrollServer(root, account string) (string, error) {
	if cfg, _, err := loadAccountConfig(root); err == nil {
		if s := resolveServerURL(cfg); s != "" {
			return s, nil
		}
	}
	if interactiveMode() {
		for attempt := 0; attempt < 2; attempt++ {
			line, err := askLineFn("control plane URL: ")
			if err != nil {
				return "", err
			}
			if line != "" {
				return strings.TrimSuffix(line, "/"), nil
			}
		}
		return "", errors.New("no control plane URL entered — set --server / $PAGNET_SERVER or re-run and enter the URL")
	}
	return "", errors.New("no control plane URL — set --server / $PAGNET_SERVER, or run 'pagnet enroll --server <url>'")
}

// enrollHostForeground runs the first-run host connection in the
// FOREGROUND: resolve the control-plane URL, authenticate the user
// token-first (the hidden paste — never a browser), mint a one-time
// enrollment token for this host, and complete the enrollment with it.
// Shared by `pagnet enroll` (without --token) and `pagnet serve` /
// `pagnet -d` (which must finish it before the daemon starts / detaches —
// the paste prompt runs in the foreground, never inside the detached child).
//
// Minting an enrollment token is an ACCOUNT-AUTHORITY operation (governance
// §33/§56): a delegated credential is refused 403
// account_authority_required. That failure is translated into product text
// and re-prompts a human; it exits only when nobody is there to ask
// (--non-interactive / no TTY), when the bearer came from an explicit
// --token / $PAGNET_TOKEN (a prompt cannot fix a flag the operator set), or
// when the human stops trying. Printing the server's JSON body and dying —
// what this did before — is the 2026-09-20 incident (plan §7).
func enrollHostForeground(root, account, name string, roots []string, rootsMode string) error {
	server, err := resolveEnrollServer(root, account)
	if err != nil {
		return err
	}
	base := server + "/"
	hostName := name
	if hostName == "" {
		hostName, _ = os.Hostname()
		if hostName == "" {
			hostName = "pagnet-host"
		}
	}
	accDir := accountConfigDir(root, account)
	for attempt := 0; ; attempt++ {
		userTok, err := userCredentialForServeFresh(root, account, server, attempt > 0)
		if err != nil {
			return err
		}
		minted, err := mintEnrollmentToken(base, userTok, hostName, roots)
		if err == nil {
			return doEnroll(server, minted, hostName, roots, rootsMode, accDir)
		}
		failure := translateAuthFailure(err, credentialClassOf(accDir, userTok))
		if !failure.Reprompt || userToken != "" || !interactiveMode() || attempt >= maxAuthReprompts {
			return failure.Err
		}
		// Product text on stderr (where the hidden paste prompt also writes),
		// then a fresh paste — the stored credential is not handed back.
		fmt.Fprintln(os.Stderr, failure.Err)
	}
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
