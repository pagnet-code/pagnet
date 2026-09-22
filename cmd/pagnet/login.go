package main

// `pagnet login` — user authentication for REST calls (phase 2 auth
// architecture + AUTH-3 token-first paste login). Mode-aware:
//
//   - paste (interactive, local/oidc servers): hidden-input paste of a
//     Pagnet Token — Account/Access tokens are exchanged once for a
//     derived client credential (see tokenlogin.go);
//   - token:  --token <admin token> (validated against /auth/me)
//   - local:  --username/--password → the server mints the account-session
//     client credential (the CLI never keeps browser session cookies)
//   - oidc:   RFC 8628 device flow — the CLI shows a user code, the user
//     authorizes in a browser, and the server mints the account-session
//     client credential.
//
// Every normal human sign-in converges on the same stored credential
// class: the account-session client credential (a pgn_pat_v1_ credential
// the server persists with authority_class='account_session'). The
// resulting bearer is stored via the OS keyring when available, else in
// the state dir's config.yaml (mode 0600, "token" key) and used by every
// command unless --token or $PAGNET_TOKEN overrides it. Host enrollment
// lives in `pagnet enroll`.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/pagnet-code/pagnet/internal/accounts"
	"github.com/pagnet-code/pagnet/internal/netpolicy"
)

func loginCmd() *cobra.Command {
	var (
		token     string
		username  string
		password  string
		stateDir  string
		noBrowser bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in as a user: store the CLI credential (paste a Pagnet Token, or the server's sign-in mode)",
		Long: `Sign in to the control plane and store the credential every command uses.

Token-first (production) servers: pagnet login prompts for your Pagnet
Token with echo off — paste an Account Token (pgn_acc_v1_…) or an Access
Token (pgn_pat_v1_…). An Account/Access Token is exchanged ONCE for a
revocable derived client credential: only the derived credential is
stored (OS keyring, 0600 file fallback), never the pasted token itself.
Press Enter at the prompt to use the server's other sign-in mode instead
(browser/OIDC, or username/password).

Every sign-in method converges on the same stored credential: the
account-session client credential the server mints for you.

--token / $PAGNET_TOKEN stay available for scripted use but are the less
safe path: argv and the environment can leak into shell history, process
listings, and CI logs.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			root := machineStateDir(stateDir)
			if _, err := accounts.MigrateLegacy(root); err != nil {
				return err
			}
			account := accounts.ActiveAccount(root, accountFlag)
			accDir := accountConfigDir(root, account)
			cfg, _, _ := loadAccountConfig(root)
			server := resolveServerURL(cfg)
			if server == "" {
				return errors.New("no control plane URL — set --server / $PAGNET_SERVER, or run 'pagnet enroll --server <url>' first")
			}
			// HTTPS-required-for-non-loopback (client-hardening wave 2):
			// login speaks raw HTTP to the control plane, so it checks the
			// policy itself (it does not go through newCLI).
			if err := netpolicy.Check(server, insecureRemoteHTTP); err != nil {
				return err
			}
			base := server + "/"
			client := &http.Client{Timeout: 60 * time.Second}

			// Which auth mode is the server running? (public endpoint)
			var status struct {
				Mode string `json:"mode"`
			}
			resp, err := client.Get(base + "api/v1/auth/setup/status")
			if err != nil {
				return fmt.Errorf("cannot reach the control plane at %s: %w", base, err)
			}
			if resp.StatusCode < 300 {
				_ = json.NewDecoder(resp.Body).Decode(&status)
			}
			resp.Body.Close()

			saved := false
			switch status.Mode {
			case "token":
				if token == "" {
					token = userToken // --token flag / $PAGNET_TOKEN
				}
				if token == "" {
					return errors.New("--token is required in token mode (the server prints the admin token once at startup when PAGNET_ADMIN_TOKEN is unset)")
				}
				ok, err := bearerMe(client, base, token)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("the server rejected the token")
				}
				fmt.Println("admin token verified.")

			case "local", "accounts", "oidc":
				// "accounts" is the canonical name of the DB-user auth
				// mode (renamed from "local", which reads like localhost);
				// "local" stays accepted for servers that predate the
				// rename.
				// AUTH-3 token-first paste login (governance §17,
				// token-first §11/§35): the interactive path is the hidden
				// paste prompt — the token never lands in argv or shell
				// history. --token / $PAGNET_TOKEN stay the scripted path
				// (documented as less safe) and skip the prompt. An empty
				// paste (Enter) falls through to the mode's existing
				// sign-in flow (browser/OIDC or username/password).
				pasted := token
				if pasted == "" {
					pasted = userToken // $PAGNET_TOKEN (scripted)
				}
				if pasted == "" && username == "" && password == "" && hasTTYFn() {
					if status.Mode == "oidc" {
						fmt.Fprintln(os.Stderr, "Paste your Pagnet Token, or press Enter to sign in through your browser.")
					} else {
						fmt.Fprintln(os.Stderr, "Paste your Pagnet Token, or press Enter for username/password sign-in.")
					}
					if pasted, err = askPagnetTokenFn("Paste your Pagnet Token: "); err != nil {
						return err
					}
				}
				if pasted != "" {
					res, err := loginWithPastedToken(accDir, account, server, client, pasted)
					if err != nil {
						return err
					}
					fmt.Println(res.Summary)
					saved = true
					break
				}
				if status.Mode == "oidc" {
					// Reuse the shared helper: it validates a stored token
					// first (idempotent re-login) and runs the sign-in flow
					// otherwise. It persists the token itself. It takes the
					// MACHINE state dir (not accDir): it applies
					// accountConfigDir internally, exactly like the REST
					// commands' newCLI does.
					apiToken, err := ensureUserToken(root, account, base, noBrowser, hasTTYFn())
					if err != nil {
						return err
					}
					token = apiToken
					saved = true
					fmt.Println("signed in.")
					break
				}
				if username == "" {
					if username, err = askLine("username: "); err != nil {
						return err
					}
				}
				if password == "" {
					if password, err = askPassword("password: "); err != nil {
						return err
					}
				}
				apiToken, err := loginLocalAPIToken(client, base, username, password)
				if err != nil {
					return err
				}
				token = apiToken
				fmt.Println("signed in; the account-session credential was created for the CLI.")

			default:
				return fmt.Errorf("unknown server auth mode %q", status.Mode)
			}

			if !saved {
				if err := saveUserToken(accDir, account, server, token); err != nil {
					return err
				}
			}
			fmt.Printf("token stored in %s (mode 0600)\n", filepath.Join(accDir, "config.yaml"))
			fmt.Println("override per call with --token or $PAGNET_TOKEN")
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "bearer for scripted login: admin token (token mode) or Pagnet Token (local/oidc modes) — less safe than the paste prompt (shell history / process listings)")
	cmd.Flags().StringVar(&username, "username", "", "username (local mode)")
	cmd.Flags().StringVar(&password, "password", "", "password (local mode; prompted when omitted)")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "state dir for the stored token (default ~/.pagnet)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "oidc: only print the verification URL, do not open it")
	return cmd
}

// bearerMe validates a bearer against /auth/me.
func bearerMe(client *http.Client, base, token string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, base+"api/v1/auth/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// --- token storage (user bearer in the shared state file) ---------------------

// credentialKey is the OS-keyring key for an account's user token. It is
// scoped per (account, server) so two accounts on the same control plane
// keep separate credentials and never overwrite each other. The default
// account keeps the legacy server-scoped key so existing keyring entries
// survive the account migration untouched.
func credentialKey(account, server string) string {
	s := strings.TrimSuffix(server, "/")
	if account == "" || account == accounts.DefaultAccount {
		return "pagnet-token-" + s
	}
	return "pagnet-token-" + account + "-" + s
}

// openKeyringFn opens the OS keyring (a test seam: replace it to force the
// 0600-file fallback in tests, where no system keyring is available). An
// empty Config means "all available backends".
var openKeyringFn = func() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{})
}

// loadUserToken reads the stored user bearer ("" when absent). The OS keyring
// is preferred when available; the 0600 account config file is the fallback.
// stateDir is the account's config dir (or a worker dir); account scopes the
// keyring key ("" = server-scoped, for workers/legacy).
func loadUserToken(stateDir, account, server string) string {
	if server != "" {
		if kr, err := openKeyringFn(); err == nil {
			if item, err := kr.Get(credentialKey(account, server)); err == nil {
				return string(item.Data)
			}
		}
	}
	return loadUserTokenFile(stateDir)
}

// loadUserTokenFile reads the token from the state file (the fallback store).
func loadUserTokenFile(stateDir string) string {
	b, err := os.ReadFile(filepath.Join(stateDir, "config.yaml"))
	if err != nil {
		return ""
	}
	var fc struct {
		Token string `yaml:"token"`
	}
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return ""
	}
	return fc.Token
}

// mergeConfigFile merges fields into the state dir's config.yaml,
// preserving unrelated keys — `pagnet login` (user token) and
// `pagnet enroll` (host credential) share the file and must not wipe
// each other's fields. A nil value DELETES the key (used to clear stale
// credential metadata and the file token copy).
func mergeConfigFile(stateDir string, fields map[string]any) error {
	path := filepath.Join(stateDir, "config.yaml")
	var fc map[string]any
	if b, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(b, &fc); err != nil {
			return fmt.Errorf("existing %s is not a mapping: %w", path, err)
		}
	}
	if fc == nil {
		fc = map[string]any{}
	}
	for k, v := range fields {
		if v == nil {
			delete(fc, k)
			continue
		}
		fc[k] = v
	}
	b, err := yaml.Marshal(fc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// saveUserToken stores a user bearer that carries no derived-credential
// metadata of its own (token mode's admin token, a worker's --user-token,
// or a sign-in flow whose response reports no restriction metadata). The
// metadata of a previous token-first login is cleared. Storage itself is
// saveCredential: OS keyring preferred, 0600 account config file fallback;
// the server URL (non-secret) is always kept in the file.
func saveUserToken(stateDir, account, server, token string) error {
	return saveCredential(stateDir, account, server, token, credentialMeta{})
}

// --- prompts ------------------------------------------------------------------

// readLine reads one line directly from the fd, byte by byte. It must NOT
// use a buffered reader: bufio would pull the following line(s) into its
// own buffer and the next prompt (or term.ReadPassword) would read EOF /
// the wrong bytes from the already-consumed file descriptor.
func readLine() (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return sb.String(), nil
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			// EOF mid-line (piped input without trailing newline): return
			// what was read when non-empty.
			if sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
	}
}

func askLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := readLine()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// askLineFn is a test seam for askLine (the interactive prompt).
var askLineFn = askLine

func askPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	defer fmt.Fprintln(os.Stderr)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// Non-interactive fallback (piped input): read a line as-is.
	line, err := readLine()
	return strings.TrimRight(line, "\r\n"), err
}

// --- local mode: password → account-session credential ------------------------

// loginLocalAPIToken performs the CLI half of local-mode login: a throwaway
// browser session is created (username/password, cli:true), the server mints
// the account-session client credential in the login response itself, and the
// session is logged out immediately — it was only a carrier for the mint and
// must not be left alive. The CLI stores only the credential.
func loginLocalAPIToken(client *http.Client, base, username, password string) (string, error) {
	// 1. POST /auth/login (cli:true) → Set-Cookie: pagnet_session +
	//    pagnet_csrf, and the minted account-session credential.
	body, _ := json.Marshal(map[string]any{"username": username, "password": password, "cli": true})
	resp, err := client.Post(base+"api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp, "login failed (check username/password)")
	}
	var session, csrf string
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "pagnet_session":
			session = c.Value
		case "pagnet_csrf":
			csrf = c.Value
		}
	}
	if session == "" || csrf == "" {
		return "", errors.New("login response did not set session cookies")
	}
	var created struct {
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil ||
		!strings.HasPrefix(created.Credential, tokenPrefixAccess) {
		return "", errors.New("login response did not return the account-session credential")
	}

	// 2. The throwaway session has served its purpose.
	logout, _ := http.NewRequest(http.MethodPost, base+"api/v1/auth/logout", nil)
	logout.Header.Set("Cookie", "pagnet_session="+session+"; pagnet_csrf="+csrf)
	logout.Header.Set("X-CSRF-Token", csrf)
	if r, err := client.Do(logout); err == nil {
		r.Body.Close()
	}
	return created.Credential, nil
}

// --- oidc mode: RFC 8628 device flow (client-mediated) -------------------------
//
// The CLI is the OIDC client's public device: it runs the Device
// Authorization Grant against the identity provider directly. The control
// plane only (a) hands out the IdP endpoints + client id (device-config) and
// (b) validates the resulting ID token and mints the account-session client
// credential (device/token).

// deviceConfig is the control plane's device-config response (all strings).
type deviceConfig struct {
	Issuer                      string `json:"issuer"`
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint"`
	TokenEndpoint               string `json:"tokenEndpoint"`
	ClientID                    string `json:"clientId"`
	Scope                       string `json:"scope"`
}

// --- PKCE (RFC 7636 / RFC 9126) ------------------------------------------------
//
// The CLI is a public client (no client secret), so the device grant carries
// PKCE: the verifier never leaves the device except in the token polls, and
// the S256 challenge is sent with the device-authorization request. IdPs that
// do not require PKCE accept the extra parameters (RFC 9126 makes this the
// conformant behavior for public clients).

// pkceVerifier generates a code_verifier per RFC 7636: 32 random bytes,
// base64url-encoded without padding — 43 unreserved characters (the RFC's
// minimum length).
func pkceVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge computes the S256 code_challenge for a verifier:
// BASE64URL(SHA256(ASCII(verifier))) without padding (RFC 7636 §4.2).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// loginOIDCDeviceFlow performs the client-mediated RFC 8628 device flow and
// returns the minted account-session client credential. noBrowser (or
// $PAGNET_NO_BROWSER=1) skips the browser-open attempt (the URL + code are
// always printed).
func loginOIDCDeviceFlow(base string, noBrowser bool) (mintedCredential, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	// 1. Device config from the control plane (public endpoint).
	var cfg deviceConfig
	resp, err := client.Get(base + "api/v1/auth/oidc/device-config")
	if err != nil {
		return mintedCredential{}, fmt.Errorf("device flow: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return mintedCredential{}, apiError(resp, "could not fetch the device config (is the server in oidc mode?)")
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		resp.Body.Close()
		return mintedCredential{}, fmt.Errorf("device flow: %w", err)
	}
	resp.Body.Close()
	if cfg.DeviceAuthorizationEndpoint == "" || cfg.TokenEndpoint == "" || cfg.ClientID == "" {
		return mintedCredential{}, errors.New("device flow: the server returned an incomplete device config")
	}

	// 2. Start the device flow at the IdP (with PKCE, RFC 9126).
	verifier, err := pkceVerifier()
	if err != nil {
		return mintedCredential{}, err
	}
	authForm := url.Values{}
	authForm.Set("client_id", cfg.ClientID)
	if cfg.Scope != "" {
		authForm.Set("scope", cfg.Scope)
	}
	authForm.Set("code_challenge", pkceChallenge(verifier))
	authForm.Set("code_challenge_method", "S256")
	daResp, err := postForm(client, cfg.DeviceAuthorizationEndpoint, authForm)
	if err != nil {
		return mintedCredential{}, fmt.Errorf("device flow: %w", err)
	}
	defer daResp.Body.Close()
	if daResp.StatusCode != http.StatusOK {
		return mintedCredential{}, apiError(daResp, "could not start the device flow at the identity provider")
	}
	var da struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.NewDecoder(daResp.Body).Decode(&da); err != nil || da.DeviceCode == "" {
		return mintedCredential{}, errors.New("device flow: unexpected device-authorization response")
	}

	// 3. Show the verification URL + code; best-effort open a browser.
	verifyURL := da.VerificationURIComplete
	if verifyURL == "" {
		verifyURL = da.VerificationURI
	}
	if verifyURL == "" {
		verifyURL = cfg.Issuer
	}
	fmt.Println()
	fmt.Printf("Open %s in a browser to sign in.\n", verifyURL)
	if da.UserCode != "" {
		fmt.Printf("Enter the code %s when prompted.\n", da.UserCode)
	}
	if !noBrowser && os.Getenv("PAGNET_NO_BROWSER") != "1" {
		fmt.Printf("Opening your browser to sign in to %s…\n", strings.TrimSuffix(base, "/"))
		if err := openBrowserFn(verifyURL); err != nil {
			fmt.Println("(could not open a browser — use the URL above)")
		}
	}
	fmt.Print("Waiting for you to sign in")

	// 4. Poll the IdP token endpoint (RFC 8628). Respect the IdP's interval
	//    and expires_in; hard-cap the wait at ~3 minutes.
	interval := time.Duration(da.Interval) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	if da.ExpiresIn <= 0 || time.Until(deadline) > 3*time.Minute {
		deadline = time.Now().Add(3 * time.Minute)
	}
	for time.Now().Before(deadline) {
		pollForm := url.Values{}
		pollForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		pollForm.Set("device_code", da.DeviceCode)
		pollForm.Set("client_id", cfg.ClientID)
		pollForm.Set("code_verifier", verifier)
		r, err := postForm(client, cfg.TokenEndpoint, pollForm)
		if err != nil {
			return mintedCredential{}, fmt.Errorf("device flow: %w", err)
		}
		switch {
		case r.StatusCode == http.StatusOK:
			var ts struct {
				IDToken string `json:"id_token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&ts); err != nil || ts.IDToken == "" {
				r.Body.Close()
				return mintedCredential{}, errors.New("device flow: the identity provider returned no ID token")
			}
			r.Body.Close()
			fmt.Println(" done")
			// 5. Exchange the ID token for the account-session client
			//    credential.
			return exchangeIDToken(client, base, ts.IDToken)
		case r.StatusCode == http.StatusBadRequest:
			var e struct {
				Error string `json:"error"`
			}
			_ = json.NewDecoder(r.Body).Decode(&e)
			r.Body.Close()
			switch e.Error {
			case "authorization_pending", "":
				// keep polling at the current interval
			case "slow_down":
				interval += 5 * time.Second // the IdP asked us to slow down
			case "expired_token":
				fmt.Println()
				return mintedCredential{}, errors.New("device flow expired before you signed in; run the command again")
			case "access_denied":
				fmt.Println()
				return mintedCredential{}, errors.New("you denied the login in the browser; run the command again")
			default:
				fmt.Println()
				return mintedCredential{}, fmt.Errorf("device flow: the identity provider rejected the device code (%s)", e.Error)
			}
		default:
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			r.Body.Close()
			return mintedCredential{}, fmt.Errorf("device flow: identity provider http %d: %s", r.StatusCode, raw)
		}
		time.Sleep(interval)
	}
	fmt.Println()
	return mintedCredential{}, errors.New("timed out waiting for browser authorization")
}

// mintedCredential is the result of the OIDC device flow: the account-session
// client credential the server minted (pgn_pat_v1_) plus the server-reported
// restriction metadata. The stored record's class is verified from the
// credential's own prefix at save time.
type mintedCredential struct {
	credential   string
	role         string
	networkScope string
}

// meta renders the server-reported restriction metadata for saveCredential.
func (m mintedCredential) meta() credentialMeta {
	return credentialMeta{Role: m.role, NetworkScope: m.networkScope}
}

// exchangeIDToken posts the ID token to the control plane and returns the
// minted account-session client credential + its restriction metadata.
func exchangeIDToken(client *http.Client, base, idToken string) (mintedCredential, error) {
	body, _ := json.Marshal(map[string]string{"idToken": idToken})
	resp, err := client.Post(base+"api/v1/auth/oidc/device/token", "application/json", bytes.NewReader(body))
	if err != nil {
		return mintedCredential{}, fmt.Errorf("device flow: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return mintedCredential{}, apiError(resp, "could not exchange the ID token for the client credential")
	}
	var ok struct {
		Credential   string `json:"credential"`
		Role         string `json:"role"`
		NetworkScope string `json:"networkScope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ok); err != nil ||
		!strings.HasPrefix(ok.Credential, tokenPrefixAccess) {
		return mintedCredential{}, errors.New("device flow: unexpected token-exchange response")
	}
	return mintedCredential{credential: ok.Credential, role: ok.Role, networkScope: ok.NetworkScope}, nil
}

// postForm POSTs form-encoded data and returns the response (the caller owns
// the body).
func postForm(client *http.Client, u string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

// --- auto-login (no stored credentials -> device flow once -> continue) --------

// hasTTY reports whether the process has an interactive terminal (stderr).
// The device flow is interactive (it waits for browser authorization), so a
// non-TTY context (script, CI) fails fast instead of looping.
func hasTTY() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// hasTTYFn is a test seam for hasTTY.
var hasTTYFn = hasTTY

// serverAuthMode queries the public /auth/setup/status endpoint.
func serverAuthMode(base string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(base + "api/v1/auth/setup/status")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}
	var s struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return "", err
	}
	return s.Mode, nil
}

// storedServerURL returns the control plane URL from the active account's
// config ("" when absent or unreadable) — the fallback for commands on an
// already connected machine when --server / $PAGNET_SERVER is empty.
func storedServerURL(stateDir string) string {
	if cfg, _, err := loadAccountConfig(stateDir); err == nil {
		return cfg.ServerURL
	}
	return ""
}

// ensureUserToken makes the CLI's user bearer available for an authenticated
// command:
//
//   - a stored token that still validates (GET /auth/me) is returned as-is —
//     zero auth-endpoint chatter beyond /auth/me;
//   - absent or rejected: the server's auth mode decides —
//     oidc     → the sign-in flow (browser; noBrowser prints the URL and polls),
//     accounts → username/password prompts (interactive only; "local" is the
//     pre-rename name of the same mode, still accepted),
//     token    → clean error: the admin token cannot be minted by a flow.
//
// Non-interactive runs (no TTY) never hang or open a browser: without
// noBrowser they fail with the exact missing piece; with noBrowser the oidc
// flow prints the URL and keeps polling (the deliberate headless case — the
// user signs in from another device). Callers holding an explicit
// --token / $PAGNET_TOKEN must not call this at all: the short-circuit
// happens before any endpoint is touched.
func ensureUserToken(stateDir, account, base string, noBrowser, interactive bool) (string, error) {
	if base == "" {
		return "", errors.New("no control plane URL — set --server / $PAGNET_SERVER, or run 'pagnet enroll --server <url>' first")
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	client := &http.Client{Timeout: 60 * time.Second}
	// The credential slot is the account's config dir (see
	// authenticateUserFresh): stateDir is the machine dir for every REST
	// command, and the account migration has already moved the credential out
	// of it.
	accDir := accountConfigDir(stateDir, account)

	// 1. A stored token that still validates is the one to use.
	if tok := loadUserToken(accDir, account, base); tok != "" {
		if ok, err := bearerMe(client, base, tok); err == nil && ok {
			return tok, nil
		}
		// Rejected (or unreachable): fall through and sign in again.
	}

	// 2. Which auth mode is the server running? (public endpoint)
	mode, err := serverAuthMode(base)
	if err != nil {
		return "", fmt.Errorf("cannot reach the control plane at %s: %w", base, err)
	}
	switch mode {
	case "oidc":
		if !interactive && !noBrowser {
			return "", errors.New("no stored credentials and no interactive terminal; run `pagnet login` in a terminal first (or set --token / $PAGNET_TOKEN)")
		}
		cred, err := loginOIDCDeviceFlow(base, noBrowser)
		if err != nil {
			return "", err
		}
		if err := saveCredential(accDir, account, base, cred.credential, cred.meta()); err != nil {
			return "", err
		}
		fmt.Printf("signed in; token stored in %s\n", accDir)
		return cred.credential, nil
	case "local", "accounts":
		// "accounts" is the canonical name of the DB-user auth mode;
		// "local" is the pre-rename name, still accepted.
		if !interactive {
			return "", errors.New("no stored credentials and no interactive terminal; run `pagnet login` in a terminal first (or set --token / $PAGNET_TOKEN)")
		}
		var username, password string
		if username, err = askLineFn("username: "); err != nil {
			return "", err
		}
		if password, err = askPassword("password: "); err != nil {
			return "", err
		}
		tok, err := loginLocalAPIToken(client, base, username, password)
		if err != nil {
			return "", err
		}
		if err := saveUserToken(accDir, account, base, tok); err != nil {
			return "", err
		}
		fmt.Printf("signed in; token stored in %s\n", accDir)
		return tok, nil
	case "token":
		return "", errors.New("the server is in token mode: the admin token cannot be minted by a sign-in flow — set --token / $PAGNET_TOKEN to the admin token (the server prints it once at startup when PAGNET_ADMIN_TOKEN is unset)")
	default:
		return "", fmt.Errorf("unknown server auth mode %q", mode)
	}
}

// apiError renders the server's {"error":{"code","message"}} shape.
func apiError(resp *http.Response, context string) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error.Message != "" {
		return fmt.Errorf("%s: %s", context, e.Error.Message)
	}
	return fmt.Errorf("%s: http %d", context, resp.StatusCode)
}
