package main

// `pagnet login` — user authentication for REST calls (phase 2 auth
// architecture). Mode-aware:
//
//   - token:  --token <admin token> (validated against /auth/me)
//   - local:  --username/--password → the server mints a revocable API
//     token (the CLI never keeps browser session cookies)
//   - oidc:   RFC 8628 device flow — the CLI shows a user code, the user
//     authorizes in a browser, and the server issues an API token.
//
// The resulting bearer is stored in the state dir's config.yaml (mode 0600,
// "token" key) and used by every command unless --token or $PAGNET_TOKEN
// overrides it. Host enrollment lives in `pagnet enroll`.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

func loginCmd() *cobra.Command {
	var (
		token     string
		username  string
		password  string
		label     string
		stateDir  string
		noBrowser bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in as a user: store the API token for REST calls (token / local / oidc modes)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if stateDir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				stateDir = filepath.Join(home, ".pagnet")
			}
			base := serverURL
			if !strings.HasSuffix(base, "/") {
				base += "/"
			}
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
				fmt.Println("token mode: admin token verified.")

			case "local":
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
				apiToken, err := loginLocalAPIToken(client, base, username, password, label)
				if err != nil {
					return err
				}
				token = apiToken
				fmt.Println("local mode: signed in; a new API token was created for the CLI.")

			case "oidc":
				apiToken, err := loginOIDCDeviceFlow(client, base, noBrowser)
				if err != nil {
					return err
				}
				token = apiToken
				fmt.Println("oidc mode: device flow complete; an API token was created for the CLI.")

			default:
				return fmt.Errorf("unknown server auth mode %q", status.Mode)
			}

			if err := saveUserToken(stateDir, base, token); err != nil {
				return err
			}
			fmt.Printf("token stored in %s (mode 0600)\n", filepath.Join(stateDir, "config.yaml"))
			fmt.Println("override per call with --token or $PAGNET_TOKEN")
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "admin token (token mode)")
	cmd.Flags().StringVar(&username, "username", "", "username (local mode)")
	cmd.Flags().StringVar(&password, "password", "", "password (local mode; prompted when omitted)")
	cmd.Flags().StringVar(&label, "label", "cli", "API token label (local mode)")
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

// loadUserToken reads the stored user bearer ("" when absent).
func loadUserToken(stateDir string) string {
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
// each other's fields.
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

// saveUserToken stores the user bearer (and the server it came from).
func saveUserToken(stateDir, server, token string) error {
	fields := map[string]any{"token": token}
	if server != "" {
		fields["serverUrl"] = strings.TrimSuffix(server, "/")
	}
	return mergeConfigFile(stateDir, fields)
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

// --- local mode: password → API token ----------------------------------------

// loginLocalAPIToken performs the CLI half of local-mode login: a throwaway
// browser session is created (username/password), used exactly once to mint
// a revocable API token, then logged out. The CLI stores only the token.
func loginLocalAPIToken(client *http.Client, base, username, password, label string) (string, error) {
	// 1. POST /auth/login → Set-Cookie: pagnet_session + pagnet_csrf.
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
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

	// 2. POST /tokens (session cookie + double-submit CSRF) → pagt_ token.
	tokenBody, _ := json.Marshal(map[string]string{"label": label})
	req, _ := http.NewRequest(http.MethodPost, base+"api/v1/tokens", bytes.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "pagnet_session="+session+"; pagnet_csrf="+csrf)
	req.Header.Set("X-CSRF-Token", csrf)
	tokResp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("create API token: %w", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode != http.StatusCreated {
		return "", apiError(tokResp, "could not create the API token")
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&created); err != nil ||
		!strings.HasPrefix(created.Token, "pagt_") {
		return "", errors.New("unexpected API token response")
	}

	// 3. The throwaway session has served its purpose.
	logout, _ := http.NewRequest(http.MethodPost, base+"api/v1/auth/logout", nil)
	logout.Header.Set("Cookie", "pagnet_session="+session+"; pagnet_csrf="+csrf)
	logout.Header.Set("X-CSRF-Token", csrf)
	if r, err := client.Do(logout); err == nil {
		r.Body.Close()
	}
	return created.Token, nil
}

// --- oidc mode: RFC 8628 device flow -------------------------------------------

func loginOIDCDeviceFlow(client *http.Client, base string, noBrowser bool) (string, error) {
	// 1. Start the flow.
	resp, err := client.Post(base+"api/v1/auth/oidc/device", "application/json", strings.NewReader(`{}`))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp, "could not start the device flow (is the server in oidc mode?)")
	}
	var da struct {
		DeviceCode      string `json:"deviceCode"`
		UserCode        string `json:"userCode"`
		VerificationURI string `json:"verificationURI"`
		ExpiresIn       int    `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&da); err != nil || da.DeviceCode == "" {
		return "", errors.New("unexpected device-flow response")
	}
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	if da.ExpiresIn <= 0 {
		deadline = time.Now().Add(5 * time.Minute)
	}

	verifyURL := da.VerificationURI
	if verifyURL == "" {
		verifyURL = base
	}
	fmt.Println("\nSign in with your identity provider:")
	fmt.Printf("  1. Open  %s\n", verifyURL)
	fmt.Printf("  2. Enter the code  %s\n\n", da.UserCode)
	if !noBrowser {
		// Best effort: the printed URL above is the headless fallback.
		_ = openBrowser(verifyURL)
	}
	fmt.Print("Waiting for authorization")

	// 2. Poll. The server long-polls the provider (~25s per request) and
	//    answers 401 authorization_pending until the user authorizes.
	pending := 0
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodPost, base+"api/v1/auth/oidc/device/token",
			strings.NewReader(fmt.Sprintf(`{"deviceCode":%q}`, da.DeviceCode)))
		req.Header.Set("Content-Type", "application/json")
		r, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("device flow: %w", err)
		}
		switch r.StatusCode {
		case http.StatusOK:
			var ok struct {
				APIToken string `json:"apiToken"`
			}
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&ok); err != nil ||
				!strings.HasPrefix(ok.APIToken, "pagt_") {
				return "", errors.New("unexpected device-flow token response")
			}
			fmt.Println(" done")
			return ok.APIToken, nil
		case http.StatusUnauthorized:
			var e struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			_ = json.NewDecoder(r.Body).Decode(&e)
			r.Body.Close()
			switch e.Error.Code {
			case "authorization_pending":
				pending++
				if pending%3 == 0 {
					fmt.Print(".")
				}
				// The server already waited its poll window; a short
				// local pause keeps the provider's rate limits happy.
				time.Sleep(2 * time.Second)
				continue
			case "device_code_invalid", "device_code_expired":
				fmt.Println()
				return "", fmt.Errorf("device flow: %s — start again", e.Error.Code)
			default:
				fmt.Println()
				return "", errors.New("device flow: authorization pending (unknown server response)")
			}
		default:
			raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			r.Body.Close()
			return "", fmt.Errorf("device flow: http %d: %s", r.StatusCode, raw)
		}
	}
	fmt.Println()
	return "", errors.New("timed out waiting for browser authorization")
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
