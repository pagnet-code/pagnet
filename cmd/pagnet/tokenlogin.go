package main

// AUTH-3 — token-first paste login + derived client credential
// (docs/2026-09-15_token-first-auth.md §11-13/§35,
// docs/2026-09-15_access-token-governance.md §7-8/§17-19).
//
// The interactive path of `pagnet login` is the hidden paste prompt: the
// user pastes a Pagnet Token (Account Token pgn_acc_v1_…, Access Token
// pgn_pat_v1_…, or a legacy API token pagt_…) with echo off — the token
// never lives in argv, shell history, or process listings. The format is
// validated locally BEFORE any round-trip; a malformed paste names the
// expected prefixes and never leaves the machine.
//
// An Account/Access Token is exchanged ONCE for a revocable derived client
// credential (governance §17-18: "server creates derived client/session
// credential"); only the derived credential is stored (keyring-preferred,
// 0600 file fallback — governance §19) and sent on later requests. The root
// Account Token is never persisted and never re-sent. A legacy pagt_ token
// keeps its current semantics (dual support): it is already a long-lived
// revocable API token, so it is verified against /auth/me and stored as-is.
//
// The exchange endpoint path and response schema are NOT fixed by the spec
// (governance §77 names only the operation "exchange Pagnet Token for
// session"); the wire contract below is the client's single, centralized
// assumption — see the AUTH-3 report for the coordinated AUTH-1 contract.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/99designs/keyring"
	"golang.org/x/term"
)

// Credential classes, keyed by the spec's token prefixes (governance §7-8).
const (
	tokenPrefixAccount = "pgn_acc_v1_"
	tokenPrefixAccess  = "pgn_pat_v1_"
	tokenPrefixLegacy  = "pagt_"
	// tokenPrefixPrincipalActivation / tokenPrefixEndpoint are the PRINCIPAL
	// credentials (governance §7-8): the one-time activation credential and
	// the durable endpoint credential. They authenticate AS an agent or a
	// service — never as the human who created them — which is what the
	// principal-only surfaces (invocations, subscriptions) require.
	tokenPrefixPrincipalActivation = "pgn_act_v1_"
	tokenPrefixEndpoint            = "pgn_epd_v1_"

	credentialKindAccount = "account"
	credentialKindAccess  = "access"
	credentialKindAPI     = "api" // legacy pagt_ (pre-AUTH-1 API token)
	// credentialKindClient is a derived client credential whose own prefix
	// proves no class the CLI can read — only the server knows what it can
	// do. It is recorded rather than guessed (plan §7).
	credentialKindClient = "client"
)

// verifiedCredentialKind is the credential class the bearer's OWN prefix
// proves ("" when its prefix proves nothing). It is the authority for what
// the CLI stores: a credential may be described by where it came from (the
// pasted root), but the CLI may never claim a class the bearer contradicts.
// That is the mislabeled state that broke `pagnet serve` — a pgn_pat_ sitting
// in config.yaml under credentialKind: account hid the mismatch locally
// while the server answered 403 account_authority_required (plan §7).
func verifiedCredentialKind(bearer string) string {
	switch {
	case strings.HasPrefix(bearer, tokenPrefixAccount):
		return credentialKindAccount
	case strings.HasPrefix(bearer, tokenPrefixAccess):
		return credentialKindAccess
	case strings.HasPrefix(bearer, tokenPrefixLegacy):
		return credentialKindAPI
	default:
		return ""
	}
}

// credentialClassLabel names a credential class the way the human surface
// does (plan §7: product text, never a wire value).
func credentialClassLabel(kind string) string {
	switch kind {
	case credentialKindAccount:
		return "your Pagnet Token"
	case credentialKindAccess:
		return "an Access Token"
	case credentialKindAPI:
		return "a legacy API token"
	case credentialKindClient:
		return "a derived client credential"
	default:
		return "a restricted credential"
	}
}

// tokenExchangePath is the token-login exchange endpoint (POST, JSON
// {"token": ...} → derived client credential). The spec authorizes the
// operation (token-first §12 "the CLI exchanges the Pagnet Token for a
// client/session credential"; governance §17, §77, §100 Phase G) but not
// the path — AUTH-3's single wire assumption, flagged for AUTH-1 alignment.
const tokenExchangePath = "api/v1/auth/token/exchange"

// --- local format validation (no server round-trip on a bad paste) -----------

// parsePagnetTokenFormat classifies a pasted credential by its prefix and
// validates its shape locally. Wrong prefix / malformed shape returns a
// clean error naming the expected prefixes — the pasted material is never
// echoed back (it may be a live secret) and never sent anywhere.
func parsePagnetTokenFormat(s string) (string, error) {
	switch {
	case strings.HasPrefix(s, tokenPrefixAccount):
		if err := checkTokenShape(s[len(tokenPrefixAccount):]); err != nil {
			return "", fmt.Errorf("malformed Account Token (%s...): %v", tokenPrefixAccount, err)
		}
		return credentialKindAccount, nil
	case strings.HasPrefix(s, tokenPrefixAccess):
		if err := checkTokenShape(s[len(tokenPrefixAccess):]); err != nil {
			return "", fmt.Errorf("malformed Access Token (%s...): %v", tokenPrefixAccess, err)
		}
		return credentialKindAccess, nil
	case strings.HasPrefix(s, tokenPrefixLegacy):
		// Legacy dual support: the client has always asserted the pagt_
		// prefix; its internal shape is the server's business.
		if len(s) <= len(tokenPrefixLegacy) {
			return "", errors.New("malformed legacy API token: no secret after the prefix")
		}
		return credentialKindAPI, nil
	default:
		return "", fmt.Errorf("unrecognized Pagnet Token — expected an Account Token (%s<lookup-id>_<secret>), an Access Token (%s<lookup-id>_<secret>), or a legacy API token (%s...)",
			tokenPrefixAccount, tokenPrefixAccess, tokenPrefixLegacy)
	}
}

// checkTokenShape validates the "<lookup-id>_<secret>" tail of a pgn_ token
// (governance §7-8). POSITIONAL, exactly like the server's central parser
// (pagnet-server internal/credentials) and the web's local check
// (packages/auth token-format): a 12-byte lookup id encodes to 16 base64url
// chars, then "_", then a 32-byte secret = 43 chars. base64url itself
// contains "_", so splitting on the first "_" would misparse valid tokens
// whose lookup id contains "_" — the lengths are fixed by the version
// carried in the prefix (governance §7-8, invariant 3).
func checkTokenShape(rest string) error {
	if len(rest) != 16+1+43 || rest[16] != '_' {
		return errors.New("expected a 16-char lookup id, \"_\", and a 43-char secret (base64url)")
	}
	if !isBase64URL(rest[:16]) || !isBase64URL(rest[17:]) {
		return errors.New("expected base64url characters (A-Za-z0-9-_)")
	}
	return nil
}

func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' {
			continue
		}
		return false
	}
	return len(s) > 0
}

// --- the hidden paste prompt --------------------------------------------------

// askPagnetToken reads the pasted Pagnet Token with echo off (governance
// §17). It NEVER reads the token from a non-terminal: scripted use passes
// --token / $PAGNET_TOKEN instead (documented as less safe — shell history
// and process listings can expose it).
func askPagnetToken(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("no interactive terminal for the token prompt — run `pagnet login` in a terminal, or pass the token with --token / $PAGNET_TOKEN (scripted; exposes it to shell history and process listings)")
	}
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// askPagnetTokenFn is a test seam for askPagnetToken (the hidden prompt).
var askPagnetTokenFn = askPagnetToken

// --- the exchange: root/delegated token → derived client credential -----------

// tokenExchangeResponse is the client's read of the exchange response. Only
// the derived credential is required; the restriction metadata (role,
// network scope, expiry, provenance) is optional — whatever the server
// returns is stored for honest UX and never invented here.
type tokenExchangeResponse struct {
	// Credential is the derived client credential; Token is the documented
	// alias (the spec leaves the field name open — AUTH-1 alignment note).
	Credential     string   `json:"credential"`
	Token          string   `json:"token"`
	Role           string   `json:"role"`
	NetworkScope   string   `json:"networkScope"`
	Networks       []string `json:"networks"`
	ExpiresAt      string   `json:"expiresAt"`
	OrganizationID string   `json:"organizationId"`
	SourceID       string   `json:"sourceId"`
}

// derived returns the client credential the CLI stores and re-sends.
func (r *tokenExchangeResponse) derived() string {
	if r.Credential != "" {
		return r.Credential
	}
	return r.Token
}

// exchangePagnetToken posts the pasted credential ONCE and returns the
// derived client credential + its restriction metadata. Failures are
// generic (governance §60): the token is never echoed, and the client does
// not distinguish "unknown" from "revoked".
func exchangePagnetToken(client *http.Client, base, token string) (*tokenExchangeResponse, error) {
	body, _ := json.Marshal(map[string]string{"token": token})
	resp, err := client.Post(base+tokenExchangePath, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("token login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp, "token login failed")
	}
	var out tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, errors.New("token login: unexpected exchange response")
	}
	if out.derived() == "" {
		return nil, errors.New("token login: the exchange returned no client credential")
	}
	return &out, nil
}

// --- the paste-login flow ------------------------------------------------------

// pastedLoginResult is the outcome of a successful paste login: the stored
// credential class (from the PREFIX — the client's own classification, not
// a server claim), the server-reported restriction metadata (may be empty),
// and the honest success line for the terminal.
type pastedLoginResult struct {
	Kind           string
	Role           string
	NetworkScope   string
	Networks       []string
	ExpiresAt      string
	OrganizationID string
	SourceID       string
	Summary        string
}

// loginWithPastedToken runs the paste/scripted login for one credential:
// local format check → (legacy: /auth/me verify | pgn_: one exchange for
// the derived credential) → store the bearer + non-secret metadata. The
// pasted root token is never persisted (governance §19) and never printed.
// stateDir is the account's config dir; account scopes the keyring key so
// two accounts on the same server keep separate credentials.
func loginWithPastedToken(stateDir, account, server string, client *http.Client, pasted string) (*pastedLoginResult, error) {
	pasted = strings.TrimSpace(pasted)
	base := strings.TrimSuffix(server, "/") + "/"
	kind, err := parsePagnetTokenFormat(pasted)
	if err != nil {
		return nil, err
	}
	res := &pastedLoginResult{Kind: kind}

	if kind == credentialKindAPI {
		// Legacy dual support: a pagt_ token is already a long-lived
		// revocable API token — verify it and keep using it as-is.
		ok, err := bearerMe(client, base, pasted)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("the control plane rejected that API token")
		}
		if err := saveCredential(stateDir, account, server, pasted, credentialMeta{Kind: kind, SourceKind: kind}); err != nil {
			return nil, err
		}
		res.Summary = "verified the legacy API token (pagt_…); it stays the CLI bearer."
		return res, nil
	}

	ex, err := exchangePagnetToken(client, base, pasted)
	if err != nil {
		return nil, err
	}
	// The stored bearer is the DERIVED credential, not the pasted root. Its
	// class is therefore whatever ITS own prefix proves; the root's class is
	// recorded separately as the provenance. Labelling a derived credential
	// with the root's class is exactly the mislabel that hid the incident
	// (plan §7), and saveCredential refuses it.
	meta := credentialMeta{
		SourceKind:     kind,
		Role:           ex.Role,
		NetworkScope:   ex.NetworkScope,
		Networks:       ex.Networks,
		ExpiresAt:      ex.ExpiresAt,
		OrganizationID: ex.OrganizationID,
		SourceID:       ex.SourceID,
	}
	if err := saveCredential(stateDir, account, server, ex.derived(), meta); err != nil {
		return nil, err
	}
	res.Role, res.NetworkScope, res.Networks = ex.Role, ex.NetworkScope, ex.Networks
	res.ExpiresAt, res.OrganizationID, res.SourceID = ex.ExpiresAt, ex.OrganizationID, ex.SourceID
	res.Summary = res.summary()
	return res, nil
}

// summary renders the honest success line: an Access Token session is
// labelled as limited, with the server-reported role/networks/expiry
// (governance §93: no fake capabilities, no confusion about scope).
func (r *pastedLoginResult) summary() string {
	if r.Kind == credentialKindAccess {
		var parts []string
		if r.Role != "" {
			parts = append(parts, "role: "+r.Role)
		}
		switch {
		case len(r.Networks) > 0:
			parts = append(parts, "networks: "+strings.Join(r.Networks, ", "))
		case r.NetworkScope != "":
			parts = append(parts, "networks: "+r.NetworkScope)
		}
		if r.ExpiresAt != "" {
			parts = append(parts, "expires: "+r.ExpiresAt)
		}
		if len(parts) == 0 {
			return "logged in with a limited access token."
		}
		return "logged in with a limited access token (" + strings.Join(parts, ", ") + ")."
	}
	return "logged in with your Account Token: the derived client credential is stored — the Account Token itself was not stored and is not sent with requests."
}

// --- storage of the derived credential + non-secret metadata -------------------

// credentialMeta is the non-secret description of the stored bearer, kept
// so later commands can render the account-vs-access distinction and the
// expiry (governance §18-19).
//
// Kind is the class of the BEARER being stored; SourceKind is the class of the
// credential it was derived from (the pasted root). saveCredential owns Kind —
// callers describe provenance, and the class is read off the material.
type credentialMeta struct {
	Kind           string
	SourceKind     string
	Role           string
	NetworkScope   string
	Networks       []string
	ExpiresAt      string
	OrganizationID string
	SourceID       string
}

// orNil maps an empty optional to nil so mergeConfigFile DELETES the key —
// a re-login must never leave the previous login's metadata behind.
func orNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (m credentialMeta) fileFields() map[string]any {
	var nets any
	if len(m.Networks) > 0 {
		nets = m.Networks
	}
	return map[string]any{
		"credentialKind":           orNil(m.Kind),
		"credentialSourceKind":     orNil(m.SourceKind),
		"credentialRole":           orNil(m.Role),
		"credentialNetworkScope":   orNil(m.NetworkScope),
		"credentialNetworks":       nets,
		"credentialExpiresAt":      orNil(m.ExpiresAt),
		"credentialOrganizationId": orNil(m.OrganizationID),
		"credentialSourceId":       orNil(m.SourceID),
	}
}

// saveCredential stores the CLI bearer (keyring-preferred, 0600 account
// config-file fallback — governance §19) plus its non-secret metadata,
// clearing the metadata keys the new login does not carry. stateDir is the
// account's config dir; account scopes the keyring key.
//
// The recorded credentialKind is always the class the stored bearer's own
// prefix proves. A caller that claims a different class is broken and fails
// loudly here: "a pgn_pat_ persisted under credentialKind: account" was the
// state that made `pagnet serve` fail with a 403 the local config described
// as an account login, and it is now unrepresentable (plan §7).
func saveCredential(stateDir, account, server, bearer string, meta credentialMeta) error {
	if verified := verifiedCredentialKind(bearer); verified != "" {
		if meta.Kind != "" && meta.Kind != verified {
			return fmt.Errorf("credential mismatch: the bearer being stored is %s, so it cannot be recorded as %s",
				credentialClassLabel(verified), credentialClassLabel(meta.Kind))
		}
		meta.Kind = verified
	} else if meta.Kind == "" {
		// A derived client credential carries no class its prefix proves;
		// the provenance (the class it was exchanged from) is the honest
		// label, and credentialKindClient is the fallback.
		meta.Kind = meta.SourceKind
		if meta.Kind == "" {
			meta.Kind = credentialKindClient
		}
	}
	fields := meta.fileFields()
	if server != "" {
		fields["serverUrl"] = strings.TrimSuffix(server, "/")
	}
	if kr, err := openKeyringFn(); err == nil {
		if err := kr.Set(keyring.Item{
			Key:   credentialKey(account, server),
			Data:  []byte(bearer),
			Label: "Pagnet client credential",
		}); err == nil {
			// Keyring holds the bearer: drop the file copy (a previous
			// fallback login may have left one there).
			fields["token"] = nil
			return mergeConfigFile(stateDir, fields)
		}
		// Keyring set failed: fall through to the file fallback.
	}
	fields["token"] = bearer
	return mergeConfigFile(stateDir, fields)
}
