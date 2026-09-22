package main

// The ONE common user-auth function: token-first paste, reused by
// `pagnet login` and first-run `pagnet serve` / `pagnet -d` / `pagnet
// enroll`. A valid stored credential is reused without a prompt; otherwise
// the hidden token-first paste runs (interactive) or the command fails
// cleanly (non-interactive — never a browser, never a hang). The raw root
// token is exchanged once and never persisted.
//
// The second half of this file is the credential-class error surface (plan §7,
// the 2026-09-20 `pagnet serve` incident): the known control-plane auth
// failures translate into product text, and a wrong-class credential
// re-prompts a human instead of dumping a server body. Authorization itself
// stays server-side and authority-based — the CLI's prefix knowledge routes
// the human to the right credential, it never decides access.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// maxAuthReprompts bounds the wrong-credential re-prompt loop: the human gets
// a bounded number of fresh pastes, then the CLI stops and reports the same
// product text (never an infinite prompt loop, never a silent give-up).
const maxAuthReprompts = 2

// pagnetTokenPath is where a human gets the credential `pagnet` signs in with
// (plan §7 / spec §23-24 copy).
const pagnetTokenPath = "Settings → Security → Pagnet Token"

// authenticateUser returns a valid user credential for (account, server):
// the stored credential when valid (reuse — no prompt), else the token-first
// paste (interactive), else a clean failure (non-interactive / no TTY).
func authenticateUser(stateDir, account, server string, interactive bool) (string, error) {
	return authenticateUserFresh(stateDir, account, server, interactive, false)
}

// authenticateUserFresh is the shared paste path. fresh ignores the stored
// credential: the caller just told the human that what is stored is the wrong
// class, so reusing it would return the very credential being replaced.
func authenticateUserFresh(stateDir, account, server string, interactive, fresh bool) (string, error) {
	base := strings.TrimSuffix(server, "/") + "/"
	client := &http.Client{Timeout: 60 * time.Second}
	// The credential slot is the ACCOUNT's config dir — the one `pagnet login`
	// writes, `pagnet status` reads, and loginWithPastedToken documents. The
	// machine dir is not a fallback: the one-time account migration moves the
	// legacy flat token out of it, so reading the root would miss every
	// credential whenever the OS keyring is unavailable.
	accDir := accountConfigDir(stateDir, account)
	// 1. Reuse the stored credential (no prompt).
	if !fresh {
		if tok := loadUserToken(accDir, account, server); tok != "" {
			if ok, _ := bearerMe(client, base, tok); ok {
				return tok, nil
			}
			// Stored credential invalid (revoked/expired): fall through to a
			// fresh paste.
		}
	}
	if !interactive {
		return "", errors.New("not signed in — run `pagnet login` (or pass --token / $PAGNET_TOKEN); --non-interactive never prompts")
	}
	// 2. Token-first paste (hidden).
	pasted, err := askPagnetTokenFn("Pagnet Token (paste, hidden): ")
	if err != nil {
		return "", err
	}
	if pasted == "" {
		return "", errors.New("no token entered")
	}
	if _, err := loginWithPastedToken(accDir, account, server, client, pasted); err != nil {
		return "", err
	}
	tok := loadUserToken(accDir, account, server)
	if tok == "" {
		return "", errors.New("login did not store a credential")
	}
	return tok, nil
}

// userCredentialForServe returns the user bearer for first-run serve /
// enroll. --token / $PAGNET_TOKEN goes through the SAME paste-login path as an
// interactive paste — local class check, one exchange, verified-kind
// recording — so a root credential is never persisted raw (plan §7). The
// short-circuit used to validate and store the pasted value itself, which put
// an unreduced root or delegated token in the account's config and recorded no
// class for it at all.
func userCredentialForServe(stateDir, account, server string) (string, error) {
	return userCredentialForServeFresh(stateDir, account, server, false)
}

// userCredentialForServeFresh is userCredentialForServe with the option to
// ignore the stored credential: a caller that just told the human the stored
// one is the wrong class must not hand it straight back.
//
// A --token / $PAGNET_TOKEN bearer is the operator's explicit input, so
// "fresh" cannot replace it — the retry loop checks that separately rather
// than silently preferring a paste over an explicit flag.
func userCredentialForServeFresh(stateDir, account, server string, fresh bool) (string, error) {
	if userToken == "" {
		return authenticateUserFresh(stateDir, account, server, interactiveMode(), fresh)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	accDir := accountConfigDir(stateDir, account)
	if _, err := loginWithPastedToken(accDir, account, server, client, userToken); err != nil {
		return "", err
	}
	tok := loadUserToken(accDir, account, server)
	if tok == "" {
		return "", errors.New("login did not store a credential")
	}
	return tok, nil
}

// --- the credential-class error surface (plan §7) ------------------------------

// credentialClassError is the product translation of "the credential this
// operation needs is not the credential in hand". It says what to do instead
// of showing a server error body, and it is re-promptable: a human holding a
// different credential can fix it by pasting that one.
type credentialClassError struct {
	// Found names the class actually in hand ("an Access Token").
	Found string
	// Why states the operation's requirement in product words.
	Why string
}

func (e *credentialClassError) Error() string {
	return fmt.Sprintf("This is %s. Use your Pagnet Token (%s). %s",
		e.Found, pagnetTokenPath, e.Why)
}

// Repromptable reports that pasting a different credential can fix this.
func (e *credentialClassError) Repromptable() bool { return true }

// authFailure is a control-plane auth failure translated for a human.
type authFailure struct {
	// Translated is true only when a KNOWN credential failure was rendered
	// into product text. An unrecognized failure comes back untranslated so
	// the caller keeps its own error: a 404 not_found or a 400 validation
	// message is information the operator needs, and rewriting it into
	// generic prose would hide the reason behind a wall of prose.
	Translated bool
	// Reprompt is true when pasting a different credential can fix it.
	Reprompt bool
	// Err is the product text. It never contains the server body.
	Err error
}

// httpFailure is a control-plane HTTP failure that keeps the pieces the auth
// translator needs (status + error code) apart from the human-facing text.
// Its Error() renders exactly what the CLI rendered before this type existed,
// so wrapping a call site changes no message — it only makes the code
// readable. The body is never printed by a translated path.
type httpFailure struct {
	status int
	code   string
	body   string
}

func (e *httpFailure) Error() string { return fmt.Sprintf("http %d: %s", e.status, e.body) }

// errCodeAccountAuthority is the server's account-authority gate
// (governance §56): the operation needs a full-account credential and a
// delegated one was presented.
const errCodeAccountAuthority = "account_authority_required"

// errCodeUserIdentityRequired is the principal-credential management gate
// (server 1052f65): an agent/service credential tried to use a user-only
// management surface. It is an AUTHORIZATION failure on a perfectly good
// credential — the credential is right, the surface is wrong — so it is
// translated but never re-prompted.
const errCodeUserIdentityRequired = "user_identity_required"

// errCodeInvalidCredentials is the server's generic authentication failure
// (governance §60: no enumeration).
const errCodeInvalidCredentials = "invalid_credentials"

// authErrCodes are the credential/auth failures the CLI has product text for.
// Everything else the control plane reports is about the REQUEST, not the
// credential, and keeps the server's own message.
var authErrCodes = map[string]bool{
	errCodeAccountAuthority:     true,
	errCodeUserIdentityRequired: true,
	errCodeInvalidCredentials:   true,
	"unauthorized":              true,
	"authentication_required":   true,
}

// translateAuthFailure renders the KNOWN control-plane credential failures as
// product text (plan §7: no raw JSON to humans). Anything else is returned
// untranslated — reported exactly as the call site produced it, never
// swallowed and never rewritten into a generic sentence.
func translateAuthFailure(err error, class string) authFailure {
	var hf *httpFailure
	if err == nil || !errors.As(err, &hf) || !authErrCodes[hf.code] {
		return authFailure{Err: err}
	}
	switch hf.code {
	case errCodeAccountAuthority:
		// The incident's exact failure. A delegated credential cannot mint
		// credentials (governance §33/§56), so name the class in hand and
		// point at the credential that works.
		if class == credentialKindAccess {
			return authFailure{
				Translated: true,
				Reprompt:   true,
				Err: &credentialClassError{
					Found: credentialClassLabel(class),
					Why: "connecting a host needs your account's own credential. " +
						"Access Tokens are restricted tokens for scripts and API integrations.",
				},
			}
		}
		// The bearer proves no class the CLI can read (a derived client
		// credential): say what happened, invent nothing.
		return authFailure{Translated: true, Reprompt: true, Err: fmt.Errorf(
			"the stored client credential does not carry account authority, so it cannot connect this host. "+
				"Paste your Pagnet Token again (%s), or create a new one there.", pagnetTokenPath)}
	case errCodeUserIdentityRequired:
		// Right credential, wrong surface — re-pasting cannot help, so this
		// exits with the explanation.
		return authFailure{Translated: true, Err: fmt.Errorf(
			"that is an agent or service credential: it authenticates to the network, not to the console API. "+
				"Manage credentials as a user — run `pagnet login` with your Pagnet Token (%s).", pagnetTokenPath)}
	default: // unauthorized / invalid_credentials / authentication_required
		return authFailure{Translated: true, Reprompt: true, Err: fmt.Errorf(
			"the control plane did not accept your Pagnet Token — it may have been revoked or replaced. "+
				"Paste it again, or create a new one (%s).", pagnetTokenPath)}
	}
}

// authError translates a control-plane credential failure from a REST call,
// and passes every other failure through untouched.
func (c *cliCtx) authError(err error) error {
	if err == nil {
		return nil
	}
	f := translateAuthFailure(err, credentialClassOf(accountConfigDir(c.stateDir, c.account), c.token))
	if !f.Translated {
		return err
	}
	return f.Err
}

// credentialClassOf reports the class of a bearer the CLI holds: what its own
// prefix proves first, then the class recorded when it was stored (a derived
// client credential carries no class the client can read), then "client".
func credentialClassOf(stateDir, bearer string) string {
	if k := verifiedCredentialKind(bearer); k != "" {
		return k
	}
	if k := storedCredentialKind(stateDir); k != "" {
		return k
	}
	return credentialKindClient
}

// storedCredentialKind reads the recorded class of the account's stored user
// credential from its config ("" when nothing is recorded). stateDir is the
// account's config dir — the same dir loadUserTokenFile reads.
func storedCredentialKind(stateDir string) string {
	b, err := os.ReadFile(filepath.Join(stateDir, "config.yaml"))
	if err != nil {
		return ""
	}
	var fc struct {
		CredentialKind string `yaml:"credentialKind"`
	}
	if yaml.Unmarshal(b, &fc) != nil {
		return ""
	}
	return fc.CredentialKind
}

// apiErrorCode extracts the {"error":{"code",...}} discriminator from a
// control-plane error body ("" when the body is not that shape).
func apiErrorCode(raw []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return ""
	}
	return e.Error.Code
}

// readFailureBody reads an error body for the httpFailure carrier. It is
// bounded and is only ever rendered by non-auth call sites.
func readFailureBody(resp *http.Response) string {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(raw)
}
