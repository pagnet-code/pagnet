package main

// The ONE common user-auth function: token-first paste, reused by
// `pagnet login` and first-run `pagnet serve` / `pagnet -d` / `pagnet
// enroll`. A valid stored credential is reused without a prompt; otherwise
// the hidden token-first paste runs (interactive) or the command fails
// cleanly (non-interactive — never a browser, never a hang). The raw root
// token is exchanged once and never persisted.

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// authenticateUser returns a valid user credential for (account, server):
// the stored credential when valid (reuse — no prompt), else the token-first
// paste (interactive), else a clean failure (non-interactive / no TTY).
func authenticateUser(stateDir, account, server string, interactive bool) (string, error) {
	base := strings.TrimSuffix(server, "/") + "/"
	client := &http.Client{Timeout: 60 * time.Second}
	// 1. Reuse the stored credential (no prompt).
	if tok := loadUserToken(stateDir, account, server); tok != "" {
		if ok, _ := bearerMe(client, base, tok); ok {
			return tok, nil
		}
		// Stored credential invalid (revoked/expired): fall through to a
		// fresh paste.
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
	if _, err := loginWithPastedToken(stateDir, account, server, client, pasted); err != nil {
		return "", err
	}
	tok := loadUserToken(stateDir, account, server)
	if tok == "" {
		return "", errors.New("login did not store a credential")
	}
	return tok, nil
}

// userCredentialForServe returns the user bearer for first-run serve /
// enroll: --token / $PAGNET_TOKEN (the short-circuit — validated and stored,
// no sign-in flow), else the common token-first auth function.
func userCredentialForServe(stateDir, account, server string) (string, error) {
	if userToken != "" {
		base := strings.TrimSuffix(server, "/") + "/"
		client := &http.Client{Timeout: 60 * time.Second}
		ok, err := bearerMe(client, base, userToken)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", errors.New("the server rejected the token")
		}
		if err := saveUserToken(stateDir, account, server, userToken); err != nil {
			return "", err
		}
		return userToken, nil
	}
	return authenticateUser(stateDir, account, server, interactiveMode())
}
