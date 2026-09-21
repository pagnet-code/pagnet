package main

// The principal-actor CLI surface (plan §9 / spec §28-29).
//
// Some control-plane routes are PRINCIPAL-only by design, and it is the
// server that says so:
//
//   - POST /networks/{id}/invocations refuses a user actor with 400
//     "invocations are made by principals (use a principal credential)"
//     (api_invocations.go) — an invocation is one principal calling another,
//     and the record's caller must be a principal.
//   - GET/POST /networks/{id}/subscriptions answer a user actor 404
//     (api_subscriptions.go): a subscription is the subscriber's own row, and
//     the SDK is the subscription manager.
//
// A signed-in human therefore cannot drive either surface with the bearer
// `pagnet login` stores. The principal's own endpoint credential (pgn_epd_)
// can — the same credential the Go SDK already runs services and agents with.
// This file is the ONE place that turns "act as a principal" into a bearer:
//
//	--credential <pgn_epd_...>       the explicit secret (mirrors --token)
//	$PAGNET_CREDENTIAL               the SDK's documented deployment path
//	<state-dir>/principals/<id>/credential   the endpoint credential the SDK
//	                                           already stored on this host
//
// The credential is proven LOCALLY (prefix + the server's positional shape)
// before any round trip, so a pasted Pagnet Token never reaches a route that
// would answer with a confusing 401/404, and the secret itself is never
// echoed. Authorization stays server-side and authority-based: the CLI's
// prefix knowledge routes the human to the right credential, it never decides
// access (the same rule auth_common.go applies to user credentials).

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pagnet-code/pagnet/sdk"
)

// principalActorOptions is the --credential / --as pair shared by every
// principal-actor command, so the two surfaces word and resolve it the same
// way. It is a per-command flag group (not a root persistent flag): the
// principal surfaces are these commands, and a global flag would advertise a
// credential the other half of the CLI cannot use.
type principalActorOptions struct {
	credential string
	as         string
}

func (p *principalActorOptions) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&p.credential, "credential", "",
		"act as the agent or service with its endpoint credential ("+tokenPrefixEndpoint+"...; falls back to $"+sdk.EnvCredential+
			", then to the endpoint credential this host stored)")
	cmd.Flags().StringVar(&p.as, "as", "",
		"agent or service id whose stored endpoint credential to use (default: the only one this host holds)")
}

// newPrincipalCLI builds the CLI context for a PRINCIPAL actor: the same
// state/server/URL resolution as newCLI, with the bearer being the principal's
// endpoint credential instead of the signed-in user's. No user sign-in runs
// and no reauth loop is armed — a rejected principal credential is reported,
// never silently "fixed" by signing a human in (who could not use the route
// anyway).
func newPrincipalCLI(stateDirOverride string, opts principalActorOptions) (*cliCtx, error) {
	c, err := newCLIContext(stateDirOverride)
	if err != nil {
		return nil, err
	}
	cred, err := c.resolvePrincipalCredential(opts)
	if err != nil {
		return nil, err
	}
	c.token = cred
	c.principal = true
	return c, nil
}

// resolvePrincipalCredential picks the endpoint credential to act with and
// proves its shape locally. Precedence: --credential, then $PAGNET_CREDENTIAL,
// then the credential this host's principal store holds for --as — or the only
// one it holds, which is the same "the only candidate wins, an ambiguous set
// is a choice you must make" rule resolveNetwork applies.
func (c *cliCtx) resolvePrincipalCredential(opts principalActorOptions) (string, error) {
	explicit := opts.credential
	if explicit == "" {
		explicit = os.Getenv(sdk.EnvCredential)
	}
	if explicit != "" {
		if err := validateEndpointCredential(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}

	// The SDK's own state dir when it is set (a deployed service's principal
	// store is not necessarily the daemon's), else this CLI's state dir.
	storeDir := os.Getenv(sdk.EnvStateDir)
	if storeDir == "" {
		storeDir = c.stateDir
	}
	stored, storeErr := sdk.StoredPrincipalIDs(storeDir)

	if opts.as != "" {
		cred, err := sdk.StoredCredential(storeDir, opts.as)
		if err != nil {
			return "", err
		}
		if cred == "" {
			return "", fmt.Errorf("no endpoint credential is stored here for %s (%s) — pass one with --credential or $%s",
				opts.as, storedListPhrase(stored, storeErr), sdk.EnvCredential)
		}
		if err := validateEndpointCredential(cred); err != nil {
			return "", err
		}
		return cred, nil
	}

	if storeErr != nil {
		return "", storeErr
	}
	switch len(stored) {
	case 0:
		return "", noPrincipalCredentialError(storeDir)
	case 1:
		cred, err := sdk.StoredCredential(storeDir, stored[0])
		if err != nil {
			return "", err
		}
		if cred == "" {
			return "", noPrincipalCredentialError(storeDir)
		}
		if err := validateEndpointCredential(cred); err != nil {
			return "", err
		}
		return cred, nil
	default:
		return "", fmt.Errorf("this host holds endpoint credentials for %d agents or services (%s) — choose one with --as <id>, or pass --credential",
			len(stored), strings.Join(stored, ", "))
	}
}

// storedListPhrase names the agents/services that DO have a stored credential,
// for the "--as matched nothing" message; an unreadable store is said, not
// silently reported as empty.
func storedListPhrase(stored []string, storeErr error) string {
	if storeErr != nil {
		return "the local credential store could not be read: " + storeErr.Error()
	}
	if len(stored) == 0 {
		return "this host holds none at all"
	}
	return "this host holds them for: " + strings.Join(stored, ", ")
}

// errNoPrincipalCredential marks the ONE resolution failure worth falling
// back on: "this host holds no endpoint credential at all". A caller that can
// still act with the user bearer does so and lets the control plane answer
// (its refusal is the message the operator needs). A malformed credential, an
// ambiguous store, or an --as that matches nothing is NOT this error — those
// are actionable and are surfaced as-is, never papered over with a bearer that
// cannot work.
var errNoPrincipalCredential = errors.New("no agent or service credential is available")

// noPrincipalCredentialError is the product text for "nothing on this host can
// make this call". It names the command that produces the credential and never
// suggests the human credential that cannot work here.
func noPrincipalCredentialError(storeDir string) error {
	return fmt.Errorf("%w — invocations and subscriptions are made by an agent or a service, "+
		"never by the signed-in user. Create the endpoint credential with `pagnet service credential create <service>` "+
		"(or `pagnet agent credential create <agent>`), then pass it with --credential or $%s "+
		"(this host stores credentials under %s/principals/)", errNoPrincipalCredential, sdk.EnvCredential, storeDir)
}

// validateEndpointCredential proves a bearer is a durable principal endpoint
// credential BEFORE any round trip (the same local-format discipline as
// parsePagnetTokenFormat). It names what was actually handed over so the fix
// is obvious, and it never echoes the secret — a pasted credential may be a
// live secret.
func validateEndpointCredential(bearer string) error {
	if strings.HasPrefix(bearer, tokenPrefixEndpoint) {
		if err := checkTokenShape(bearer[len(tokenPrefixEndpoint):]); err != nil {
			return fmt.Errorf("malformed endpoint credential (%s...): %v", tokenPrefixEndpoint, err)
		}
		return nil
	}
	switch verifiedCredentialKind(bearer) {
	case credentialKindAccount, credentialKindAccess, credentialKindAPI:
		return fmt.Errorf("that is %s — a human credential, and this call is made by an agent or a service, "+
			"never by the signed-in user. Pass that agent's or service's endpoint credential (%s...), printed once by "+
			"`pagnet service credential create <service>` or `pagnet agent credential create <agent>`",
			credentialClassLabel(verifiedCredentialKind(bearer)), tokenPrefixEndpoint)
	}
	if strings.HasPrefix(bearer, tokenPrefixPrincipalActivation) {
		return fmt.Errorf("that is the one-time activation credential (%s...): it is consumed by the endpoint's first connect, "+
			"which exchanges it for the durable endpoint credential. Pass the endpoint credential (%s...) instead, or create a "+
			"fresh one with `pagnet service credential create <service>`", tokenPrefixPrincipalActivation, tokenPrefixEndpoint)
	}
	return fmt.Errorf("not an agent or service endpoint credential: expected %s<lookup-id>_<secret>. Create one with "+
		"`pagnet service credential create <service>` (or `pagnet agent credential create <agent>`)", tokenPrefixEndpoint)
}

// --- the two one-sided answers these surfaces produce -------------------------

// principalActorRequiredPhrase is the control plane's own discriminator for a
// human caller on the invocation route (api_invocations.go). It is matched on
// the message because the response CODE is the generic bad_request — the one
// case where the server's prose is the contract, so it is quoted exactly.
const principalActorRequiredPhrase = "invocations are made by principals"

// userCallerFailure renders the control plane's refusal of a HUMAN caller as
// product text. Any other failure is returned untouched: a 404, a validation
// message, or a network error is information the operator needs, and
// rewriting it into prose would hide the reason (auth_common.go's rule for
// untranslated failures).
func userCallerFailure(err error) error {
	var hf *httpFailure
	if err == nil || !errors.As(err, &hf) {
		return err
	}
	if hf.status != http.StatusBadRequest || !strings.Contains(hf.body, principalActorRequiredPhrase) {
		return err
	}
	return fmt.Errorf("the control plane does not let a signed-in user invoke a capability — an invocation is one agent or "+
		"service calling another, so it must be made as one. Run this as the agent or service that owns the call: "+
		"--credential <%s...> (or $%s). The endpoint credential is printed once by "+
		"`pagnet service credential create <service>` or `pagnet agent credential create <agent>`",
		tokenPrefixEndpoint, sdk.EnvCredential)
}

// principalCredentialFailure renders a REJECTED endpoint credential as product
// text. The generic 401 path in cliCtx.do appends "run `pagnet login` or set
// --token", which is wrong advice on this surface (a human bearer cannot use
// the route at all), so the whole error is replaced rather than wrapped. Every
// other failure — a 403 network_scope, a 404, a validation message — passes
// through with the server's own reason intact.
func principalCredentialFailure(err error) error {
	var hf *httpFailure
	if err == nil || !errors.As(err, &hf) {
		return err
	}
	if hf.status != http.StatusUnauthorized && !authErrCodes[hf.code] {
		return err
	}
	return fmt.Errorf("the control plane did not accept this endpoint credential — it may have been revoked, expired, or " +
		"replaced. Create a fresh one with `pagnet service credential create <service>` (or `pagnet agent credential create <agent>`)")
}
