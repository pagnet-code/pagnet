package sdk

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TextServiceInstallationProof consumes a host claim for the current service
// endpoint. Keep the same claim, generation and nonce for an explicit retry.
// Nonce is local secret material and must contain exactly 32 bytes.
type TextServiceInstallationProof struct {
	InstallationID string
	ClaimID        string
	Generation     int64
	Nonce          []byte `json:"-"`
}

// String redacts the local proof secret from ordinary diagnostic formatting.
func (p TextServiceInstallationProof) String() string {
	return fmt.Sprintf("TextServiceInstallationProof{InstallationID:%s ClaimID:%s Generation:%d Nonce:[REDACTED]}", p.InstallationID, p.ClaimID, p.Generation)
}

// GoString also redacts the secret when formatted with %#v.
func (p TextServiceInstallationProof) GoString() string { return p.String() }

// TextServiceReadiness contains installation metadata only, never a nonce or
// credential. Readiness is a server snapshot, not permission to dispatch work.
type TextServiceReadiness struct {
	InstallationID string     `json:"installationId"`
	Generation     int64      `json:"generation"`
	ClaimID        *string    `json:"claimId,omitempty"`
	ClaimExpiresAt *time.Time `json:"claimExpiresAt,omitempty"`
	Ready          bool       `json:"ready"`
}

// ProveTextServiceInstallation proves a host's installation claim using the
// current authenticated endpoint. It performs one request without retrying;
// callers may explicitly retry the exact proof after an ambiguous failure.
func (c *Client) ProveTextServiceInstallation(ctx context.Context, proof TextServiceInstallationProof) (TextServiceReadiness, error) {
	var out TextServiceReadiness
	if !projectUUID(proof.InstallationID, false) || !projectUUID(proof.ClaimID, false) || proof.Generation < 1 || len(proof.Nonce) != 32 {
		return out, errors.New("sdk: invalid text service installation proof")
	}
	if err := c.checkOpen(); err != nil {
		return out, err
	}
	endpoint := c.EndpointID()
	credential, _ := c.credential.Load().(string)
	if !c.connected.Load() || !projectUUID(endpoint, false) || !strings.HasPrefix(credential, "pgn_epd_v1_") || c.rest == nil || c.rest.http == nil {
		return out, errors.New("sdk: text service installation proof requires a connected endpoint credential")
	}
	body := struct {
		ClaimID    string `json:"claimId"`
		Generation int64  `json:"generation"`
		Nonce      string `json:"nonce"`
		EndpointID string `json:"endpointId"`
	}{proof.ClaimID, proof.Generation, base64.StdEncoding.EncodeToString(proof.Nonce), endpoint}
	// A proof is one request. In particular, 307/308 redirects must never
	// replay the nonce and bearer, even to another path on the same server.
	// Copy both clients so other SDK methods retain their redirect policy.
	rest := *c.rest
	transport := *rest.http
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	rest.http = &transport
	err := rest.do(ctx, http.MethodPost, "/sharing/text-services/installations/"+proof.InstallationID+"/prove", body, &out)
	if err != nil {
		// A server or transport error may echo the request. Never expose its body or
		// underlying error, which could contain a nonce or endpoint credential.
		if errors.Is(err, ErrCredentialDead) {
			return TextServiceReadiness{}, fmt.Errorf("%w: text service installation proof rejected", ErrCredentialDead)
		}
		var re *restError
		if errors.As(err, &re) {
			return TextServiceReadiness{}, &restError{status: re.status, body: "text service installation proof rejected"}
		}
		if ctx.Err() != nil {
			return TextServiceReadiness{}, ctx.Err()
		}
		return TextServiceReadiness{}, errors.New("sdk: text service installation proof request failed")
	}
	if out.InstallationID != proof.InstallationID || out.Generation != proof.Generation || out.ClaimID == nil || *out.ClaimID != proof.ClaimID {
		return TextServiceReadiness{}, errors.New("sdk: text service installation proof response binding mismatch")
	}
	return out, nil
}
