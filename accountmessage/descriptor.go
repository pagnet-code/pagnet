// Package accountmessage defines the frozen browser account message schema.
package accountmessage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"
)

const BrowserAccountDelegateSenderKind = "browser_account_delegate"

type Sender struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Descriptor's declaration order is the v1 cross-language canonical contract.
type Descriptor struct {
	V                        int    `json:"v"`
	MessageID                string `json:"messageId"`
	TenantID                 string `json:"tenantId"`
	OwnerUserID              string `json:"ownerUserId"`
	ConnectionID             string `json:"connectionId"`
	Sender                   Sender `json:"sender"`
	NetworkID                string `json:"networkId"`
	TargetPrincipalID        string `json:"targetPrincipalId"`
	HostID                   string `json:"hostId"`
	TargetDefinitionID       string `json:"targetDefinitionId"`
	TargetInstanceID         string `json:"targetInstanceId"`
	ConsentID                string `json:"consentId"`
	ResourceID               string `json:"resourceId"`
	IdentityIncarnationID    string `json:"identityIncarnationId"`
	DesiredRevision          string `json:"desiredRevision"`
	RunnerID                 string `json:"runnerId"`
	RunnerConnectedAt        string `json:"runnerConnectedAt"`
	ServerInstanceID         string `json:"serverInstanceId"`
	HostConnectionGeneration string `json:"hostConnectionGeneration"`
	KeyHolderID              string `json:"keyHolderId"`
	EpochID                  string `json:"epochId"`
	OfferID                  string `json:"offerId"`
	ReadinessGeneration      string `json:"readinessGeneration"`
	OfferDigest              string `json:"offerDigest"`
	SubscriptionID           string `json:"subscriptionId"`
	SubscriptionVersion      string `json:"subscriptionVersion"`
	CreatedAt                string `json:"createdAt"`
	ExpiresAt                string `json:"expiresAt"`
}

func canonical(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		panic("account message canonical encoding")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func validDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (d Descriptor) CanonicalJSON() []byte { return canonical(d) }
func (d Descriptor) BindingDigest() string {
	h := sha256.Sum256(d.CanonicalJSON())
	return hex.EncodeToString(h[:])
}
func (d Descriptor) Validate() error {
	invalid := errors.New("invalid account message descriptor")
	if d.V != 1 || d.Sender.Kind != BrowserAccountDelegateSenderKind || !validDigest(d.OfferDigest) {
		return invalid
	}
	for _, s := range []string{d.MessageID, d.TenantID, d.OwnerUserID, d.ConnectionID, d.Sender.ID, d.NetworkID, d.TargetPrincipalID, d.HostID, d.TargetDefinitionID, d.TargetInstanceID, d.ConsentID, d.ResourceID, d.IdentityIncarnationID, d.RunnerID, d.ServerInstanceID, d.KeyHolderID, d.EpochID, d.OfferID, d.SubscriptionID} {
		if len(s) < 1 || len(s) > 128 || !utf8.ValidString(s) {
			return invalid
		}
	}
	for _, s := range []string{d.DesiredRevision, d.HostConnectionGeneration, d.ReadinessGeneration} {
		n, e := strconv.ParseInt(s, 10, 64)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
			return invalid
		}
	}
	n, e := strconv.ParseUint(d.SubscriptionVersion, 10, 64)
	if e != nil || n == 0 || strconv.FormatUint(n, 10) != d.SubscriptionVersion {
		return invalid
	}
	for _, s := range []string{d.RunnerConnectedAt, d.CreatedAt, d.ExpiresAt} {
		t, e := time.Parse(time.RFC3339Nano, s)
		if e != nil || t.UTC().Format(time.RFC3339Nano) != s {
			return invalid
		}
	}
	created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
	expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
	if !expires.After(created) || expires.Sub(created) > time.Minute {
		return invalid
	}
	return nil
}
