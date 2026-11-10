package transport

import (
	"encoding/hex"
	"errors"
	"github.com/pagnet-code/pagnet/domain"
	"time"
)

const AccountMessagingReadinessProtocol = "browser-account-messaging-readiness-v1"
const MsgAccountMessagingReadinessHello = "account.messaging.readiness.hello"
const MsgAccountMessagingReadinessOffer = "account.messaging.readiness.offer"
const MsgAccountMessagingReadinessAck = "account.messaging.readiness.ack"
const AccountMessagingReadinessMaxPayload = 4096

type AccountMessagingReadinessHelloPayload struct {
	V        int    `json:"v"`
	Protocol string `json:"protocol"`
}
type AccountMessagingReadinessOfferPayload struct {
	V        int                            `json:"v"`
	Protocol string                         `json:"protocol"`
	Route    AccountMessagingReadinessRoute `json:"route"`
}
type AccountMessagingReadinessAckPayload struct {
	V        int    `json:"v"`
	Protocol string `json:"protocol"`
	AccountMessagingReadinessAck
}

type AccountMessagingReadinessCandidate struct {
	ConnectionID      domain.ID `json:"connectionId"`
	NetworkID         domain.ID `json:"networkId"`
	TargetPrincipalID domain.ID `json:"targetPrincipalId"`
	HostID            domain.ID `json:"hostId"`
}
type AccountMessagingReadinessAck struct {
	AccountMessagingReadinessCandidate
	OfferID    domain.ID `json:"offerId"`
	Generation int64     `json:"generation"`
	Digest     string    `json:"digest"`
}

// This is handshake evidence only. LogicalSenderID has no principal,
// membership, credential, command, message, or dispatch authority.
type AccountMessagingReadinessRoute struct {
	AccountMessagingReadinessCandidate
	LogicalSenderID          domain.ID  `json:"logicalSenderId"`
	Generation               int64      `json:"generation"`
	ConsentID                domain.ID  `json:"consentId"`
	ResourceID               string     `json:"resourceId"`
	IdentityIncarnationID    string     `json:"identityIncarnationId"`
	DesiredRevision          int64      `json:"desiredRevision"`
	TargetDefinitionID       domain.ID  `json:"targetDefinitionId"`
	TargetInstanceID         domain.ID  `json:"targetInstanceId"`
	RunnerID                 domain.ID  `json:"runnerId"`
	RunnerConnectedAt        time.Time  `json:"runnerConnectedAt"`
	ServerInstanceID         string     `json:"serverInstanceId"`
	HostConnectionGeneration int64      `json:"hostConnectionGeneration"`
	KeyHolderID              domain.ID  `json:"keyHolderId"`
	EpochID                  string     `json:"epochId"`
	OfferID                  domain.ID  `json:"offerId"`
	Digest                   string     `json:"digest"`
	OfferedAt                time.Time  `json:"offeredAt"`
	OfferDeadline            time.Time  `json:"offerDeadline"`
	AckedAt                  *time.Time `json:"ackedAt,omitempty"`
	ExpiresAt                time.Time  `json:"expiresAt"`
	Status                   string     `json:"status"`
	MessagingAvailable       bool       `json:"messagingAvailable"`
}

// ParseAccountMessagingReadinessOffer accepts handshake evidence only; an ACK
// echoes this evidence and never establishes messaging or dispatch authority.
func ParseAccountMessagingReadinessOffer(raw []byte) (AccountMessagingReadinessRoute, error) {
	var p AccountMessagingReadinessOfferPayload
	invalid := errors.New("transport: invalid account messaging readiness offer")
	if len(raw) > AccountMessagingReadinessMaxPayload || DecodeOwnerTextConsolePayload(raw, &p) != nil || p.V != 1 || p.Protocol != AccountMessagingReadinessProtocol {
		return AccountMessagingReadinessRoute{}, invalid
	}
	r := p.Route
	for _, id := range []domain.ID{r.ConnectionID, r.NetworkID, r.TargetPrincipalID, r.HostID, r.LogicalSenderID, r.ConsentID, r.TargetDefinitionID, r.TargetInstanceID, r.RunnerID, r.KeyHolderID, r.OfferID, domain.ID(r.IdentityIncarnationID)} {
		parsed, err := domain.ParseID(id.String())
		if err != nil || parsed != id {
			return AccountMessagingReadinessRoute{}, invalid
		}
	}
	for _, id := range []string{r.ResourceID, r.IdentityIncarnationID, r.ServerInstanceID, r.EpochID} {
		if id == "" || len(id) > 256 {
			return AccountMessagingReadinessRoute{}, invalid
		}
	}
	digest, err := hex.DecodeString(r.Digest)
	if err != nil || len(digest) != 32 || r.Generation <= 0 || r.DesiredRevision <= 0 || r.HostConnectionGeneration <= 0 || r.RunnerConnectedAt.IsZero() || r.OfferedAt.IsZero() || !r.OfferDeadline.After(r.OfferedAt) || r.ExpiresAt.Before(r.OfferDeadline) || r.AckedAt != nil || r.Status != "offered" || r.MessagingAvailable {
		return AccountMessagingReadinessRoute{}, invalid
	}
	return r, nil
}
