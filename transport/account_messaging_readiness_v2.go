package transport

import (
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/pagnet-code/pagnet/domain"
)

const AccountMessagingReadinessSubscriptionProtocol = "browser-account-messaging-readiness-v2"
const MsgAccountMessagingReadinessReset = "account.messaging.readiness.reset"
const MsgAccountMessagingReadinessSnapshotComplete = "account.messaging.readiness.snapshot.complete"
const MsgAccountMessagingReadinessAccepted = "account.messaging.readiness.accepted"

type AccountMessagingReadinessSubscriptionHelloPayload struct {
	V        int    `json:"v"`
	Protocol string `json:"protocol"`
	Reset    bool   `json:"reset"`
}

type AccountMessagingReadinessSubscriptionFrame struct {
	V              int       `json:"v"`
	Protocol       string    `json:"protocol"`
	SubscriptionID domain.ID `json:"subscriptionId"`
	Version        string    `json:"version"`
}

type AccountMessagingReadinessSubscriptionResetPayload struct {
	AccountMessagingReadinessSubscriptionFrame
	Reason string `json:"reason"`
}

type AccountMessagingReadinessSubscriptionOfferPayload struct {
	AccountMessagingReadinessSubscriptionFrame
	Route AccountMessagingReadinessRoute `json:"route"`
}

type AccountMessagingReadinessSubscriptionCompletePayload struct {
	AccountMessagingReadinessSubscriptionFrame
	OfferCount int    `json:"offerCount"`
	Status     string `json:"status"`
}

type AccountMessagingReadinessSubscriptionAcceptedPayload struct {
	AccountMessagingReadinessSubscriptionFrame
	Route AccountMessagingReadinessRoute `json:"route"`
}

type AccountMessagingReadinessSubscriptionAckPayload struct {
	AccountMessagingReadinessSubscriptionFrame
	AccountMessagingReadinessAck
}

func validAccountMessagingReadinessSubscriptionFrame(p AccountMessagingReadinessSubscriptionFrame) bool {
	id, err := domain.ParseID(p.SubscriptionID.String())
	if err != nil || id != p.SubscriptionID || p.V != 2 || p.Protocol != AccountMessagingReadinessSubscriptionProtocol {
		return false
	}
	version, err := strconv.ParseUint(p.Version, 10, 64)
	return err == nil && version > 0 && strconv.FormatUint(version, 10) == p.Version
}

func decodeAccountMessagingReadinessSubscription(raw []byte, target any) bool {
	return len(raw) <= AccountMessagingReadinessMaxPayload && DecodeOwnerTextConsolePayload(raw, target) == nil
}

func ParseAccountMessagingReadinessSubscriptionReset(raw []byte) (AccountMessagingReadinessSubscriptionResetPayload, error) {
	var p AccountMessagingReadinessSubscriptionResetPayload
	if decodeAccountMessagingReadinessSubscription(raw, &p) && validAccountMessagingReadinessSubscriptionFrame(p.AccountMessagingReadinessSubscriptionFrame) {
		switch p.Reason {
		case "initial", "changed", "client_reset", "expired":
			return p, nil
		}
	}
	return AccountMessagingReadinessSubscriptionResetPayload{}, errors.New("transport: invalid account messaging readiness subscription reset")
}

func ParseAccountMessagingReadinessSubscriptionOffer(raw []byte) (AccountMessagingReadinessSubscriptionOfferPayload, error) {
	var p AccountMessagingReadinessSubscriptionOfferPayload
	if !decodeAccountMessagingReadinessSubscription(raw, &p) || !validAccountMessagingReadinessSubscriptionFrame(p.AccountMessagingReadinessSubscriptionFrame) || !validAccountMessagingReadinessSubscriptionRoute(p.Route, false) {
		return AccountMessagingReadinessSubscriptionOfferPayload{}, errors.New("transport: invalid account messaging readiness subscription offer")
	}
	return p, nil
}

func ParseAccountMessagingReadinessSubscriptionComplete(raw []byte) (AccountMessagingReadinessSubscriptionCompletePayload, error) {
	var p AccountMessagingReadinessSubscriptionCompletePayload
	if !decodeAccountMessagingReadinessSubscription(raw, &p) || !validAccountMessagingReadinessSubscriptionFrame(p.AccountMessagingReadinessSubscriptionFrame) || p.OfferCount < 0 || p.OfferCount > 256 || (p.Status != "complete" && p.Status != "capacity_exceeded") || (p.Status == "capacity_exceeded" && p.OfferCount != 0) {
		return AccountMessagingReadinessSubscriptionCompletePayload{}, errors.New("transport: invalid account messaging readiness subscription complete")
	}
	return p, nil
}

// Accepted is handshake evidence only and does not establish messaging authority.
func ParseAccountMessagingReadinessSubscriptionAccepted(raw []byte) (AccountMessagingReadinessSubscriptionAcceptedPayload, error) {
	var p AccountMessagingReadinessSubscriptionAcceptedPayload
	if !decodeAccountMessagingReadinessSubscription(raw, &p) || !validAccountMessagingReadinessSubscriptionFrame(p.AccountMessagingReadinessSubscriptionFrame) || !validAccountMessagingReadinessSubscriptionRoute(p.Route, true) {
		return AccountMessagingReadinessSubscriptionAcceptedPayload{}, errors.New("transport: invalid account messaging readiness subscription accepted")
	}
	return p, nil
}

func validAccountMessagingReadinessSubscriptionRoute(r AccountMessagingReadinessRoute, accepted bool) bool {
	for _, id := range []domain.ID{r.ConnectionID, r.NetworkID, r.TargetPrincipalID, r.HostID, r.LogicalSenderID, r.ConsentID, r.TargetDefinitionID, r.TargetInstanceID, r.RunnerID, r.KeyHolderID, r.OfferID, domain.ID(r.IdentityIncarnationID)} {
		parsed, err := domain.ParseID(id.String())
		if err != nil || parsed != id {
			return false
		}
	}
	for _, id := range []string{r.ResourceID, r.IdentityIncarnationID, r.ServerInstanceID, r.EpochID} {
		if id == "" || len(id) > 256 {
			return false
		}
	}
	digest, err := hex.DecodeString(r.Digest)
	if err != nil || len(digest) != 32 || r.Generation <= 0 || r.DesiredRevision <= 0 || r.HostConnectionGeneration <= 0 || r.RunnerConnectedAt.IsZero() || r.OfferedAt.IsZero() || !r.OfferDeadline.After(r.OfferedAt) || r.ExpiresAt.Before(r.OfferDeadline) || r.MessagingAvailable {
		return false
	}
	if accepted {
		return r.Status == "ready" && r.AckedAt != nil && !r.AckedAt.IsZero()
	}
	return r.Status == "offered" && r.AckedAt == nil
}
