package daemon

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/pagnet-code/pagnet/internal/accountmessage"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

// sealAccountMessage is intentionally not registered with any socket reader.
// This foundation only stages ciphertext; readiness never grants dispatch.
func (c *accountMessagingReadinessConnection) sealAccountMessage(ctx context.Context, j *accountmessage.Journal, raw []byte) (accountmessage.Sealed, error) {
	r, err := accountmessage.ParseSeal(raw)
	if err != nil {
		return accountmessage.Sealed{}, err
	}
	a := c.subscription
	if a == nil || j == nil {
		return accountmessage.Sealed{}, errors.New("account sealing unavailable")
	}
	d := r.Descriptor
	a.mu.Lock()
	revision, frame := a.revision, a.frame
	route, accepted := a.accepted[d.OfferID]
	a.mu.Unlock()
	if !accepted || !accountSealRouteMatches(d, frame, route) {
		return accountmessage.Sealed{}, errors.New("account seal route not accepted")
	}
	guard := func() bool {
		s, ok := c.session()
		if !ok || s.TenantID != d.TenantID || s.AccountID != d.OwnerUserID || s.HostID != d.HostID || s.RunnerID != d.RunnerID || s.RunnerEpoch.UTC().Format(time.RFC3339Nano) != d.RunnerConnectedAt {
			return false
		}
		now := time.Now()
		created, _ := time.Parse(time.RFC3339Nano, d.CreatedAt)
		expires, _ := time.Parse(time.RFC3339Nano, d.ExpiresAt)
		if now.Before(created) || !now.Before(expires) || !now.Before(route.ExpiresAt) || !c.usesSubscription() || !c.networkMatches(d.NetworkID, d.TenantID, d.EpochID) || c.d.accountMessagingMutationActive() {
			return false
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		current, ok := a.accepted[d.OfferID]
		return ok && a.revision == revision && a.matches(frame) && a.complete && !c.d.accountMessagingMutationActive() && accountSealRouteMatches(d, frame, current)
	}
	if !guard() {
		return accountmessage.Sealed{}, errors.New("account seal fenced")
	}
	row, found, err := c.lookup(d.TargetInstanceID)
	if err != nil || !found || row.DefinitionID != d.TargetDefinitionID || row.AgentPrincipalID != d.TargetPrincipalID || row.NetworkID != d.NetworkID || (row.Status != "idle" && row.Status != "working") {
		return accountmessage.Sealed{}, errors.New("account seal target unavailable")
	}
	kr, err := c.loadKeyring(d.NetworkID)
	if err != nil {
		return accountmessage.Sealed{}, err
	}
	epoch, ok := kr.EpochByID(d.EpochID)
	if !ok || (epoch.State != crypto.EpochActive && epoch.State != crypto.EpochRotated) {
		return accountmessage.Sealed{}, errors.New("account seal epoch unavailable")
	}
	key, err := epoch.KeyArray()
	if err != nil {
		return accountmessage.Sealed{}, err
	}
	defer clear(key[:])
	return j.Seal(ctx, r, key, guard)
}

func accountSealRouteMatches(d accountmessage.Descriptor, f transport.AccountMessagingReadinessSubscriptionFrame, r transport.AccountMessagingReadinessRoute) bool {
	return d.SubscriptionID == f.SubscriptionID.String() && d.SubscriptionVersion == f.Version &&
		d.ConnectionID == r.ConnectionID.String() && d.NetworkID == r.NetworkID.String() && d.TargetPrincipalID == r.TargetPrincipalID.String() && d.HostID == r.HostID.String() && d.Sender.ID == r.LogicalSenderID.String() &&
		d.TargetDefinitionID == r.TargetDefinitionID.String() && d.TargetInstanceID == r.TargetInstanceID.String() && d.ConsentID == r.ConsentID.String() && d.ResourceID == r.ResourceID && d.IdentityIncarnationID == r.IdentityIncarnationID && d.DesiredRevision == strconv.FormatInt(r.DesiredRevision, 10) && d.RunnerID == r.RunnerID.String() && d.RunnerConnectedAt == r.RunnerConnectedAt.UTC().Format(time.RFC3339Nano) && d.ServerInstanceID == r.ServerInstanceID && d.HostConnectionGeneration == strconv.FormatInt(r.HostConnectionGeneration, 10) && d.KeyHolderID == r.KeyHolderID.String() && d.EpochID == r.EpochID && d.OfferID == r.OfferID.String() && d.ReadinessGeneration == strconv.FormatInt(r.Generation, 10) && d.OfferDigest == r.Digest && r.Status == "ready" && r.AckedAt != nil
}
