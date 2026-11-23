package daemon

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/internal/accountmessage"
	"github.com/pagnet-code/pagnet/internal/crypto"
	"github.com/pagnet-code/pagnet/transport"
)

func accountSealFixture(t *testing.T) (readinessFixture, *accountmessage.Journal, accountmessage.SealRequest) {
	t.Helper()
	f := newReadinessSubscriptionFixture(t)
	readinessSubscriptionAdmit(t, f)
	frame := readinessSubscriptionFrame()
	readinessSubscriptionReset(t, f, frame)
	readinessSubscriptionOffer(t, f, frame, f.route)
	readinessSubscriptionComplete(t, f, frame, 1)
	f.expect(t, "account.messaging.readiness.ack")
	readinessSubscriptionIdle(t, f)
	route := f.route
	now := time.Now().UTC()
	route.Status = "ready"
	route.AckedAt = &now
	f.c.subscription.mu.Lock()
	f.c.subscription.accepted = map[string]transport.AccountMessagingReadinessRoute{}
	f.c.subscription.mu.Unlock()
	d := accountmessage.Descriptor{V: 1, MessageID: domain.NewID().String(), TenantID: f.session.TenantID, OwnerUserID: f.session.AccountID, ConnectionID: route.ConnectionID.String(), Sender: accountmessage.Sender{Kind: "browser_account_delegate", ID: route.LogicalSenderID.String()}, NetworkID: route.NetworkID.String(), TargetPrincipalID: route.TargetPrincipalID.String(), HostID: route.HostID.String(), TargetDefinitionID: route.TargetDefinitionID.String(), TargetInstanceID: route.TargetInstanceID.String(), ConsentID: route.ConsentID.String(), ResourceID: route.ResourceID, IdentityIncarnationID: route.IdentityIncarnationID, DesiredRevision: strconv.FormatInt(route.DesiredRevision, 10), RunnerID: route.RunnerID.String(), RunnerConnectedAt: route.RunnerConnectedAt.UTC().Format(time.RFC3339Nano), ServerInstanceID: route.ServerInstanceID, HostConnectionGeneration: strconv.FormatInt(route.HostConnectionGeneration, 10), KeyHolderID: route.KeyHolderID.String(), EpochID: route.EpochID, OfferID: route.OfferID.String(), ReadinessGeneration: strconv.FormatInt(route.Generation, 10), OfferDigest: route.Digest, SubscriptionID: frame.SubscriptionID.String(), SubscriptionVersion: frame.Version, CreatedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	f.c.subscription.mu.Lock()
	f.c.subscription.accepted[d.OfferID] = route
	f.c.subscription.mu.Unlock()
	j, e := accountmessage.OpenJournal(filepath.Join(t.TempDir(), "private"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	return f, j, accountmessage.SealRequest{V: 1, Descriptor: d, BindingDigest: d.BindingDigest(), Text: "account delegate private message"}
}
func TestAccountMessageSealAcceptedAndFrozenEpoch(t *testing.T) {
	f, j, r := accountSealFixture(t)
	raw, _ := json.Marshal(r)
	s, e := f.c.sealAccountMessage(context.Background(), j, raw)
	if e != nil {
		t.Fatal(e)
	}
	if s.MessageID != r.Descriptor.MessageID || s.Envelope.KeyEpochID != r.Descriptor.EpochID {
		t.Fatal("lost frozen identity")
	}
	again, e := f.c.sealAccountMessage(context.Background(), j, raw)
	if e != nil || s.Envelope != again.Envelope {
		t.Fatal("changed retry", e)
	}
}
func TestAccountMessageSealRejectsChangedEvidence(t *testing.T) {
	for _, kind := range []string{"subscription", "route", "mutation", "epoch", "disconnect"} {
		t.Run(kind, func(t *testing.T) {
			f, j, r := accountSealFixture(t)
			switch kind {
			case "subscription":
				f.c.subscription.mu.Lock()
				f.c.subscription.frame.Version = "2"
				f.c.subscription.mu.Unlock()
			case "route":
				r.Descriptor.TargetInstanceID = domain.NewID().String()
				r.BindingDigest = r.Descriptor.BindingDigest()
			case "mutation":
				finish := f.c.d.beginAccountMessagingMutation()
				defer finish()
			case "disconnect":
				f.c.close()
			case "epoch":
				f.c.loadKeyring = func(string) (*crypto.Keyring, error) { return &crypto.Keyring{}, nil }
			}
			raw, _ := json.Marshal(r)
			if _, e := f.c.sealAccountMessage(context.Background(), j, raw); e == nil {
				t.Fatal("accepted changed evidence")
			}
		})
	}
}
