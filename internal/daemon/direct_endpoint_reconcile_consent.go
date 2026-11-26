//go:build linux || darwin

package daemon

import (
	"context"
	"slices"
	"time"

	"github.com/pagnet-code/pagnet/transport"
)

// These dormant constructors bind a pass to an enabled consent snapshot and the
// exact admitted subscription. installation must come from the scoped consent
// store. Each pass validates consent against its authenticated observation before
// journal, material or remote mutations. They neither read consent storage nor
// register a lease: the caller must acquire the matching registry consent lease
// before wake.attach and retain its synchronization for dispatch.
func newDirectSourceReconcilePassWithConsent(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2, installation string, record directChannelConsentRecord, expectedRevision int64) (directEndpointReconcilePass, error) {
	return newDirectSourceReconcilePassWithConsentAndClient(d, captured, s, issue, installation, record, expectedRevision, nil, time.Now)
}

func newDirectSourceReconcilePassWithConsentAndClient(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.DirectManagedSourceCredentialIssueV2, installation string, record directChannelConsentRecord, expectedRevision int64, client directEndpointReconcilePassClient, now func() time.Time) (directEndpointReconcilePass, error) {
	wrap, err := directReconcileConsentObserverWrapper(captured, s, installation, record, expectedRevision, now)
	if err != nil {
		return nil, err
	}
	return newDirectSourceReconcilePassWithObserver(d, captured, s, issue, client, now, wrap)
}

func newDirectTargetReconcilePassWithConsent(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, installation string, record directChannelConsentRecord, expectedRevision int64) (directEndpointReconcilePass, error) {
	return newDirectTargetReconcilePassWithConsentAndClient(d, captured, s, issue, installation, record, expectedRevision, nil, time.Now)
}

func newDirectTargetReconcilePassWithConsentAndClient(d *Daemon, captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, issue transport.ManagedDirectCredentialIssue, installation string, record directChannelConsentRecord, expectedRevision int64, client directEndpointReconcilePassClient, now func() time.Time) (directEndpointReconcilePass, error) {
	wrap, err := directReconcileConsentObserverWrapper(captured, s, installation, record, expectedRevision, now)
	if err != nil {
		return nil, err
	}
	return newDirectTargetReconcilePassWithObserver(d, captured, s, issue, client, now, wrap)
}

func directReconcileConsentObserverWrapper(captured ManagedEndpointPrepareScope, s *DirectEndpointSubscription, installation string, record directChannelConsentRecord, expectedRevision int64, now func() time.Time) (func(directEndpointReconcileObserver) directEndpointReconcileObserver, error) {
	if now == nil || expectedRevision <= 0 {
		return nil, errDirectChannelConsent
	}
	captured.Session.ProtocolFeatures = slices.Clone(captured.Session.ProtocolFeatures)
	if record.Binding != nil {
		binding := *record.Binding
		record.Binding = &binding
	}
	return func(observe directEndpointReconcileObserver) directEndpointReconcileObserver {
		return func(ctx context.Context) (directEndpointReconcileObservation, error) {
			observed, err := observe(ctx)
			if err != nil {
				return directEndpointReconcileObservation{}, err
			}
			if err := validateDirectChannelConsentEligibility(record, expectedRevision, s, captured, installation, observed.Binding, now()); err != nil {
				return directEndpointReconcileObservation{}, err
			}
			return observed, nil
		}
	}, nil
}
