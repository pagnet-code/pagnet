package fabricnative

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric/registry"
)

type LaunchPage struct {
	Claims     []LaunchState
	NextCursor string
}

// ListLaunches enumerates actual signed retained launch slots, including retired
// or uncertain records. None is process evidence. Startup must authenticate the
// original physical worker before exposing the root-owner listener.
func (c *Checkpoints) ListLaunches(ctx context.Context, cursor string, limit int) (LaunchPage, error) {
	if c == nil || ctx == nil {
		return LaunchPage{}, checkpointDenied()
	}
	page, err := c.store.ListGlobalAuthorityRecords(ctx, c.owner, registry.AuthorityNativeCheckpoint, "launch/", cursor, limit)
	if err != nil {
		return LaunchPage{}, err
	}
	out := LaunchPage{NextCursor: page.NextCursor, Claims: make([]LaunchState, 0, len(page.Records))}
	for _, record := range page.Records {
		var claim launchClaim
		if record.Retired || decodeCheckpoint(record.Value, &claim) != nil || claim.Version != "pagnet.native.launch-claim.v2" || claim.Ownership.Validate() != nil {
			return LaunchPage{}, checkpointDenied()
		}
		key, err := launchClaimKey(claim.Ownership)
		if err != nil || key != record.Key {
			return LaunchPage{}, checkpointDenied()
		}
		// Lookup repeats the signed CURRENT slot check before decryption. Snapshot
		// changes between page and lookup fail closed through original state equality.
		state, err := c.LookupLaunch(ctx, claim.Ownership)
		if err != nil || !state.Exists || state.Ownership != claim.Ownership {
			return LaunchPage{}, checkpointDenied()
		}
		if claim.Phase == "observed" && (state.Observed == nil || claim.Process == nil || *state.Observed != *claim.Process) {
			return LaunchPage{}, checkpointDenied()
		}
		if claim.Phase == "launching" && state.Observed != nil {
			return LaunchPage{}, checkpointDenied()
		}
		out.Claims = append(out.Claims, state)
	}
	return out, nil
}
