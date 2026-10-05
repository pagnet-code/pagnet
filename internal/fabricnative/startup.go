package fabricnative

import (
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/internal/nativeauthority"
)

// StartupPolicy holds a current independent operator fence, outside SQLite,
// synchronously through metadata-only original worker classification.
type StartupPolicy interface {
	WithCurrentOwner(context.Context, fabric.ExecutionContext, func(context.Context) error) error
}
type StartupConfig struct {
	Checkpoints      *Checkpoints
	Launcher         *Launcher
	ControllerBootID string
	MaxWorkers       int
	MaxMetadataBytes int
	Policy           StartupPolicy
}

// StartupResult is private composition state, not a caller/discovery DTO. A
// nonnil error never permits owner-listener exposure, including partial adoption.
type StartupResult struct{ Workers []*WorkerConnection }

// RecoverStartup authenticates ALL retained physical launch slots before the
// composed node exposes owner authentication. It never reads current profiles,
// invokes native intent, replaces workers or treats historical PID as liveness.
func RecoverStartup(ctx context.Context, c StartupConfig) (result StartupResult, err error) {
	if ctx == nil || c.Checkpoints == nil || c.Launcher == nil || c.Checkpoints != c.Launcher.config.Checkpoints || c.Policy == nil || c.ControllerBootID == "" || len(c.ControllerBootID) > 128 || c.MaxWorkers < 1 || c.MaxWorkers > 4096 || c.MaxWorkers > c.Launcher.config.MaxWorkers || c.MaxMetadataBytes < 1024 || c.MaxMetadataBytes > 64<<20 {
		return result, checkpointDenied()
	}
	err = onceCurrentPolicy(ctx, func(next func(context.Context) error) error {
		return c.Policy.WithCurrentOwner(ctx, c.Checkpoints.owner, next)
	}, func(current context.Context) error {
		// ObserveLaunched may FULL-update a launching claim. Collect first so those
		// genuine writes cannot invalidate the signed enumeration generation cursor.
		claims, err := collectStartupClaims(current, c)
		if err != nil {
			return err
		}
		workers := make([]*WorkerConnection, 0, len(claims))
		for _, claim := range claims {
			if current.Err() != nil {
				return current.Err()
			}
			connection, err := c.Launcher.Adopt(current, claim.Directory, claim.Ownership, c.ControllerBootID)
			if err != nil {
				return err
			}
			workers = append(workers, connection)
		}
		result.Workers = workers
		return nil
	})
	if err != nil {
		return StartupResult{}, err
	}
	return result, nil
}
func collectStartupClaims(ctx context.Context, c StartupConfig) ([]LaunchState, error) {
	var claims []LaunchState
	directories := make(map[string]bool)
	physical := make(map[string]bool)
	var cursor string
	bytes := 0
	for {
		page, err := c.Checkpoints.ListLaunches(ctx, cursor, 32)
		if err != nil {
			return nil, err
		}
		for _, claim := range page.Claims {
			if !claim.Exists || claim.Ownership.Kind() != nativeauthority.Local || claim.Ownership.Validate() != nil || !validLaunchDirectory(claim.Directory) || len(claims) >= c.MaxWorkers || directories[claim.Directory] {
				return nil, checkpointDenied()
			}
			key, err := launchClaimKey(claim.Ownership)
			if err != nil || physical[key.ID] {
				return nil, checkpointDenied()
			}
			encoded, err := json.Marshal(claim)
			if err != nil || len(encoded) > c.MaxMetadataBytes-bytes {
				return nil, checkpointDenied()
			}
			bytes += len(encoded)
			directories[claim.Directory] = true
			physical[key.ID] = true
			claims = append(claims, claim)
		}
		if page.NextCursor == "" {
			return claims, nil
		}
		if page.NextCursor == cursor || len(page.Claims) == 0 {
			return nil, checkpointDenied()
		}
		cursor = page.NextCursor
	}
}
