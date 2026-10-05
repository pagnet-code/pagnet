package continuations

import (
	"context"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/extension"
)

// ConfiguredPlan is an immutable trusted composition snapshot: Plan and its
// exact private configuration evidence must come from one registry publication.
// Evidence is private checkpoint data, not catalog or invocation metadata.
type ConfiguredPlan struct {
	Plan     *extension.Plan
	Evidence []byte
}

func (ConfiguredPlan) MarshalJSON() ([]byte, error) {
	return nil, invalid("Private configured plan cannot be serialized")
}

type ConfiguredPlanProvider func(context.Context) (ConfiguredPlan, error)

func configuredPlan(ctx context.Context, provider ConfiguredPlanProvider, limits fabric.WireLimits) (ConfiguredPlan, error) {
	if ctx == nil || provider == nil || ctx.Err() != nil {
		return ConfiguredPlan{}, invalid("Missing configured plan provider")
	}
	plan, err := provider(ctx)
	if err != nil {
		return ConfiguredPlan{}, err
	}
	if plan.Plan == nil || plan.Plan.Revision() == "" || len(plan.Evidence) == 0 {
		return ConfiguredPlan{}, invalid("Incomplete configured plan snapshot")
	}
	var value any
	if fabric.DecodeJSONWithLimits(plan.Evidence, &value, limits) != nil {
		return ConfiguredPlan{}, invalid("Invalid bounded configured plan evidence")
	}
	// The provider owns the canonical encoding (including typed integer fields).
	// Keep those original exact bytes; reencoding generic JSON can change integers.
	plan.Evidence = append([]byte(nil), plan.Evidence...)
	return plan, nil
}
