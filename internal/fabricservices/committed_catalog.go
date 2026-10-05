package fabricservices

import (
	"context"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
)

// SetDescriptorsCommittedHook installs a bounded, nonblocking notification
// before any connection begins. Hooks run only AFTER successful real catalog
// commits; initial and SDK tool-change synchronization follow the same path.
// Notifications convey no descriptor/credential data and grant no authority.
func (c *Connections) SetDescriptorsCommittedHook(hook func()) error {
	if c == nil {
		return denied()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.entries) != 0 || len(c.pending) != 0 {
		return denied()
	}
	c.onDescriptorsCommitted = hook
	return nil
}

type committedCatalog struct {
	mcp.Catalog
	hook func()
}

func (c committedCatalog) Apply(ctx context.Context, binding string, endpoint fabric.EndpointRef, d mcp.CatalogDelta) ([]mcp.ToolBinding, error) {
	result, e := c.Catalog.Apply(ctx, binding, endpoint, d)
	if e == nil && c.hook != nil {
		c.hook()
	}
	return result, e
}
