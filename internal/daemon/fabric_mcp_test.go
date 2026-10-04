package daemon

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/pagnet-code/pagnet/fabric/mcpbridge"
	"github.com/pagnet-code/pagnet/internal/fabricmcp"
)

type deniedManagedFactory struct {
	closed atomic.Int32
	built  atomic.Int32
}

func (f *deniedManagedFactory) Build(context.Context, mcpbridge.Call) ([]byte, any, error) {
	f.built.Add(1)
	return nil, nil, errors.New("must not build")
}
func (f *deniedManagedFactory) Close() error { f.closed.Add(1); return nil }
func TestManagedFabricFailedBindingClosesReturnedIdentitySession(t *testing.T) {
	d := newTestDaemon(t)
	factory := &deniedManagedFactory{}
	d.FabricMCP = &ManagedFabricMCP{Server: &fabricmcp.Server{}, BindVerified: func(context.Context, net.Conn, ManagedFabricPeer) (fabricmcp.SessionFactory, error) {
		return factory, errors.New("authority denied")
	}}
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	if result, err := d.prepareManagedFabricPeer(t.Context(), conn, &InstanceRow{InstanceID: "exact-instance"}, "worker", "activation-private", 42); err == nil || result != nil || factory.closed.Load() != 1 || factory.built.Load() != 0 {
		t.Fatal("failed authority binding leaked or accepted session", err)
	}
}
