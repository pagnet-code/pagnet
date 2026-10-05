package fabricnode

import (
	"context"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/transport"
)

// HostedCatalogPublisher is an explicit trusted product composition: the same
// actual node authority, original daemon, private association and network keys.
// It is not an extension, alternative registry, or cloud plaintext search path.
type HostedCatalogPublisher struct {
	bindings *HostedRuntimeBindings
	exporter *registry.CatalogExporter
}

func NewHostedCatalogPublisher(ctx context.Context, bindings *HostedRuntimeBindings, owner fabric.ExecutionContext) (*HostedCatalogPublisher, error) {
	if bindings == nil {
		return nil, localDenied()
	}
	exporter, err := registry.NewCatalogExporter(ctx, bindings.store, owner)
	if err != nil {
		return nil, err
	}
	return &HostedCatalogPublisher{bindings, exporter}, nil
}

// Publish retains the original encrypted packet atomically before sending.
// Retrying after an unknown relay outcome sends that same packet, without
// re-encrypting, changing epoch, silently advancing a revision or choosing a
// different worker. The cloud CAS expectation is explicit operator input.
func (p *HostedCatalogPublisher) Publish(ctx context.Context, access *fabricauth.OwnerAdministration, ref fabric.EndpointRef, revision fabric.Revision, binding string, expectedCloudRevision fabric.Revision) error {
	if p == nil || revision == "" || binding == "" {
		return localDenied()
	}
	h := p.bindings
	_, scope, profile, err := h.selected(ctx, ref, revision, binding)
	if err != nil {
		return err
	}
	publication, err := h.profiles.PreparePublication(ctx, access, scope, expectedCloudRevision, func(ctx context.Context, actual fabricagent.HostedProfile) (transport.FabricHostedPublication, error) {
		if actual != profile {
			return transport.FabricHostedPublication{}, localDenied()
		}
		record, err := p.exporter.Exact(ctx, ref, revision)
		if err != nil {
			return transport.FabricHostedPublication{}, err
		}
		packet := transport.FabricHostedPublication{RequestID: domain.NewID().String(), Ref: ref, Revision: revision, ExpectedRevision: expectedCloudRevision, DomainPublicKey: h.root.PublicKey, NetworkID: actual.NetworkID, InstanceID: actual.Scope.InstanceID, OwnershipID: actual.OwnershipID, OwnershipGeneration: actual.Scope.Generation}
		return h.daemon.PrepareHostedCatalog(ctx, actual, packet, h.store.Genesis(), record)
	})
	if err != nil {
		return err
	}
	if err = access.VerifyCurrent(ctx); err != nil {
		return err
	}
	return h.daemon.PublishHostedCatalog(ctx, profile, publication)
}
