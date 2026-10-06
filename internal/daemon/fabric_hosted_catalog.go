package daemon

import (
	"context"
	"encoding/json"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricagent"
	"github.com/pagnet-code/pagnet/transport"
)

// HostedCatalogBody is plaintext only inside explicitly trusted host nodes.
// The relay receives its encrypted representation, never this descriptor proof.
// Genesis is verification material, not implicit permission to pin a domain.
type HostedCatalogBody struct {
	Protocol string                 `json:"protocol"`
	Genesis  registry.GenesisRecord `json:"genesis"`
	Record   registry.Record        `json:"record"`
}

// PrepareHostedCatalog uses the existing network epoch and genuine original
// worker. Its result must be retained by the signed local publication journal
// before sending so retries reuse the identical encrypted body and request ID.
func (d *Daemon) PrepareHostedCatalog(ctx context.Context, profile fabricagent.HostedProfile, publication transport.FabricHostedPublication, genesis registry.GenesisRecord, record registry.Record) (transport.FabricHostedPublication, error) {
	if err := d.ProbeHostedProfile(ctx, profile); err != nil {
		return transport.FabricHostedPublication{}, err
	}
	if publication.NetworkID != profile.NetworkID || publication.InstanceID != profile.Scope.InstanceID || publication.OwnershipID != profile.OwnershipID || publication.OwnershipGeneration != profile.Scope.Generation || registry.VerifyCatalogRecord(genesis, record, publication.Ref, publication.Revision) != nil {
		return transport.FabricHostedPublication{}, ErrNativeObservationConflict
	}
	namespace, err := fabric.DomainNamespace(publication.DomainPublicKey)
	if err != nil || namespace != publication.Ref.Domain() {
		return transport.FabricHostedPublication{}, ErrNativeObservationConflict
	}
	var root registry.GenesisBody
	if fabric.DecodeJSON(genesis.Body, &root) != nil || string(root.PublicKey) != string(publication.DomainPublicKey) {
		return transport.FabricHostedPublication{}, ErrNativeObservationConflict
	}
	body, err := json.Marshal(HostedCatalogBody{hostedCatalogProtocol, genesis, record})
	if err != nil || len(body) > 128<<10 {
		return transport.FabricHostedPublication{}, fabric.NewError(fabric.CodeInvalidInput, "Hosted catalog proof exceeds its bounded descriptor budget")
	}
	defer clear(body)
	cryptoState, err := d.contentCryptoReady(profile.NetworkID)
	if err != nil {
		return transport.FabricHostedPublication{}, err
	}
	publication.Envelope, publication.AAD, err = d.encryptProtected(cryptoState, transport.ObjectTypeFabricDescriptor, publication.Ref.String(), profile.Scope.InstanceID, publication.Ref.String(), string(body))
	if err != nil {
		return transport.FabricHostedPublication{}, err
	}
	if err = publication.Validate(); err != nil {
		return transport.FabricHostedPublication{}, err
	}
	return publication, nil
}

// PublishHostedCatalog never chooses another authenticated host connection.
// Losing the original account/socket returns an error to the caller.
func (d *Daemon) PublishHostedCatalog(ctx context.Context, profile fabricagent.HostedProfile, publication transport.FabricHostedPublication) error {
	if err := publication.Validate(); err != nil {
		return err
	}
	if publication.NetworkID != profile.NetworkID || publication.InstanceID != profile.Scope.InstanceID || publication.OwnershipID != profile.OwnershipID || publication.OwnershipGeneration != profile.Scope.Generation {
		return ErrNativeObservationConflict
	}
	if err := d.ProbeHostedProfile(ctx, profile); err != nil {
		return err
	}
	d.nativeWorkersMu.Lock()
	link := d.nativeWorkers[profile.Scope.InstanceID]
	d.nativeWorkersMu.Unlock()
	if link == nil {
		return ErrNativeOriginAdmissionDeferred
	}
	proxy, err := d.nativeWorkerFor(link.conn, profile.Scope.InstanceID)
	if err != nil || proxy != link.proxy || proxy.scope != profile.Scope {
		return ErrNativeObservationConflict
	}
	d.connMu.Lock()
	connection := d.nativeConn
	current := d.curConn == link.conn
	d.connMu.Unlock()
	if connection == nil || !current {
		return ErrNativeOriginAdmissionDeferred
	}
	session, err := connection.AuthenticatedNativeHostSession()
	if err != nil || session.TenantID != profile.Scope.TenantID || session.AccountID != profile.Scope.AccountID {
		return ErrNativeObservationConflict
	}
	return connection.PublishHostedFabric(ctx, publication)
}
