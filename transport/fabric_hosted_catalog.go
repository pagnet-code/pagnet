package transport

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
	"github.com/pagnet-code/pagnet/e2ee"
	"github.com/pagnet-code/pagnet/fabric"
)

// The hosted catalog import relay: the daemon requests bounded pages of the
// server-side hosted catalog over the authenticated host connection. The
// server scopes pages to the host's authenticated network membership (its
// fabric_hosted_catalog table) and replies on the same connection; there is
// no HTTP surface and the relay never carries ledger history — each record is
// one exact signed object the daemon verifies against an explicitly trusted
// domain root before retention.
const (
	MsgFabricHostedCatalogRequest = "host.fabric_hosted_catalog_request"
	MsgFabricHostedCatalogPage    = "host.fabric_hosted_catalog_page"

	// FabricHostedCatalogPageMaxBytes is the transport budget for one served
	// page (same discipline as the other FabricHosted* payloads).
	FabricHostedCatalogPageMaxBytes = 512 << 10
	// FabricHostedCatalogPageMaxRecords bounds one page's record count.
	FabricHostedCatalogPageMaxRecords = 64
	// FabricHostedCatalogCursorMaxBytes bounds the opaque server-side import
	// watermark (the daemon never parses it).
	FabricHostedCatalogCursorMaxBytes = 256
)

type FabricHostedCatalogRequest struct {
	RequestID  string `json:"requestId"`
	NetworkID  string `json:"networkId"`
	Cursor     string `json:"cursor"`
	MaxBytes   int    `json:"maxBytes"`
	MaxRecords int    `json:"maxRecords"`
}

func (r FabricHostedCatalogRequest) Validate() error {
	for _, id := range []string{r.RequestID, r.NetworkID} {
		if _, err := domain.ParseID(id); err != nil {
			return fabric.NewError(fabric.CodeInvalidInput, "Invalid hosted catalog import identity")
		}
	}
	if len(r.Cursor) > FabricHostedCatalogCursorMaxBytes || !utf8.ValidString(r.Cursor) || containsNUL(r.Cursor) {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid hosted catalog import cursor")
	}
	if r.MaxBytes < 1 || r.MaxBytes > FabricHostedCatalogPageMaxBytes || r.MaxRecords < 1 || r.MaxRecords > FabricHostedCatalogPageMaxRecords {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid hosted catalog import bounds")
	}
	if raw, err := json.Marshal(r); err != nil || len(raw) > 8192 {
		return fabric.NewError(fabric.CodeInvalidInput, "Hosted catalog import request exceeds transport budget")
	}
	return nil
}

// FabricHostedCatalogRecord is one exact signed object relayed by the server.
// The record itself rides inside the sealed envelope (the same
// HostedCatalogBody shape the publish path encrypts); the plaintext fields
// here are routing metadata only. A signed record authenticates one object;
// it does not prove ledger contiguity or freshness.
type FabricHostedCatalogRecord struct {
	Ref             fabric.EndpointRef      `json:"ref"`
	Revision        fabric.Revision         `json:"revision"`
	DomainPublicKey []byte                  `json:"domainPublicKey"`
	Tombstone       bool                    `json:"tombstone"`
	Envelope        e2ee.EncryptedPayloadV1 `json:"envelope"`
	AAD             e2ee.AAD                `json:"aad"`
}

type FabricHostedCatalogPage struct {
	RequestID  string                      `json:"requestId"`
	NetworkID  string                      `json:"networkId"`
	Records    []FabricHostedCatalogRecord `json:"records"`
	NextCursor string                      `json:"nextCursor"`
	Terminal   bool                        `json:"terminal"`
	Error      *fabric.Error               `json:"error,omitempty"`
}

func (p FabricHostedCatalogPage) Validate() error {
	for _, id := range []string{p.RequestID, p.NetworkID} {
		if _, err := domain.ParseID(id); err != nil {
			return fabric.NewError(fabric.CodeInvalidInput, "Invalid hosted catalog page identity")
		}
	}
	if len(p.NextCursor) > FabricHostedCatalogCursorMaxBytes || !utf8.ValidString(p.NextCursor) || containsNUL(p.NextCursor) {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid hosted catalog page cursor")
	}
	// A terminal page carries no cursor; the import is complete.
	if p.Terminal && p.NextCursor != "" {
		return fabric.NewError(fabric.CodeInvalidInput, "Terminal hosted catalog page carries a cursor")
	}
	if len(p.Records) > FabricHostedCatalogPageMaxRecords {
		return fabric.NewError(fabric.CodeInvalidInput, "Hosted catalog page exceeds record budget")
	}
	for _, r := range p.Records {
		if err := r.validateFor(p.NetworkID); err != nil {
			return err
		}
	}
	if raw, err := json.Marshal(p); err != nil || len(raw) > FabricHostedCatalogPageMaxBytes {
		return fabric.NewError(fabric.CodeInvalidInput, "Hosted catalog page exceeds transport budget")
	}
	return nil
}

func (r FabricHostedCatalogRecord) validateFor(networkID string) error {
	namespace, err := fabric.DomainNamespace(r.DomainPublicKey)
	if err != nil || r.Ref.Domain() != namespace || r.Revision == "" || len(r.Revision) > 256 {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid hosted catalog record routing")
	}
	if r.Envelope.Validate() != nil || r.AAD.ValidateScope() != nil || r.AAD.ProtocolVersion != ProtocolVersion || r.AAD.ObjectType != ObjectTypeFabricDescriptor || r.AAD.ObjectID != r.Ref.String() || r.AAD.Recipient != r.Ref.String() || r.AAD.NetworkID != networkID || r.AAD.KeyEpochID != r.Envelope.KeyEpochID || r.AAD.NativeContent != nil || r.AAD.ProtectedContext != nil {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid protected hosted catalog record")
	}
	return nil
}

func containsNUL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return true
		}
	}
	return false
}
