package e2ee

// AAD is the associated-data binding for a protected object (plan §11.4).
// Its canonical serialization (CanonicalBytes) is the GCM associated-data:
// tampering with ANY bound field makes decryption fail.
//
// The fields are the server-readable routing metadata the ciphertext is
// bound to. The recipient reconstructs the AAD from the routing metadata it
// receives and passes it to Decrypt; if the server altered any field, the
// reconstructed AAD differs from the one used at encryption and GCM
// authentication fails.
//
// CreatedAt is a deterministic RFC3339 UTC string (not a time.Time) so the
// canonical bytes are stable across implementations.
type AAD struct {
	ProtocolVersion int    `json:"protocol_version"`
	TenantID        string `json:"tenant_id"`
	NetworkID       string `json:"network_id"`
	ObjectType      string `json:"object_type"`
	ObjectID        string `json:"object_id"`
	Sender          string `json:"sender"`
	Recipient       string `json:"recipient"`
	CreatedAt       string `json:"created_at"`
	KeyEpochID      string `json:"key_epoch_id"`
}

// CanonicalBytes returns the canonical serialization of the AAD: compact
// JSON, keys in declaration order, no HTML escaping, no trailing newline.
// These bytes are the GCM associated-data.
//
// Encoding a struct of strings and one int cannot fail; the panic guards an
// impossible condition rather than forcing callers through dead error
// handling.
func (a AAD) CanonicalBytes() []byte {
	b, err := canonicalJSON(a)
	if err != nil {
		panic("e2ee: canonical AAD encoding failed: " + err.Error())
	}
	return b
}
