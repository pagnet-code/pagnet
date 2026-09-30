package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/pagnet-code/pagnet/e2ee"
)

// GetInvocation reads a durable invocation without submitting new work. Only
// the caller can read its decrypted outcome; server authorization also applies.
// A nonterminal state is returned immediately, so callers can poll after an
// Invoke timeout or reconnect using the original invocation ID.
func (c *Client) GetInvocation(ctx context.Context, networkID, invocationID string) (*Invocation, error) {
	if err := c.checkOpen(); err != nil {
		return nil, err
	}
	if networkID == "" || invocationID == "" {
		return nil, errors.New("sdk: network and invocation IDs are required")
	}
	rec, err := c.rest.getInvocation(ctx, url.PathEscape(networkID), url.PathEscape(invocationID))
	if err != nil {
		return nil, err
	}
	if rec.NetworkID != networkID || rec.ID != invocationID {
		return nil, errors.New("sdk: invocation response scope mismatch")
	}
	if rec.CallerPrincipalID != c.principalID.Load() {
		return nil, errors.New("sdk: invocation is not owned by this caller")
	}
	out := &Invocation{ID: rec.ID, NetworkID: rec.NetworkID, TargetPrincipalID: rec.TargetPrincipalID, CapabilityID: rec.CapabilityID, CapabilityVersion: rec.CapabilityVersion, State: rec.State, PublicResultCode: rec.PublicResultCode, UsageMetadata: rec.UsageMetadata}
	validate := func(field *encryptedField, kind string) error {
		if field.AAD.NetworkID != networkID || field.AAD.ObjectID != invocationID || field.AAD.ObjectType != kind || field.AAD.Sender != rec.TargetPrincipalID || field.AAD.Recipient != rec.CallerPrincipalID {
			return errors.New("sdk: invocation result AAD routing mismatch")
		}
		return nil
	}
	if rec.ProtectedOutput != nil {
		if err := validate(rec.ProtectedOutput, e2ee.ObjectTypeInvocationOutput); err != nil {
			return nil, err
		}
		plain, err := c.decryptObject(networkID, rec.ProtectedOutput.Envelope, rec.ProtectedOutput.AAD)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(plain, &out.Output); err != nil {
			return nil, fmt.Errorf("sdk: decode invocation result: %w", err)
		}
	}
	if rec.ProtectedError != nil {
		if err := validate(rec.ProtectedError, e2ee.ObjectTypeInvocationError); err != nil {
			return nil, err
		}
		plain, err := c.decryptObject(networkID, rec.ProtectedError.Envelope, rec.ProtectedError.AAD)
		if err != nil {
			return nil, err
		}
		out.Err = errors.New(string(plain))
	}
	return out, nil
}
