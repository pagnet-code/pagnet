package transport

import (
	"errors"
	"strconv"
)

// Direct endpoint wake carries hints only; authenticated HTTP remains the
// authority for current endpoint state. These payloads use envelope version 2.
const (
	MsgDirectEndpointWakeSubscribe       = "direct.endpoint.wake.subscribe"
	MsgDirectEndpointWakeOffer           = "direct.endpoint.wake.offer"
	MsgDirectEndpointWakeACK             = "direct.endpoint.wake.ack"
	MsgDirectEndpointWakeUnsubscribe     = "direct.endpoint.wake.unsubscribe"
	MsgDirectEndpointWakeClosed          = "direct.endpoint.wake.closed"
	DirectEndpointWakeProtocolV1         = "direct-endpoint-wake-v1"
	DirectEndpointWakeFeatureV1          = "direct-endpoint-wake-v1"
	DirectEndpointWakeQueryKey           = "direct_endpoint_wake"
	DirectEndpointWakeMaxPayloadBytesV1  = 4096
	DirectEndpointWakeRoleSourceV2       = "source-v2"
	DirectEndpointWakeRoleTargetV1       = "target-v1"
	DirectEndpointWakeClosedUnsubscribed = "unsubscribed"
	// Unavailable is the generic reason for authority loss.
	DirectEndpointWakeClosedUnavailable    = "unavailable"
	DirectEndpointWakeClosedRetryExhausted = "retry_exhausted"
)

var errDirectEndpointWakeV1 = errors.New("transport: invalid direct endpoint wake v1 payload")

type DirectEndpointWakeSubscribeV1 struct {
	Protocol       string `json:"protocol"`
	SubscriptionID string `json:"subscriptionId"`
	DirectIntentID string `json:"directIntentId"`
	EndpointRole   string `json:"endpointRole"`
	CredentialID   string `json:"credentialId"`
}

// DirectEndpointWakeOfferV1 identifies an exact hint. Generation and revision
// are canonical positive decimal strings bounded by the signed 64-bit range.
type DirectEndpointWakeOfferV1 struct {
	Protocol       string `json:"protocol"`
	SubscriptionID string `json:"subscriptionId"`
	StreamID       string `json:"streamId"`
	ContinuityID   string `json:"continuityId"`
	Generation     string `json:"generation"`
	OfferID        string `json:"offerId"`
	Revision       string `json:"revision"`
}

// DirectEndpointWakeACKV1 echoes every field of the exact received offer.
type DirectEndpointWakeACKV1 DirectEndpointWakeOfferV1

type DirectEndpointWakeUnsubscribeV1 struct {
	Protocol       string `json:"protocol"`
	SubscriptionID string `json:"subscriptionId"`
}

type DirectEndpointWakeClosedV1 struct {
	Protocol       string `json:"protocol"`
	SubscriptionID string `json:"subscriptionId"`
	Reason         string `json:"reason"`
}

func directEndpointWakeIdentityV1(protocol, subscriptionID string) bool {
	return protocol == DirectEndpointWakeProtocolV1 && directV2ID(subscriptionID)
}

func directEndpointWakeDecimalV1(s string) bool {
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == s
}

func (p DirectEndpointWakeSubscribeV1) CanonicalBytes() ([]byte, error) {
	if !directEndpointWakeIdentityV1(p.Protocol, p.SubscriptionID) || !directV2ID(p.DirectIntentID) || !directV2ID(p.CredentialID) || (p.EndpointRole != DirectEndpointWakeRoleSourceV2 && p.EndpointRole != DirectEndpointWakeRoleTargetV1) {
		return nil, errDirectEndpointWakeV1
	}
	return directV2Canonical(p, DirectEndpointWakeMaxPayloadBytesV1)
}

func (p DirectEndpointWakeOfferV1) CanonicalBytes() ([]byte, error) {
	if !directEndpointWakeIdentityV1(p.Protocol, p.SubscriptionID) || !directV2ID(p.StreamID) || !directV2ID(p.ContinuityID) || !directV2ID(p.OfferID) || !directEndpointWakeDecimalV1(p.Generation) || !directEndpointWakeDecimalV1(p.Revision) {
		return nil, errDirectEndpointWakeV1
	}
	return directV2Canonical(p, DirectEndpointWakeMaxPayloadBytesV1)
}

func (p DirectEndpointWakeACKV1) CanonicalBytes() ([]byte, error) {
	return DirectEndpointWakeOfferV1(p).CanonicalBytes()
}

// ValidateDirectEndpointWakeACKV1 compares the complete offer tuple. It does
// not establish credential authority or acknowledge HTTP processing.
func ValidateDirectEndpointWakeACKV1(ack DirectEndpointWakeACKV1, offer DirectEndpointWakeOfferV1) error {
	if _, err := ack.CanonicalBytes(); err != nil {
		return err
	}
	if _, err := offer.CanonicalBytes(); err != nil {
		return err
	}
	if DirectEndpointWakeOfferV1(ack) != offer {
		return errDirectEndpointWakeV1
	}
	return nil
}

func (p DirectEndpointWakeUnsubscribeV1) CanonicalBytes() ([]byte, error) {
	if !directEndpointWakeIdentityV1(p.Protocol, p.SubscriptionID) {
		return nil, errDirectEndpointWakeV1
	}
	return directV2Canonical(p, DirectEndpointWakeMaxPayloadBytesV1)
}

func (p DirectEndpointWakeClosedV1) CanonicalBytes() ([]byte, error) {
	if !directEndpointWakeIdentityV1(p.Protocol, p.SubscriptionID) {
		return nil, errDirectEndpointWakeV1
	}
	switch p.Reason {
	case DirectEndpointWakeClosedUnsubscribed, DirectEndpointWakeClosedUnavailable, DirectEndpointWakeClosedRetryExhausted:
	default:
		return nil, errDirectEndpointWakeV1
	}
	return directV2Canonical(p, DirectEndpointWakeMaxPayloadBytesV1)
}

func decodeDirectEndpointWakeV1(raw []byte, p interface{ CanonicalBytes() ([]byte, error) }) error {
	if directV2Decode(raw, p, DirectEndpointWakeMaxPayloadBytesV1) != nil {
		return errDirectEndpointWakeV1
	}
	if _, err := p.CanonicalBytes(); err != nil {
		return errDirectEndpointWakeV1
	}
	return nil
}

func DecodeDirectEndpointWakeSubscribeV1(raw []byte) (DirectEndpointWakeSubscribeV1, error) {
	var p DirectEndpointWakeSubscribeV1
	if err := decodeDirectEndpointWakeV1(raw, &p); err != nil {
		return DirectEndpointWakeSubscribeV1{}, err
	}
	return p, nil
}
func DecodeDirectEndpointWakeOfferV1(raw []byte) (DirectEndpointWakeOfferV1, error) {
	var p DirectEndpointWakeOfferV1
	if err := decodeDirectEndpointWakeV1(raw, &p); err != nil {
		return DirectEndpointWakeOfferV1{}, err
	}
	return p, nil
}
func DecodeDirectEndpointWakeACKV1(raw []byte) (DirectEndpointWakeACKV1, error) {
	var p DirectEndpointWakeACKV1
	if err := decodeDirectEndpointWakeV1(raw, &p); err != nil {
		return DirectEndpointWakeACKV1{}, err
	}
	return p, nil
}
func DecodeDirectEndpointWakeUnsubscribeV1(raw []byte) (DirectEndpointWakeUnsubscribeV1, error) {
	var p DirectEndpointWakeUnsubscribeV1
	if err := decodeDirectEndpointWakeV1(raw, &p); err != nil {
		return DirectEndpointWakeUnsubscribeV1{}, err
	}
	return p, nil
}
func DecodeDirectEndpointWakeClosedV1(raw []byte) (DirectEndpointWakeClosedV1, error) {
	var p DirectEndpointWakeClosedV1
	if err := decodeDirectEndpointWakeV1(raw, &p); err != nil {
		return DirectEndpointWakeClosedV1{}, err
	}
	return p, nil
}
