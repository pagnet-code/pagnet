package fabric

import "time"

const ControlSigningPurpose = "pagnet.fabric.control.v1"

// ControlFrame authenticates a fresh control operation on an existing receipt.
// It never grants permission to execute or repeat the original invocation.
// The entire proof belongs inside the encrypted peer transport.
type ControlFrame struct {
	ProtocolVersion              string    `json:"protocolVersion"`
	SourceDomain                 string    `json:"sourceDomain"`
	SourceStoreID                string    `json:"sourceStoreId"`
	SourceKeyRevision            uint64    `json:"sourceKeyRevision,string"`
	DestinationDomain            string    `json:"destinationDomain"`
	DestinationStoreID           string    `json:"destinationStoreId"`
	SourcePeerBindingDigest      [32]byte  `json:"sourcePeerBindingDigest"`
	DestinationPeerBindingDigest [32]byte  `json:"destinationPeerBindingDigest"`
	Principal                    Principal `json:"principal"`
	InvocationID                 string    `json:"invocationId"`
	ReceiptDigest                [32]byte  `json:"receiptDigest"`
	AttemptID                    string    `json:"attemptId,omitempty"`
	Action                       string    `json:"action"`
	PayloadDigest                [32]byte  `json:"payloadDigest"`
	ReplayID                     string    `json:"replayId"`
	IssuedAt                     string    `json:"issuedAt"`
	ExpiresAt                    string    `json:"expiresAt"`
	BindingProfile               string    `json:"bindingProfile"`
}

type SignedControlProof struct {
	Frame     ControlFrame `json:"frame"`
	Signature []byte       `json:"signature"`
}

func (f ControlFrame) SigningBytes() ([]byte, error) {
	if f.ProtocolVersion != "1" || !canonicalDomainNamespace(f.SourceDomain) || !canonicalDomainNamespace(f.DestinationDomain) || f.SourceDomain == f.DestinationDomain || !forwardStoreID(f.SourceStoreID) || !forwardStoreID(f.DestinationStoreID) || f.SourceKeyRevision == 0 || f.SourcePeerBindingDigest == ([32]byte{}) || f.DestinationPeerBindingDigest == ([32]byte{}) || f.ReceiptDigest == ([32]byte{}) || f.PayloadDigest == ([32]byte{}) || !validSigningText(f.Principal.Ref, false) || !validSigningText(f.Principal.Issuer, false) || !ValidNamespacedName(f.Principal.Kind) || !validSigningText(f.InvocationID, false) || !validSigningText(f.ReplayID, false) || !validSigningText(f.AttemptID, true) || f.BindingProfile != ForwardBindingProfile {
		return nil, referenceInputError("invalid control signing fields")
	}
	switch f.Action {
	case "status", "cancel":
	case "pull", "ack":
		if f.AttemptID == "" {
			return nil, referenceInputError("control requires original attempt")
		}
	default:
		return nil, referenceInputError("unsupported control action")
	}
	if f.IssuedAt == "" || f.ExpiresAt == "" || !validSigningDeadline(f.IssuedAt) || !validSigningDeadline(f.ExpiresAt) {
		return nil, referenceInputError("invalid control validity")
	}
	issued, _ := time.Parse(time.RFC3339Nano, f.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, f.ExpiresAt)
	if !expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return nil, referenceInputError("unbounded control validity")
	}
	return encodeSigningFields(ControlSigningPurpose, []byte(f.ProtocolVersion), []byte(f.SourceDomain), []byte(f.SourceStoreID), signingCounter(f.SourceKeyRevision), []byte(f.DestinationDomain), []byte(f.DestinationStoreID), f.SourcePeerBindingDigest[:], f.DestinationPeerBindingDigest[:], []byte(f.Principal.Ref), []byte(f.Principal.Kind), []byte(f.Principal.Issuer), []byte(f.InvocationID), f.ReceiptDigest[:], []byte(f.AttemptID), []byte(f.Action), f.PayloadDigest[:], []byte(f.ReplayID), []byte(f.IssuedAt), []byte(f.ExpiresAt), []byte(f.BindingProfile))
}
