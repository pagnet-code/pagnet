package fabric

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const ForwardSigningPurpose = "pagnet.fabric.forward.v1"
const ForwardBindingProfile = "pagnet.fabric.hpke-auth.v1"

// ForwardFrame is an engine forwarding attestation, distinct from an ordinary
// caller signature. It belongs inside the encrypted transport, never the relay
// routing stub. Parsing proves neither current peer trust nor replay admission.
type ForwardFrame struct {
	SourceDomain                 string       `json:"sourceDomain"`
	SourceStoreID                string       `json:"sourceStoreId"`
	SourceKeyRevision            uint64       `json:"sourceKeyRevision,string"`
	DestinationDomain            string       `json:"destinationDomain"`
	DestinationStoreID           string       `json:"destinationStoreId"`
	SourcePeerBindingDigest      [32]byte     `json:"sourcePeerBindingDigest"`
	DestinationPeerBindingDigest [32]byte     `json:"destinationPeerBindingDigest"`
	Principal                    Principal    `json:"principal"`
	Operation                    Operation    `json:"operation"`
	InvocationID                 string       `json:"invocationId"`
	ReplayID                     string       `json:"replayId"`
	OriginalEnvelopeDigest       [32]byte     `json:"originalEnvelopeDigest"`
	ForwardedEnvelopeDigest      [32]byte     `json:"forwardedEnvelopeDigest"`
	OriginalProvenance           Provenance   `json:"originalProvenance"`
	ForwardedProvenance          Provenance   `json:"forwardedProvenance"`
	Target                       *EndpointRef `json:"target,omitempty"`
	ExpectedRevision             Revision     `json:"expectedRevision,omitempty"`
	IssuedAt                     string       `json:"issuedAt"`
	ExpiresAt                    string       `json:"expiresAt"`
	Deadline                     string       `json:"deadline,omitempty"`
	BindingProfile               string       `json:"bindingProfile"`
}

type SignedForwardProof struct {
	Frame     ForwardFrame `json:"frame"`
	Signature []byte       `json:"signature"`
}

func forwardStoreID(id string) bool {
	raw, e := hex.DecodeString(id)
	return e == nil && len(raw) == 32 && hex.EncodeToString(raw) == id
}
func forwardProvenanceDigest(p Provenance) ([32]byte, error) {
	// Validate shape without constructing an authenticated execution context.
	e := validateProvenance(p)
	if e != nil {
		return [32]byte{}, e
	}
	raw, e := json.Marshal(p)
	if e != nil || len(raw) > MaxSigningFrameBytes {
		return [32]byte{}, referenceInputError("forward lineage exceeds bounds")
	}
	return sha256.Sum256(raw), nil
}

func (f ForwardFrame) SigningBytes() ([]byte, error) {
	if !canonicalDomainNamespace(f.SourceDomain) || !canonicalDomainNamespace(f.DestinationDomain) || f.SourceDomain == f.DestinationDomain || !forwardStoreID(f.SourceStoreID) || !forwardStoreID(f.DestinationStoreID) || f.SourceKeyRevision == 0 || f.SourcePeerBindingDigest == ([32]byte{}) || f.DestinationPeerBindingDigest == ([32]byte{}) || f.OriginalEnvelopeDigest == ([32]byte{}) || f.ForwardedEnvelopeDigest == ([32]byte{}) || !validSigningText(f.Principal.Ref, false) || !validSigningText(f.Principal.Issuer, false) || !ValidNamespacedName(f.Principal.Kind) || !validSigningText(f.InvocationID, false) || !validSigningText(f.ReplayID, false) || f.BindingProfile != ForwardBindingProfile {
		return nil, referenceInputError("invalid forward signing fields")
	}
	if f.Operation != OperationDiscover && f.Operation != OperationDescribe && f.Operation != OperationInvoke {
		return nil, referenceInputError("invalid forwarded operation")
	}
	target := ""
	if f.Operation == OperationInvoke {
		if f.Target == nil || f.Target.Domain() != f.DestinationDomain || f.ExpectedRevision == "" || !validSigningText(string(f.ExpectedRevision), false) {
			return nil, referenceInputError("forward exact target missing or wrong audience")
		}
		target = f.Target.String()
	} else if f.Target != nil || f.ExpectedRevision != "" {
		return nil, referenceInputError("forward read has invocation target")
	}
	if !validSigningDeadline(f.IssuedAt) || !validSigningDeadline(f.ExpiresAt) || f.IssuedAt == "" || f.ExpiresAt == "" || !validSigningDeadline(f.Deadline) {
		return nil, referenceInputError("invalid forward validity")
	}
	issued, _ := time.Parse(time.RFC3339Nano, f.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, f.ExpiresAt)
	if !expires.After(issued) || expires.Sub(issued) > 24*time.Hour {
		return nil, referenceInputError("unbounded forward validity")
	}
	if f.Deadline != "" {
		deadline, _ := time.Parse(time.RFC3339Nano, f.Deadline)
		if expires.After(deadline) {
			return nil, referenceInputError("forward validity extends original deadline")
		}
	}
	original, e := forwardProvenanceDigest(f.OriginalProvenance)
	if e != nil {
		return nil, e
	}
	forwarded, e := forwardProvenanceDigest(f.ForwardedProvenance)
	if e != nil {
		return nil, e
	}
	return encodeSigningFields(ForwardSigningPurpose, []byte(f.SourceDomain), []byte(f.SourceStoreID), signingCounter(f.SourceKeyRevision), []byte(f.DestinationDomain), []byte(f.DestinationStoreID), f.SourcePeerBindingDigest[:], f.DestinationPeerBindingDigest[:], []byte(f.Principal.Ref), []byte(f.Principal.Kind), []byte(f.Principal.Issuer), []byte(f.Operation), []byte(f.InvocationID), []byte(f.ReplayID), f.OriginalEnvelopeDigest[:], f.ForwardedEnvelopeDigest[:], original[:], forwarded[:], []byte(target), []byte(f.ExpectedRevision), []byte(f.IssuedAt), []byte(f.ExpiresAt), []byte(f.Deadline), []byte(f.BindingProfile))
}
