package fabric

import (
	"bytes"
	"encoding/binary"
	"time"
	"unicode/utf8"
)

const (
	MaxSigningFrameBytes    = 64 << 10
	MaxSigningTextBytes     = 4 << 10
	genesisSigningPurpose   = "pagnet.fabric.genesis.v1"
	registrySigningPurpose  = "pagnet.fabric.registry.v1"
	callerSigningPurpose    = "pagnet.fabric.caller-proof.v1"
	admissionSigningPurpose = "pagnet.fabric.dispatch-admission.v1"
)

// Signing frames commit to exact bounded payload bytes, never a decoded and
// re-encoded arbitrary JSON map. Encoding/decoding alone verifies no signature,
// trust pin, replay admission, current authority or registry ownership.
type GenesisFrame struct {
	Namespace        string
	GenesisPublicKey [32]byte
	PayloadDigest    [32]byte
}

type RegistryFrame struct {
	IssuerNamespace       string
	IssuerKeyRevision     uint64
	AudienceDomain        string
	ActionKind            string
	ExactTargetRef        EndpointRef
	ExpectedPriorRevision Revision
	NewRevision           Revision
	Sequence              uint64
	PreviousHeadDigest    [32]byte
	PayloadDigest         [32]byte
}

// CallerProofFrame binds the original caller request. It is not authorization
// for input/target changed later by the engine's preparation stages.
type CallerProofFrame struct {
	SourceDomain           string
	CallerRef              string
	IssuerKeyRevision      uint64
	AudienceDomain         string
	Operation              Operation
	OriginalEnvelopeID     string
	ReplayID               string
	OriginalEnvelopeDigest [32]byte
	Deadline               string
}

// DispatchAdmissionFrame separately commits to the engine-finalized view.
// The verifying issuer key comes from pinned authority, not this caller data.
type DispatchAdmissionFrame struct {
	SourceDomain            string
	CallerRef               string
	AudienceDomain          string
	InvocationID            string
	AttemptID               string
	ReplayID                string
	FinalizedDispatchDigest [32]byte
	Deadline                string
}

func validSigningText(text string, optional bool) bool {
	return len(text) <= MaxSigningTextBytes && (optional || text != "") && utf8.ValidString(text)
}
func validSigningDeadline(text string) bool {
	if text == "" {
		return true
	}
	if !validSigningText(text, false) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == text
}
func signingCounter(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}
func encodeSigningFields(purpose string, fields ...[]byte) ([]byte, error) {
	size := len(purpose) + 1
	for _, field := range fields {
		if len(field) > MaxSigningTextBytes || len(field) > MaxSigningFrameBytes-size-4 {
			return nil, referenceInputError("signing frame exceeds bounds")
		}
		size += 4 + len(field)
	}
	framed := make([]byte, 0, size)
	framed = append(framed, purpose...)
	framed = append(framed, 0)
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		framed = append(framed, length[:]...)
		framed = append(framed, field...)
	}
	return framed, nil
}
func decodeSigningFields(raw []byte, purpose string, count int) ([][]byte, error) {
	prefix := purpose + "\x00"
	if len(raw) > MaxSigningFrameBytes || len(raw) < len(prefix) || !bytes.Equal(raw[:len(prefix)], []byte(prefix)) {
		return nil, referenceInputError("invalid signing frame purpose or bounds")
	}
	fields := make([][]byte, count)
	offset := len(prefix)
	for i := range count {
		if len(raw)-offset < 4 {
			return nil, referenceInputError("truncated signing frame")
		}
		size := binary.BigEndian.Uint32(raw[offset : offset+4])
		offset += 4
		if size > MaxSigningTextBytes || size > uint32(len(raw)-offset) {
			return nil, referenceInputError("invalid signing field length")
		}
		fields[i] = raw[offset : offset+int(size)]
		offset += int(size)
	}
	if offset != len(raw) {
		return nil, referenceInputError("signing frame contains trailing fields or bytes")
	}
	return fields, nil
}
func copySigningDigest(field []byte, dest *[32]byte) bool {
	if len(field) != len(dest) {
		return false
	}
	copy(dest[:], field)
	return true
}
func decodeSigningCounter(field []byte) (uint64, bool) {
	if len(field) != 8 {
		return 0, false
	}
	value := binary.BigEndian.Uint64(field)
	return value, value > 0
}

func (f GenesisFrame) SigningBytes() ([]byte, error) {
	namespace, err := DomainNamespace(f.GenesisPublicKey[:])
	if err != nil || namespace != f.Namespace {
		return nil, referenceInputError("genesis namespace does not match its public key")
	}
	return encodeSigningFields(genesisSigningPurpose, []byte(f.Namespace), f.GenesisPublicKey[:], f.PayloadDigest[:])
}
func ParseGenesisFrame(raw []byte) (GenesisFrame, error) {
	var f GenesisFrame
	fields, err := decodeSigningFields(raw, genesisSigningPurpose, 3)
	if err != nil {
		return f, err
	}
	f.Namespace = string(fields[0])
	if !copySigningDigest(fields[1], &f.GenesisPublicKey) || !copySigningDigest(fields[2], &f.PayloadDigest) {
		return GenesisFrame{}, referenceInputError("genesis key and digest must be 32 bytes")
	}
	if _, err = f.SigningBytes(); err != nil {
		return GenesisFrame{}, err
	}
	return f, nil
}

func (f RegistryFrame) SigningBytes() ([]byte, error) {
	if !canonicalDomainNamespace(f.IssuerNamespace) || !canonicalDomainNamespace(f.AudienceDomain) || f.IssuerKeyRevision == 0 || f.Sequence == 0 || !validSigningText(f.ActionKind, false) || !validSigningText(string(f.ExpectedPriorRevision), true) || !validSigningText(string(f.NewRevision), false) {
		return nil, referenceInputError("invalid registry signing fields")
	}
	if _, err := ParseEndpointRef(f.ExactTargetRef.String()); err != nil {
		return nil, err
	}
	return encodeSigningFields(registrySigningPurpose, []byte(f.IssuerNamespace), signingCounter(f.IssuerKeyRevision), []byte(f.AudienceDomain), []byte(f.ActionKind), []byte(f.ExactTargetRef.String()), []byte(f.ExpectedPriorRevision), []byte(f.NewRevision), signingCounter(f.Sequence), f.PreviousHeadDigest[:], f.PayloadDigest[:])
}
func ParseRegistryFrame(raw []byte) (RegistryFrame, error) {
	var f RegistryFrame
	fields, err := decodeSigningFields(raw, registrySigningPurpose, 10)
	if err != nil {
		return f, err
	}
	f.IssuerNamespace = string(fields[0])
	f.AudienceDomain = string(fields[2])
	f.ActionKind = string(fields[3])
	f.ExpectedPriorRevision = Revision(fields[5])
	f.NewRevision = Revision(fields[6])
	var ok bool
	if f.IssuerKeyRevision, ok = decodeSigningCounter(fields[1]); !ok {
		return RegistryFrame{}, referenceInputError("invalid registry issuer key revision")
	}
	if f.Sequence, ok = decodeSigningCounter(fields[7]); !ok {
		return RegistryFrame{}, referenceInputError("invalid registry sequence")
	}
	if f.ExactTargetRef, err = ParseEndpointRef(string(fields[4])); err != nil {
		return RegistryFrame{}, err
	}
	if !copySigningDigest(fields[8], &f.PreviousHeadDigest) || !copySigningDigest(fields[9], &f.PayloadDigest) {
		return RegistryFrame{}, referenceInputError("registry digests must be 32 bytes")
	}
	if _, err = f.SigningBytes(); err != nil {
		return RegistryFrame{}, err
	}
	return f, nil
}

func (f CallerProofFrame) SigningBytes() ([]byte, error) {
	if !canonicalDomainNamespace(f.SourceDomain) || !canonicalDomainNamespace(f.AudienceDomain) || f.IssuerKeyRevision == 0 || !validSigningText(f.CallerRef, false) || !validSigningText(string(f.Operation), false) || !validSigningText(f.OriginalEnvelopeID, false) || !validSigningText(f.ReplayID, false) || !validSigningDeadline(f.Deadline) {
		return nil, referenceInputError("invalid caller proof signing fields")
	}
	return encodeSigningFields(callerSigningPurpose, []byte(f.SourceDomain), []byte(f.CallerRef), signingCounter(f.IssuerKeyRevision), []byte(f.AudienceDomain), []byte(f.Operation), []byte(f.OriginalEnvelopeID), []byte(f.ReplayID), f.OriginalEnvelopeDigest[:], []byte(f.Deadline))
}
func ParseCallerProofFrame(raw []byte) (CallerProofFrame, error) {
	var f CallerProofFrame
	fields, err := decodeSigningFields(raw, callerSigningPurpose, 9)
	if err != nil {
		return f, err
	}
	f.SourceDomain = string(fields[0])
	f.CallerRef = string(fields[1])
	f.AudienceDomain = string(fields[3])
	f.Operation = Operation(fields[4])
	f.OriginalEnvelopeID = string(fields[5])
	f.ReplayID = string(fields[6])
	f.Deadline = string(fields[8])
	var ok bool
	if f.IssuerKeyRevision, ok = decodeSigningCounter(fields[2]); !ok {
		return CallerProofFrame{}, referenceInputError("invalid caller issuer key revision")
	}
	if !copySigningDigest(fields[7], &f.OriginalEnvelopeDigest) {
		return CallerProofFrame{}, referenceInputError("original envelope digest must be 32 bytes")
	}
	if _, err = f.SigningBytes(); err != nil {
		return CallerProofFrame{}, err
	}
	return f, nil
}

func (f DispatchAdmissionFrame) SigningBytes() ([]byte, error) {
	if !canonicalDomainNamespace(f.SourceDomain) || !canonicalDomainNamespace(f.AudienceDomain) || !validSigningText(f.CallerRef, false) || !validSigningText(f.InvocationID, false) || !validSigningText(f.AttemptID, false) || !validSigningText(f.ReplayID, false) || !validSigningDeadline(f.Deadline) {
		return nil, referenceInputError("invalid dispatch admission signing fields")
	}
	return encodeSigningFields(admissionSigningPurpose, []byte(f.SourceDomain), []byte(f.CallerRef), []byte(f.AudienceDomain), []byte(f.InvocationID), []byte(f.AttemptID), []byte(f.ReplayID), f.FinalizedDispatchDigest[:], []byte(f.Deadline))
}
func ParseDispatchAdmissionFrame(raw []byte) (DispatchAdmissionFrame, error) {
	var f DispatchAdmissionFrame
	fields, err := decodeSigningFields(raw, admissionSigningPurpose, 8)
	if err != nil {
		return f, err
	}
	f.SourceDomain = string(fields[0])
	f.CallerRef = string(fields[1])
	f.AudienceDomain = string(fields[2])
	f.InvocationID = string(fields[3])
	f.AttemptID = string(fields[4])
	f.ReplayID = string(fields[5])
	f.Deadline = string(fields[7])
	if !copySigningDigest(fields[6], &f.FinalizedDispatchDigest) {
		return DispatchAdmissionFrame{}, referenceInputError("finalized dispatch digest must be 32 bytes")
	}
	if _, err = f.SigningBytes(); err != nil {
		return DispatchAdmissionFrame{}, err
	}
	return f, nil
}
