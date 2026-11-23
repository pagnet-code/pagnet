package transport

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pagnet-code/pagnet/domain"
)

const NativeShareSourceEnrollmentMaxBodyBytes = 16 * 1024

// NativeShareSourceHolderScope is public local provenance, not authorization.
// Its fields match the daemon's persisted source holder scope exactly.
type NativeShareSourceHolderScope struct {
	ServerURL string    `json:"serverUrl"`
	TenantID  domain.ID `json:"tenantId"`
	AccountID domain.ID `json:"accountId"`
	HostID    domain.ID `json:"hostId"`
}

// NativeShareSourceHolderDescriptor contains only dedicated public holder keys.
// Generation is a JSON number to match the local persisted descriptor.
type NativeShareSourceHolderDescriptor struct {
	Version        int                          `json:"version"`
	Scope          NativeShareSourceHolderScope `json:"scope"`
	InstallationID domain.ID                    `json:"installationId"`
	HolderID       domain.ID                    `json:"holderId"`
	Generation     uint64                       `json:"generation"`
	X25519         string                       `json:"x25519"`
	Ed25519        string                       `json:"ed25519"`
	Fingerprint    string                       `json:"fingerprint"`
}

// NativeShareSourceEnrollment binds a source selection to captured session
// evidence. Expiry, replay, registry and authorization checks remain caller duties.
type NativeShareSourceEnrollment struct {
	Version               int                       `json:"version"`
	EnrollmentID          domain.ID                 `json:"enrollmentId"`
	NetworkID             domain.ID                 `json:"networkId"`
	PreviousEpochID       domain.ID                 `json:"previousEpochId"`
	ProposalID            domain.ID                 `json:"proposalId"`
	ProposalRevision      uint64                    `json:"proposalRevision,string"`
	GrantID               domain.ID                 `json:"grantId"`
	GrantGeneration       uint64                    `json:"grantGeneration,string"`
	BindingID             domain.ID                 `json:"bindingId"`
	BindingDigest         string                    `json:"bindingDigest"`
	SourceInstanceID      domain.ID                 `json:"sourceInstanceId"`
	NativeGeneration      string                    `json:"nativeGeneration"`
	Subject               NativeShareBindingSubject `json:"subject"`
	ConnectedAt           string                    `json:"connectedAt"`
	HostCredentialID      string                    `json:"hostCredentialId"`
	OwnershipScope        string                    `json:"ownershipScope"`
	ConnectionID          string                    `json:"connectionId"`
	AuthorityConnectionID string                    `json:"authorityConnectionId"`
	ExpiresAt             string                    `json:"expiresAt"`
}

type NativeShareSourcePreparePayload struct {
	CommandID  domain.ID                   `json:"commandId"`
	Enrollment NativeShareSourceEnrollment `json:"enrollment"`
}

type NativeShareSourcePreparedPayload struct {
	Prepare          NativeShareSourcePreparePayload   `json:"prepare"`
	Descriptor       NativeShareSourceHolderDescriptor `json:"descriptor"`
	EnrollmentDigest string                            `json:"enrollmentDigest"`
	Signature        []byte                            `json:"signature"`
}

func nativeShareSourceURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && utf8.ValidString(s) && len(s) <= 2048 && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && !strings.ContainsAny(s, "?#") && !u.ForceQuery && u.RawQuery == "" && u.Fragment == "" && u.RawFragment == ""
}

func (s NativeShareSourceHolderScope) CanonicalBytes() ([]byte, error) {
	if !nativeShareSourceURL(s.ServerURL) || !nativeShareBindingID(s.TenantID) || !nativeShareBindingID(s.AccountID) || !nativeShareBindingID(s.HostID) {
		return nil, errNativeShareSource
	}
	return json.Marshal(s)
}

// DigestFingerprint uses the exact persisted descriptor representation with an
// empty fingerprint, including the fingerprint field itself.
func (d NativeShareSourceHolderDescriptor) DigestFingerprint() (string, error) {
	if _, err := d.Scope.CanonicalBytes(); err != nil {
		return "", err
	}
	if d.Version != 1 || d.Generation != 1 || !nativeShareBindingID(d.InstallationID) || !nativeShareBindingID(d.HolderID) || !nativeShareBindingHex(d.X25519) || !nativeShareBindingHex(d.Ed25519) {
		return "", errNativeShareSource
	}
	d.Fingerprint = ""
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (d NativeShareSourceHolderDescriptor) CanonicalBytes() ([]byte, error) {
	fingerprint, err := d.DigestFingerprint()
	if err != nil {
		return nil, err
	}
	if d.Fingerprint != fingerprint {
		return nil, errNativeShareSource
	}
	return json.Marshal(d)
}

func (e NativeShareSourceEnrollment) CanonicalBytes() ([]byte, error) {
	if e.Version != NativeShareSourceVersion || e.ProposalRevision == 0 || e.GrantGeneration == 0 || !nativeShareBindingHex(e.BindingDigest) || !nativeShareOpaque(e.NativeGeneration) || !nativeShareBindingTime(e.ConnectedAt) || !nativeShareBindingTime(e.ExpiresAt) {
		return nil, errNativeShareSource
	}
	for _, id := range []domain.ID{e.EnrollmentID, e.NetworkID, e.PreviousEpochID, e.ProposalID, e.GrantID, e.BindingID, e.SourceInstanceID} {
		if !nativeShareBindingID(id) {
			return nil, errNativeShareSource
		}
	}
	for _, s := range []string{e.HostCredentialID, e.OwnershipScope, e.ConnectionID, e.AuthorityConnectionID} {
		if !nativeShareOpaque(s) {
			return nil, errNativeShareSource
		}
	}
	if !nativeShareSourceURL(e.Subject.ServerURL) {
		return nil, errNativeShareSource
	}
	if _, err := e.Subject.CanonicalBytes(); err != nil {
		return nil, err
	}
	return nativeShareSourceEnrollmentMarshal(e)
}

func (p NativeShareSourcePreparePayload) CanonicalBytes() ([]byte, error) {
	if !nativeShareBindingID(p.CommandID) {
		return nil, errNativeShareSource
	}
	if _, err := p.Enrollment.CanonicalBytes(); err != nil {
		return nil, err
	}
	return nativeShareSourceEnrollmentMarshal(p)
}

func (p NativeShareSourcePreparedPayload) Digest() (string, error) {
	if _, err := p.Prepare.CanonicalBytes(); err != nil {
		return "", err
	}
	if _, err := p.Descriptor.CanonicalBytes(); err != nil {
		return "", err
	}
	s := p.Prepare.Enrollment.Subject
	if p.Descriptor.Scope != (NativeShareSourceHolderScope{ServerURL: s.ServerURL, TenantID: s.TenantID, AccountID: s.AccountID, HostID: s.HostID}) {
		return "", errNativeShareSource
	}
	raw, err := json.Marshal(struct {
		Prepare    NativeShareSourcePreparePayload   `json:"prepare"`
		Descriptor NativeShareSourceHolderDescriptor `json:"descriptor"`
	}{p.Prepare, p.Descriptor})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("pagnet/native-share-source/enrollment/v1/"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

func (p NativeShareSourcePreparedPayload) SignatureBytes() ([]byte, error) {
	digest, err := p.Digest()
	if err != nil {
		return nil, err
	}
	if p.EnrollmentDigest != digest {
		return nil, errNativeShareSource
	}
	return []byte("pagnet/native-share-source/prepared/v1/" + digest), nil
}

func (p NativeShareSourcePreparedPayload) CanonicalBytes() ([]byte, error) {
	if _, err := p.SignatureBytes(); err != nil {
		return nil, err
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return nil, errNativeShareSource
	}
	return nativeShareSourceEnrollmentMarshal(p)
}

func nativeShareSourcePrepareObject(raw []byte) error {
	fields, err := nativeShareSourceObject(raw, "commandId", "enrollment")
	if err != nil {
		return err
	}
	e, err := nativeShareSourceObject(fields["enrollment"], "version", "enrollmentId", "networkId", "previousEpochId", "proposalId", "proposalRevision", "grantId", "grantGeneration", "bindingId", "bindingDigest", "sourceInstanceId", "nativeGeneration", "subject", "connectedAt", "hostCredentialId", "ownershipScope", "connectionId", "authorityConnectionId", "expiresAt")
	if err != nil {
		return err
	}
	if _, err = nativeShareSourceObject(e["subject"], "serverUrl", "tenantId", "accountId", "hostId", "nativeAdmissionId", "runnerId", "runnerEpoch", "bootId", "profileFingerprint"); err != nil {
		return err
	}
	var enrollment NativeShareSourceEnrollment
	if json.Unmarshal(fields["enrollment"], &enrollment) != nil {
		return errNativeShareSource
	}
	for name, value := range map[string]uint64{"proposalRevision": enrollment.ProposalRevision, "grantGeneration": enrollment.GrantGeneration} {
		canonical, _ := json.Marshal(strconv.FormatUint(value, 10))
		if string(e[name]) != string(canonical) {
			return errNativeShareSource
		}
	}
	return nil
}

func DecodeNativeShareSourcePreparePayload(raw []byte) (NativeShareSourcePreparePayload, error) {
	var p NativeShareSourcePreparePayload
	if len(raw) > NativeShareSourceEnrollmentMaxBodyBytes || !utf8.Valid(raw) {
		return p, errNativeShareSource
	}
	if err := nativeShareSourcePrepareObject(raw); err != nil {
		return p, err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	_, err := p.CanonicalBytes()
	return p, err
}

func DecodeNativeShareSourcePreparedPayload(raw []byte) (NativeShareSourcePreparedPayload, error) {
	var p NativeShareSourcePreparedPayload
	if len(raw) > NativeShareSourceEnrollmentMaxBodyBytes || !utf8.Valid(raw) {
		return p, errNativeShareSource
	}
	fields, err := nativeShareSourceObject(raw, "prepare", "descriptor", "enrollmentDigest", "signature")
	if err != nil {
		return p, err
	}
	if err := nativeShareSourcePrepareObject(fields["prepare"]); err != nil {
		return p, err
	}
	d, err := nativeShareSourceObject(fields["descriptor"], "version", "scope", "installationId", "holderId", "generation", "x25519", "ed25519", "fingerprint")
	if err != nil {
		return p, err
	}
	if _, err := nativeShareSourceObject(d["scope"], "serverUrl", "tenantId", "accountId", "hostId"); err != nil {
		return p, err
	}
	var encoded string
	if json.Unmarshal(fields["signature"], &encoded) != nil {
		return p, errNativeShareSource
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return p, errNativeShareSource
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	_, err = p.CanonicalBytes()
	return p, err
}

// Verify uses a descriptor and dedicated signer retained from an authenticated
// command acknowledgement. It grants no source, membership or epoch authority.
func (p NativeShareSourcePreparedPayload) Verify(expected NativeShareSourcePreparePayload, descriptor NativeShareSourceHolderDescriptor, trustedSigner ed25519.PublicKey) error {
	if _, err := p.CanonicalBytes(); err != nil {
		return err
	}
	raw, err := p.SignatureBytes()
	if err != nil {
		return err
	}
	if p.Prepare != expected || p.Descriptor != descriptor || len(trustedSigner) != ed25519.PublicKeySize || hex.EncodeToString(trustedSigner) != descriptor.Ed25519 || len(p.Signature) != ed25519.SignatureSize || !ed25519.Verify(trustedSigner, raw, p.Signature) {
		return errNativeShareSource
	}
	return nil
}

func nativeShareSourceEnrollmentMarshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(raw) > NativeShareSourceEnrollmentMaxBodyBytes {
		return nil, errNativeShareSource
	}
	return raw, nil
}
