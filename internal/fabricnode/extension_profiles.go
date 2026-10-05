package fabricnode

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/events/durable"
	"github.com/pagnet-code/pagnet/fabric/localinstallation"
	"github.com/pagnet-code/pagnet/fabric/registry"
)

const extensionHTTPProtocol = "pagnet.interceptor.http.v1"
const extensionProfilesID = "pagnet.extensions.profiles"

type ExtensionProfile struct {
	Protocol           string `json:"protocol"`
	URL                string `json:"url"`
	CredentialSelector string `json:"credentialSelector"`
	MaxConcurrency     int    `json:"maxConcurrency"`
	AllowHTTP          bool   `json:"allowHttp,omitempty"`
}
type extensionProfilesHeader struct {
	Format             uint32
	MaxProfiles, Count int
	Key                durable.KeyReference
}
type extensionCipher struct {
	Cipher []byte `json:"cipher"`
}
type ExtensionProfiles struct {
	installation *localinstallation.Installation
	root         registry.AuthorityIdentity
	maxProfiles  int
}

func extensionProfileKey(id string) registry.AuthorityKey {
	return registry.AuthorityKey{Kind: registry.AuthorityExtensionConfiguration, ID: id}
}
func validExtensionProfile(p ExtensionProfile) error {
	if p.Protocol != extensionHTTPProtocol {
		return fabric.NewError(fabric.CodeUnsupported, "Selected interceptor protocol is not installed")
	}
	u, e := url.Parse(p.URL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || len(p.URL) > 4096 || strings.ContainsAny(p.URL, "\x00\r\n") || p.MaxConcurrency < 1 || p.MaxConcurrency > 256 || !fabric.ValidNamespacedName(p.CredentialSelector) || len(p.CredentialSelector) > 256 {
		return fabric.NewError(fabric.CodeInvalidInput, "Invalid explicitly selected interceptor profile")
	}
	if u.Scheme == "http" && !p.AllowHTTP {
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fabric.NewError(fabric.CodeInvalidInput, "Select HTTPS or explicitly allow HTTP for this interceptor")
		}
	}
	return nil
}
func extensionProfileDigest(p ExtensionProfile) string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func (p *ExtensionProfiles) aad(id string) []byte {
	raw, _ := json.Marshal(struct {
		Purpose, Domain, Store, ID string
		Key                        durable.KeyReference
	}{"pagnet.extension.profile.v1", p.root.Namespace, p.root.StoreID, id, p.installation.Keys.Reference()})
	return raw
}
func (p *ExtensionProfiles) seal(id string, value any) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 8192 {
		return nil, localDenied()
	}
	defer clear(raw)
	cipher, e := p.installation.Keys.Seal(p.aad(id), raw)
	if e != nil {
		return nil, e
	}
	return json.Marshal(extensionCipher{cipher})
}
func (p *ExtensionProfiles) decode(id string, row registry.AuthorityRecord, out any) error {
	if row.Key != extensionProfileKey(id) || row.Retired || registry.VerifyAuthorityRecord(p.root, row) != nil {
		return localDenied()
	}
	var box extensionCipher
	if fabric.DecodeJSONWithLimits(row.Value, &box, fabric.WireLimits{MaxBytes: 16 << 10, MaxDepth: 4, MaxMembers: 4}) != nil || len(box.Cipher) > 8192+64 {
		return localDenied()
	}
	raw, e := p.installation.Keys.Open(p.aad(id), box.Cipher)
	if e != nil {
		return e
	}
	defer clear(raw)
	return fabric.DecodeJSONWithLimits(raw, out, fabric.WireLimits{MaxBytes: 8192, MaxDepth: 8, MaxMembers: 32})
}
func extensionProfilesFor(i *localinstallation.Installation, max int) (*ExtensionProfiles, error) {
	if i == nil || i.Store == nil || i.Keys == nil || max < 1 || max > 256 {
		return nil, localDenied()
	}
	return &ExtensionProfiles{i, i.Store.AuthorityIdentity(), max}, nil
}
func initializeExtensionProfiles(ctx context.Context, i *localinstallation.Installation, max int) error {
	p, e := extensionProfilesFor(i, max)
	if e != nil {
		return e
	}
	owner, e := i.Operator(ctx)
	if e != nil {
		return e
	}
	value, e := p.seal(extensionProfilesID, extensionProfilesHeader{1, max, 0, i.Keys.Reference()})
	if e != nil {
		return e
	}
	return i.WithCurrentOperator(ctx, owner, func(c context.Context) error {
		return i.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
			row, err := tx.Get(extensionProfileKey(extensionProfilesID))
			if err == nil {
				var h extensionProfilesHeader
				if p.decode(extensionProfilesID, row, &h) != nil || h.Format != 1 || h.MaxProfiles != max || h.Count < 0 || h.Count > max || h.Key != i.Keys.Reference() {
					return localDenied()
				}
				return nil
			}
			var f *fabric.Error
			if !errors.As(err, &f) || f.Code != fabric.CodeNotFound {
				return err
			}
			_, err = tx.CAS(extensionProfileKey(extensionProfilesID), 0, value, false)
			return err
		})
	})
}

// OpenExtensionProfiles is startup-only; missing state is not initialized here.
func OpenExtensionProfiles(ctx context.Context, i *localinstallation.Installation, max int) (*ExtensionProfiles, error) {
	p, e := extensionProfilesFor(i, max)
	if e != nil {
		return nil, e
	}
	owner, e := i.Operator(ctx)
	if e != nil {
		return nil, e
	}
	e = i.WithCurrentOperator(ctx, owner, func(c context.Context) error {
		return i.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{HistoryOnly: true}, func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(extensionProfileKey(extensionProfilesID))
			if e != nil {
				return e
			}
			var h extensionProfilesHeader
			if p.decode(extensionProfilesID, row, &h) != nil || h.Format != 1 || h.MaxProfiles != max || h.Count < 0 || h.Count > max || h.Key != i.Keys.Reference() {
				return localDenied()
			}
			return nil
		})
	})
	return p, e
}

// Put is an explicit operator setup. Profiles are immutable/content-addressed;
// selecting another URL/credential slot requires a new binding commitment.
func (p *ExtensionProfiles) Put(ctx context.Context, profile ExtensionProfile) (string, error) {
	if p == nil {
		return "", localDenied()
	}
	if e := validExtensionProfile(profile); e != nil {
		return "", e
	}
	digest := extensionProfileDigest(profile)
	id := "pagnet.extensions.profile." + digest
	value, e := p.seal(id, profile)
	if e != nil {
		return "", e
	}
	owner, e := p.installation.Operator(ctx)
	if e != nil {
		return "", e
	}
	e = p.installation.WithCurrentOperator(ctx, owner, func(c context.Context) error {
		return p.installation.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{}, func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(extensionProfileKey(extensionProfilesID))
			if e != nil {
				return e
			}
			var h extensionProfilesHeader
			if p.decode(extensionProfilesID, row, &h) != nil || h.Format != 1 || h.MaxProfiles != p.maxProfiles || h.Count < 0 || h.Count > h.MaxProfiles {
				return localDenied()
			}
			prior, e := tx.Get(extensionProfileKey(id))
			if e == nil {
				var old ExtensionProfile
				if p.decode(id, prior, &old) != nil || old != profile {
					return localDenied()
				}
				return nil
			}
			var f *fabric.Error
			if !errors.As(e, &f) || f.Code != fabric.CodeNotFound {
				return e
			}
			if h.Count == h.MaxProfiles {
				return fabric.NewError(fabric.CodeTargetUnavailable, "Private interceptor profile capacity reached")
			}
			h.Count++
			header, e := p.seal(extensionProfilesID, h)
			if e != nil {
				return e
			}
			if _, e = tx.CAS(extensionProfileKey(id), 0, value, false); e != nil {
				return e
			}
			_, e = tx.CAS(extensionProfileKey(extensionProfilesID), row.Revision, header, false)
			return e
		})
	})
	return digest, e
}
func (p *ExtensionProfiles) Get(ctx context.Context, digest string) (ExtensionProfile, error) {
	var profile ExtensionProfile
	decoded, e := hex.DecodeString(digest)
	if p == nil || e != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != digest {
		return profile, localDenied()
	}
	owner, e := p.installation.Operator(ctx)
	if e != nil {
		return profile, e
	}
	id := "pagnet.extensions.profile." + digest
	e = p.installation.WithCurrentOperator(ctx, owner, func(c context.Context) error {
		return p.installation.Store.WithNativeAuthority(c, owner, registry.AuthorityScope{HistoryOnly: true}, func(tx *registry.AuthorityTx) error {
			row, e := tx.Get(extensionProfileKey(id))
			if e != nil {
				return e
			}
			if row.Revision != 1 {
				return localDenied()
			}
			return p.decode(id, row, &profile)
		})
	})
	if e == nil && (validExtensionProfile(profile) != nil || extensionProfileDigest(profile) != digest) {
		e = localDenied()
	}
	return profile, e
}
