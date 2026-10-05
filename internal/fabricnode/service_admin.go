package fabricnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pagnet-code/pagnet/fabric"
	"github.com/pagnet-code/pagnet/fabric/adapters/mcp"
	"github.com/pagnet-code/pagnet/fabric/registry"
	"github.com/pagnet-code/pagnet/internal/fabricadmin"
	"github.com/pagnet-code/pagnet/internal/fabricauth"
	"github.com/pagnet-code/pagnet/internal/fabricservices"
)

type ServiceAddInput struct {
	URL                string `json:"url"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	ProtocolVersion    string `json:"protocolVersion,omitempty"`
	CredentialSelector string `json:"credentialSelector,omitempty"`
	AllowHTTP          bool   `json:"allowHttp,omitempty"`
}
type ServiceAddResult struct {
	Ref             fabric.EndpointRef `json:"ref"`
	Revision        fabric.Revision    `json:"revision,omitempty"`
	Name            string             `json:"name"`
	State           string             `json:"state"`
	ProtocolVersion string             `json:"protocolVersion,omitempty"`
	ErrorCode       fabric.ErrorCode   `json:"errorCode,omitempty"`
}

func validateServiceAdd(v *ServiceAddInput) error {
	u, e := url.Parse(v.URL)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(v.URL) > 4096 || strings.ContainsAny(v.URL, "\x00\r\n") || (u.Scheme != "https" && u.Scheme != "http") {
		return fabric.NewError(fabric.CodeInvalidInput, "Provide a selected MCP URL without embedded credentials or query tokens")
	}
	if u.Scheme == "http" && !v.AllowHTTP {
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fabric.NewError(fabric.CodeInvalidInput, "Use HTTPS or explicitly select --allow-http for this MCP endpoint")
		}
		v.AllowHTTP = true
	}
	if v.Name == "" {
		v.Name = u.Hostname()
	}
	if v.CredentialSelector == "" {
		v.CredentialSelector = "none"
	}
	if strings.TrimSpace(v.Name) == "" || len(v.Name) > 256 || strings.ContainsAny(v.Name, "\x00\r\n") || strings.TrimSpace(v.Description) == "" || len(v.Description) > 4096 || strings.ContainsRune(v.Description, 0) || len(v.ProtocolVersion) > 128 || strings.ContainsAny(v.ProtocolVersion, "\x00\r\n") || len(v.CredentialSelector) > 256 || strings.ContainsAny(v.CredentialSelector, "\x00\r\n") {
		return fabric.NewError(fabric.CodeInvalidInput, "Service name and network-facing description required")
	}
	if v.ProtocolVersion != "" && !slices.Contains(sdkmcp.SupportedProtocolVersions(), v.ProtocolVersion) {
		return fabric.NewError(fabric.CodeUnsupported, "The explicitly selected MCP protocol version is not supported by this SDK")
	}
	return nil
}

// ServiceAdministration performs metadata setup through current kernel-owner
// administration, never invocation authority or a provider paid effect.
func (n *InstalledNode) ServiceAdministration() map[string]fabricadmin.Handler {
	return map[string]fabricadmin.Handler{"service.add": func(ctx context.Context, access *fabricauth.OwnerAdministration, r fabricadmin.Request) (json.RawMessage, error) {
		if n == nil || n.Installation == nil || access == nil || r.Operation != "service.add" || r.ExpectedRevision != "" || access.VerifyCurrent(ctx) != nil {
			return nil, localDenied()
		}
		if n.Runtime == nil || n.Services == nil || n.Publisher == nil {
			return nil, fabric.NewError(fabric.CodeUnsupported, "Initialize service support with pagnet init, then restart the local node")
		}
		var v ServiceAddInput
		if fabric.DecodeJSON(r.Input, &v) != nil {
			return nil, localDenied()
		}
		decoder := json.NewDecoder(bytes.NewReader(r.Input))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&v) != nil {
			return nil, fabric.NewError(fabric.CodeInvalidInput, "Unsupported service setup fields")
		}
		if e := validateServiceAdd(&v); e != nil {
			return nil, e
		}
		settings, e := LoadInstalledServiceSettings(ctx, n.Installation)
		if e != nil || settings == nil {
			return nil, localDenied()
		}
		if settings.ProviderSelector == "credentials.none" && v.CredentialSelector != "none" {
			return nil, fabric.NewError(fabric.CodeUnsupported, "This installation explicitly selects credential-free services only")
		}
		owner, e := n.Installation.Operator(ctx)
		if e != nil {
			return nil, e
		}
		if access.PrincipalView() != owner.PrincipalView() {
			return nil, localDenied()
		}
		var out json.RawMessage
		e = n.Installation.WithCurrentOperator(ctx, owner, func(current context.Context) error {
			credentials, e := n.Services.config.Credentials.Resolve(current, v.CredentialSelector)
			if e != nil {
				return fabric.NewError(fabric.CodeUnauthenticated, "The explicitly selected private service credential provider is unavailable")
			}
			if credentials.BindingDigest == [32]byte{} {
				return localDenied()
			}
			canonical, e := json.Marshal(struct {
				Input    ServiceAddInput
				Account  [32]byte
				Provider string
			}{v, credentials.BindingDigest, settings.ProviderSelector})
			if e != nil {
				return e
			}
			defer clear(canonical)
			ref, e := n.ReserveSetupEndpoint(current, access, "service.add", r.ID, canonical)
			if e != nil {
				return e
			}
			result := ServiceAddResult{Ref: ref, Name: v.Name, State: "incomplete"}
			version, e := n.serviceSetupVersion(current, owner, access, r.ID, ref, sha256.Sum256(canonical), v, credentials)
			if e != nil {
				var failure *fabric.Error
				if !errors.As(e, &failure) || failure.Code != fabric.CodeTargetUnavailable {
					return e
				}
				result.ErrorCode = fabric.CodeTargetUnavailable
				out, _ = json.Marshal(result)
				return nil
			}
			result.ProtocolVersion = version
			if e = access.VerifyCurrent(current); e != nil {
				return e
			}
			revision, e := n.Installation.Store.Register(current, owner, fabric.RegistryUpdate{Descriptor: fabric.EndpointDescriptor{Ref: ref, Kind: "service.mcp", Name: v.Name, Description: v.Description, Bindings: []fabric.BindingSummary{{ID: "mcp", Protocol: "mcp.tools", Version: version, Cancellation: true, Idempotency: true}}}})
			if e != nil {
				return e
			}
			result.Revision = revision
			scope := registry.DescriptorBatchScope{Endpoint: ref, ExpectedEndpointRevision: revision, BindingID: "mcp"}
			_, e = n.Services.Profiles.Install(current, scope, fabricservices.Profile{Protocol: "mcp.tools", Version: version, CredentialSelector: v.CredentialSelector, BindingDigest: credentials.BindingDigest, MCP: &fabricservices.MCPProfile{URL: v.URL, AllowHTTP: v.AllowHTTP, Limits: mcp.DefaultLimits}})
			if e != nil {
				return e
			}
			if e = access.VerifyCurrent(current); e != nil {
				return e
			}
			n.Publisher.Notify()
			bootstrap := false
			if _, probeErr := n.Installation.Store.ReadBindingProjection(current, owner, scope, "", 1); authorityMissing(probeErr) {
				bootstrap = true
			} else if probeErr != nil {
				return probeErr
			}
			if e = n.Services.Connect(current, scope, bootstrap); e != nil {
				result.State = "offline"
				for _, status := range n.Services.Status() {
					if status.Selection.Scope == scope && status.Connecting {
						result.State = "connecting"
					}
				}
				result.ErrorCode = fabric.CodeTargetUnavailable
			} else {
				result.State = "connected"
			}
			out, e = json.Marshal(result)
			return e
		})
		return out, e
	}}
}

type setupProtocol struct {
	Version  int
	InputSHA [32]byte
	Ref      fabric.EndpointRef
	Protocol string
}

func (n *InstalledNode) serviceSetupVersion(ctx context.Context, owner fabric.ExecutionContext, access *fabricauth.OwnerAdministration, id string, ref fabric.EndpointRef, inputSHA [32]byte, v ServiceAddInput, credentials fabricservices.Credentials) (string, error) {
	digest := sha256.Sum256([]byte("pagnet.service.protocol.v1\x00" + id))
	key := registry.AuthorityKey{Kind: registry.AuthorityLocalInstallation, ID: "service/protocol/" + hex.EncodeToString(digest[:])}
	aad := []byte(n.Installation.Store.Namespace() + "/" + key.ID)
	var saved setupProtocol
	read := func(tx *registry.AuthorityTx) error {
		row, e := tx.Get(key)
		if e != nil {
			return e
		}
		if row.Retired {
			return localDenied()
		}
		var box setupCreateCipher
		if fabric.DecodeJSON(row.Value, &box) != nil {
			return localDenied()
		}
		raw, e := n.Installation.Keys.Open(aad, box.Cipher)
		if e != nil {
			return localDenied()
		}
		defer clear(raw)
		if fabric.DecodeJSON(raw, &saved) != nil || saved.Version != 1 || saved.InputSHA != inputSHA || saved.Ref != ref || saved.Protocol == "" {
			return localDenied()
		}
		return nil
	}
	e := n.Installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 2, Timeout: 5 * time.Second}, read)
	if e == nil {
		return saved.Protocol, nil
	}
	if !authorityMissing(e) {
		return "", e
	}
	version := v.ProtocolVersion
	if version == "" {
		standard, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return "", fabric.NewError(fabric.CodeUnsupported, "Selected MCP setup requires an explicit supported HTTP transport")
		}
		base := standard.Clone()
		base.Proxy = nil
		base.MaxResponseHeaderBytes = 64 << 10
		base.ResponseHeaderTimeout = 10 * time.Second
		base.MaxConnsPerHost = 4
		defer base.CloseIdleConnections()
		probe, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		version, e = mcp.NegotiateRemote(probe, mcp.RemoteFactory{Endpoint: v.URL, AllowHTTP: v.AllowHTTP, Client: &http.Client{Transport: base}}, credentials.MCP, mcp.DefaultLimits)
		if e != nil {
			return "", e
		}
	}
	if e = access.VerifyCurrent(ctx); e != nil {
		return "", e
	}
	raw, _ := json.Marshal(setupProtocol{1, inputSHA, ref, version})
	defer clear(raw)
	cipher, e := n.Installation.Keys.Seal(aad, raw)
	if e != nil {
		return "", e
	}
	defer clear(cipher)
	box, _ := json.Marshal(setupCreateCipher{cipher})
	defer clear(box)
	e = n.Installation.Store.WithNativeAuthority(ctx, owner, registry.AuthorityScope{MaxOperations: 3, Timeout: 5 * time.Second}, func(tx *registry.AuthorityTx) error {
		if e := read(tx); e == nil {
			if saved.Protocol != version {
				return localDenied()
			}
			return nil
		} else if !authorityMissing(e) {
			return e
		}
		_, e := tx.CAS(key, 0, box, false)
		return e
	})
	return version, e
}
