package sdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const textInstallationID = "eb8a664b-f7b8-4712-a90e-670a20bf4e68"
const textClaimID = "9c43a289-d8af-4e2e-a09e-87c1fc50defe"
const textEndpointID = "748b494c-a7c2-44bf-a68e-bb060b6787c1"

func textProofInput() TextServiceInstallationProof {
	return TextServiceInstallationProof{InstallationID: textInstallationID, ClaimID: textClaimID, Generation: 2, Nonce: bytes.Repeat([]byte{0xfb}, 32)}
}
func textProofClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c := &Client{cur: &conn{dead: make(chan struct{})}}
	c.endpointID.Store(textEndpointID)
	c.credential.Store("pgn_epd_v1_current-secret")
	c.connected.Store(true)
	c.rest = newRestClient(server.URL, "proof-test", func() string { return c.credential.Load().(string) })
	return c
}
func textProofResponse() TextServiceReadiness {
	claim := textClaimID
	expiry := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	return TextServiceReadiness{InstallationID: textInstallationID, Generation: 2, ClaimID: &claim, ClaimExpiresAt: &expiry, Ready: true}
}

func TestProveTextServiceInstallationCurrentEndpoint(t *testing.T) {
	proof := textProofInput()
	credential := "pgn_epd_v1_rotated-secret"
	endpoint := "f6ac6a1b-677e-42dc-a641-112198a736ed"
	calls := 0
	c := textProofClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sharing/text-services/installations/"+textInstallationID+"/prove" || r.URL.RawQuery != "" {
			t.Error("wrong proof route")
		}
		if r.Header.Get("Authorization") != "Bearer "+credential || r.Header.Get("Content-Type") != "application/json" {
			t.Error("proof did not use current endpoint credential")
		}
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body) != 4 {
			t.Error("unexpected proof fields")
		}
		var got struct {
			ClaimID    string `json:"claimId"`
			Generation int64  `json:"generation"`
			Nonce      string `json:"nonce"`
			EndpointID string `json:"endpointId"`
		}
		raw, _ := json.Marshal(body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(got.Nonce)
		if err != nil || !bytes.Equal(decoded, proof.Nonce) || base64.StdEncoding.EncodeToString(decoded) != got.Nonce || got.ClaimID != proof.ClaimID || got.Generation != proof.Generation || got.EndpointID != endpoint {
			t.Error("incorrect proof body or endpoint identity")
		}
		// Unknown secret-bearing response fields must never enter the typed result.
		out, _ := json.Marshal(textProofResponse())
		out = append(out[:len(out)-1], []byte(`,"nonce":"response-secret","credential":"response-secret"}`)...)
		w.Write(out)
	})
	c.credential.Store(credential)
	c.endpointID.Store(endpoint)
	for i := 0; i < 2; i++ {
		got, err := c.ProveTextServiceInstallation(context.Background(), proof)
		if err != nil || !got.Ready || got.InstallationID != proof.InstallationID || got.ClaimID == nil || *got.ClaimID != proof.ClaimID || got.Generation != proof.Generation || got.ClaimExpiresAt == nil {
			t.Fatalf("proof metadata: %v", err)
		}
		raw, _ := json.Marshal(got)
		for _, secret := range []string{base64.StdEncoding.EncodeToString(proof.Nonce), credential, "response-secret"} {
			if strings.Contains(string(raw), secret) {
				t.Fatal("proof returned secret material")
			}
		}
	}
	if calls != 2 {
		t.Fatal("explicit exact retry changed request count")
	}
}

func TestProveTextServiceInstallationInvalidInputNoNetwork(t *testing.T) {
	calls := 0
	c := textProofClient(t, func(w http.ResponseWriter, r *http.Request) { calls++; t.Error("invalid input reached server") })
	for _, kind := range []string{"installation", "claim", "zero generation", "negative generation", "short nonce", "long nonce", "nil nonce"} {
		t.Run(kind, func(t *testing.T) {
			proof := textProofInput()
			switch kind {
			case "installation":
				proof.InstallationID = "../escape"
			case "claim":
				proof.ClaimID = "00000000-0000-0000-0000-000000000000"
			case "zero generation":
				proof.Generation = 0
			case "negative generation":
				proof.Generation = -1
			case "short nonce":
				proof.Nonce = proof.Nonce[:31]
			case "long nonce":
				proof.Nonce = append(proof.Nonce, 0)
			case "nil nonce":
				proof.Nonce = nil
			}
			if _, err := c.ProveTextServiceInstallation(context.Background(), proof); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	for _, kind := range []string{"disconnected", "host credential", "missing endpoint", "closed"} {
		t.Run(kind, func(t *testing.T) {
			c.connected.Store(true)
			c.closed.Store(false)
			c.endpointID.Store(textEndpointID)
			c.credential.Store("pgn_epd_v1_current-secret")
			switch kind {
			case "disconnected":
				c.connected.Store(false)
			case "host credential":
				c.credential.Store("pgn_host_v1_secret")
			case "missing endpoint":
				c.endpointID.Store("")
			case "closed":
				c.closed.Store(true)
			}
			if _, err := c.ProveTextServiceInstallation(context.Background(), textProofInput()); err == nil {
				t.Fatal("invalid endpoint accepted")
			}
		})
	}
	if calls != 0 {
		t.Fatal("invalid proof caused network request")
	}
}

func TestProveTextServiceInstallationServerErrorsAndExplicitRetry(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusInternalServerError, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			var firstBody []byte
			c := textProofClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				body, _ := io.ReadAll(r.Body)
				if calls == 1 {
					firstBody = body
					w.Header().Set("Location", "/unexpected-redirect")
					w.WriteHeader(status)
					w.Write(append(body, []byte(r.Header.Get("Authorization"))...))
					return
				}
				if !bytes.Equal(firstBody, body) {
					t.Error("explicit retry changed proof")
				}
				json.NewEncoder(w).Encode(textProofResponse())
			})
			got, err := c.ProveTextServiceInstallation(context.Background(), textProofInput())
			if err == nil || got.InstallationID != "" || calls != 1 {
				t.Fatal("failed proof retried or returned metadata")
			}
			for _, secret := range []string{base64.StdEncoding.EncodeToString(textProofInput().Nonce), "pgn_epd_v1_current-secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("proof error exposed secret material")
				}
			}
			if status == http.StatusUnauthorized && !errors.Is(err, ErrCredentialDead) {
				t.Fatal("credential failure sentinel lost")
			}
			if status != http.StatusUnauthorized {
				var re *restError
				if !errors.As(err, &re) || re.status != status {
					t.Fatal("server status lost")
				}
			}
			if _, err := c.ProveTextServiceInstallation(context.Background(), textProofInput()); err != nil || calls != 2 {
				t.Fatal("explicit retry failed")
			}
		})
	}
}

func TestProveTextServiceInstallationRejectsWrongResponseBinding(t *testing.T) {
	for _, kind := range []string{"installation", "claim", "generation", "missing claim", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			c := textProofClient(t, func(w http.ResponseWriter, r *http.Request) {
				out := textProofResponse()
				switch kind {
				case "installation":
					out.InstallationID = textEndpointID
				case "claim":
					claim := textEndpointID
					out.ClaimID = &claim
				case "generation":
					out.Generation++
				case "missing claim":
					out.ClaimID = nil
				case "malformed":
					w.Write([]byte(`{"secret":"malformed-response-secret"`))
					return
				}
				json.NewEncoder(w).Encode(out)
			})
			got, err := c.ProveTextServiceInstallation(context.Background(), textProofInput())
			if err == nil || got.InstallationID != "" || strings.Contains(err.Error(), "malformed-response-secret") {
				t.Fatal("invalid response did not fail safely")
			}
		})
	}
}

func TestTextServiceInstallationProofRedactsNonce(t *testing.T) {
	proof := textProofInput()
	for _, value := range []any{proof, &proof} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 3 || fields["Nonce"] != nil || fields["nonce"] != nil {
			t.Fatal("proof JSON includes nonce")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			diagnostic := fmt.Sprintf(format, value)
			if !strings.Contains(diagnostic, "Nonce:[REDACTED]") || strings.Contains(diagnostic, string(proof.Nonce)) || strings.Contains(diagnostic, base64.StdEncoding.EncodeToString(proof.Nonce)) {
				t.Fatal("proof diagnostic did not redact nonce")
			}
		}
	}
}

func TestProveTextServiceInstallationKeepsSharedRedirectPolicy(t *testing.T) {
	requests := 0
	c := textProofClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Location", "/must-not-follow")
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	originalRest, originalHTTP := c.rest, c.rest.http
	marker := errors.New("original redirect policy")
	policyCalls := 0
	c.rest.http.CheckRedirect = func(*http.Request, []*http.Request) error { policyCalls++; return marker }
	if _, err := c.ProveTextServiceInstallation(context.Background(), textProofInput()); err == nil {
		t.Fatal("proof followed redirect")
	}
	if requests != 1 || policyCalls != 0 {
		t.Fatal("proof did not use isolated no-redirect policy")
	}
	if c.rest != originalRest || c.rest.http != originalHTTP || !errors.Is(c.rest.http.CheckRedirect(nil, nil), marker) || policyCalls != 1 {
		t.Fatal("proof changed shared REST redirect policy")
	}
}

func TestProveTextServiceInstallationRejectsReplacedEndpoint(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	c := textProofClient(t, func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		json.NewEncoder(w).Encode(textProofResponse())
	})
	endpoint, dead, err := c.TextServiceEndpointSession()
	if err != nil || endpoint != textEndpointID {
		t.Fatal("live session unavailable")
	}
	done := make(chan error, 1)
	go func() { _, err := c.ProveTextServiceInstallation(context.Background(), textProofInput()); done <- err }()
	<-entered
	c.connMu.Lock()
	close(c.cur.dead)
	c.cur = &conn{dead: make(chan struct{})}
	c.endpointID.Store("f6ac6a1b-677e-42dc-a641-112198a736ed")
	c.connMu.Unlock()
	close(release)
	if err = <-done; err == nil {
		t.Fatal("proof response survived endpoint replacement")
	}
	select {
	case <-dead:
	default:
		t.Fatal("old endpoint pin remained live")
	}
	fresh, freshDone, err := c.TextServiceEndpointSession()
	if err != nil || fresh == endpoint || freshDone == dead {
		t.Fatal("replacement inherited old session pin")
	}
}
