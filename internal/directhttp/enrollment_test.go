package directhttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func enrollmentFixture(t *testing.T) (Enrollment, string, string) {
	t.Helper()
	p, ch, proof, _, now := directV2TestFixture(t)
	raw, _ := ch.CanonicalBytes()
	sum := sha256.Sum256(raw)
	expires, _ := time.Parse(time.RFC3339Nano, p.Descriptor.ExpiresAt)
	proofRaw, _ := proof.CanonicalBytes()
	proofSum := sha256.Sum256(proofRaw)
	ph := ch.PublicationHash
	return Enrollment{
		DescriptorHash: ch.DescriptorHash, PublicationHash: &ph,
		Challenge:  &EnrollmentChallenge{ch, base64.RawURLEncoding.EncodeToString(sum[:])},
		Proof:      &EnrollmentProof{base64.RawURLEncoding.EncodeToString(proofSum[:]), now},
		Authority:  EnrollmentAuthority{ch.ParentGrantID, ch.GrantGeneration, ch.ChannelID, ch.ChannelGeneration, ch.EpochID, expires},
		ObservedAt: now.Add(time.Second),
	}, ch.CredentialID + ":" + directV2TestBinary(90, 32), ch.DirectIntentID
}

func enrollmentJSON(t *testing.T, v Enrollment) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEnrollmentRecovery(t *testing.T) {
	for _, state := range []string{"missing", "publication", "challenge", "proof", "historical proof", "active", "peer"} {
		t.Run(state, func(t *testing.T) {
			v, credential, id := enrollmentFixture(t)
			role := "S"
			switch state {
			case "missing":
				v.PublicationHash, v.Challenge, v.Proof = nil, nil, nil
			case "publication":
				v.Challenge, v.Proof = nil, nil
			case "challenge":
				v.Proof = nil
			case "historical proof":
				v.ObservedAt = v.ObservedAt.Add(10 * time.Minute)
			case "active":
				v.Activation = &EnrollmentActivation{v.ObservedAt, v.Authority.ExpiresAt}
			case "peer":
				role = "P"
				p, _, _, _, _ := directV2TestFixture(t)
				credential = p.Descriptor.P.CredentialID + ":" + directV2TestBinary(90, 32)
				v.Challenge.Challenge.Role = role
				v.Challenge.Challenge.CredentialID = p.Descriptor.P.CredentialID
				v.Challenge.Challenge.PrincipalID = p.Descriptor.P.PrincipalID
				v.Challenge.Challenge.EndpointID = p.Descriptor.P.EndpointID
				raw, _ := v.Challenge.Challenge.CanonicalBytes()
				sum := sha256.Sum256(raw)
				v.Challenge.TranscriptHash = base64.RawURLEncoding.EncodeToString(sum[:])
			}
			raw := enrollmentJSON(t, v)
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.RequestURI() != prefix+"/intents/"+id+"/enrollment" || r.Header.Get("Authorization") != "Pagnet-Direct-V2 "+credential || r.Header.Get("Accept") != "application/json" {
					t.Error("recovery request mismatch")
				}
				body, _ := io.ReadAll(r.Body)
				if len(body) != 0 || r.Header.Get("Content-Type") != "" {
					t.Error("recovery request body")
				}
				for _, h := range []string{"Cookie", "Origin", "Forwarded", "Sec-Fetch-Site", "User-Agent"} {
					if r.Header.Get(h) != "" {
						t.Errorf("unexpected %s", h)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(raw)
			})
			got, err := c.Enrollment(t.Context(), credential, id, role)
			if err != nil || !bytes.Equal(enrollmentJSON(t, got), raw) {
				t.Fatalf("recovery failed: %v", err)
			}
		})
	}
}

func TestEnrollmentRejectsMalformed(t *testing.T) {
	mutations := map[string]func(*Enrollment){
		"descriptor hash":               func(v *Enrollment) { v.DescriptorHash += "=" },
		"publication hash":              func(v *Enrollment) { *v.PublicationHash = "" },
		"parent uuid":                   func(v *Enrollment) { v.Authority.ParentGrantID = strings.ToUpper(v.Authority.ParentGrantID[:35]) + "A" },
		"epoch version":                 func(v *Enrollment) { v.Authority.EpochID = directV2TestID(3) },
		"generation":                    func(v *Enrollment) { v.Authority.GrantGeneration = "01" },
		"generation overflow":           func(v *Enrollment) { v.Authority.ChannelGeneration = "18446744073709551616" },
		"channel":                       func(v *Enrollment) { v.Authority.ChannelID = "" },
		"zero time":                     func(v *Enrollment) { v.ObservedAt = time.Time{} },
		"offset time":                   func(v *Enrollment) { v.ObservedAt = v.ObservedAt.In(time.FixedZone("offset", 3600)) },
		"expired authority":             func(v *Enrollment) { v.ObservedAt = v.Authority.ExpiresAt },
		"role":                          func(v *Enrollment) { v.Challenge.Challenge.Role = "P" },
		"credential":                    func(v *Enrollment) { v.Challenge.Challenge.CredentialID = directV2TestID(99) },
		"intent":                        func(v *Enrollment) { v.Challenge.Challenge.DirectIntentID = directV2TestID(99) },
		"transcript":                    func(v *Enrollment) { v.Challenge.TranscriptHash = directV2TestBinary(99, 32) },
		"challenge authority":           func(v *Enrollment) { v.Challenge.Challenge.ChannelGeneration = "3" },
		"challenge without publication": func(v *Enrollment) { v.PublicationHash = nil },
		"proof without challenge":       func(v *Enrollment) { v.Challenge = nil },
		"proof digest":                  func(v *Enrollment) { v.Proof.Digest += "=" },
		"proof outside challenge":       func(v *Enrollment) { v.Proof.ReceivedAt = v.ObservedAt.Add(10 * time.Minute) },
		"activation without proof": func(v *Enrollment) {
			v.Proof = nil
			v.Activation = &EnrollmentActivation{v.ObservedAt, v.Authority.ExpiresAt}
		},
		"activation expiry": func(v *Enrollment) {
			v.Activation = &EnrollmentActivation{v.ObservedAt, v.Authority.ExpiresAt.Add(time.Second)}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v, credential, id := enrollmentFixture(t)
			mutate(&v)
			if v.Challenge != nil && name != "transcript" {
				raw, _ := v.Challenge.Challenge.CanonicalBytes()
				sum := sha256.Sum256(raw)
				v.Challenge.TranscriptHash = base64.RawURLEncoding.EncodeToString(sum[:])
			}
			assertEnrollmentProtocol(t, credential, id, enrollmentJSON(t, v))
		})
	}
	v, credential, id := enrollmentFixture(t)
	raw := string(enrollmentJSON(t, v))
	for name, body := range map[string]string{
		"missing field":    strings.Replace(raw, `"activation":null,`, "", 1),
		"unknown field":    strings.TrimSuffix(raw, "}") + `,"readinessVerifier":"secret"}`,
		"nested duplicate": strings.Replace(raw, `"digest":`, `"digest":"ignored","digest":`, 1),
		"nested unknown":   strings.Replace(raw, `"receivedAt":`, `"secret":"ignored","receivedAt":`, 1),
		"duplicate field":  strings.TrimSuffix(raw, "}") + `,"activation":null}`,
		"null authority":   strings.Replace(raw, `"authority":{`, `"authority":null,"other":{`, 1),
		"whitespace":       " " + raw,
		"trailing":         raw + "{}",
		"oversized":        strings.Repeat("x", 8193),
	} {
		t.Run(name, func(t *testing.T) { assertEnrollmentProtocol(t, credential, id, []byte(body)) })
	}
}

func assertEnrollmentProtocol(t *testing.T, credential, id string, raw []byte) {
	t.Helper()
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	})
	got, err := c.Enrollment(t.Context(), credential, id, "S")
	var typed *Error
	if !errors.As(err, &typed) || typed.Kind != Protocol || typed.UnknownCommit || got.DescriptorHash != "" {
		t.Fatalf("malformed recovery classification: %v", err)
	}
}

func TestEnrollmentFailures(t *testing.T) {
	_, credential, id := enrollmentFixture(t)
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid request reached server") })
	for _, input := range [][3]string{{credential, id, "other"}, {credential + "=", id, "S"}, {credential, "bad", "S"}} {
		_, err := c.Enrollment(t.Context(), input[0], input[1], input[2])
		var typed *Error
		if !errors.As(err, &typed) || typed.Kind != Invalid || typed.UnknownCommit {
			t.Fatalf("invalid input: %v", err)
		}
	}
	for _, status := range []int{401, 404, 409, 503, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			hits := 0
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				hits++
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(status)
			})
			_, err := c.Enrollment(t.Context(), credential, id, "S")
			var typed *Error
			if !errors.As(err, &typed) || typed.Status != status || typed.UnknownCommit || hits != 1 {
				t.Fatalf("read failure classification: %v", err)
			}
		})
	}
}

func TestEnrollmentReadFailures(t *testing.T) {
	_, credential, id := enrollmentFixture(t)
	for _, mode := range []string{"disconnect", "truncated", "streamed oversize", "content type"} {
		t.Run(mode, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if mode == "disconnect" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "truncated":
					w.Header().Set("Content-Length", "100")
					io.WriteString(w, "{")
				case "streamed oversize":
					w.(http.Flusher).Flush()
					io.WriteString(w, strings.Repeat("x", 8193))
				case "content type":
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					io.WriteString(w, "{}")
				}
			})
			_, err := c.Enrollment(t.Context(), credential, id, "S")
			var typed *Error
			kind := Protocol
			if mode == "disconnect" {
				kind = Transport
			}
			if !errors.As(err, &typed) || typed.Kind != kind || typed.UnknownCommit || strings.Contains(err.Error(), credential) {
				t.Fatalf("read failure classification: %v", err)
			}
		})
	}
}
