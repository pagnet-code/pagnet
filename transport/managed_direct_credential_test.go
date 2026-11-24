package transport

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pagnet-code/pagnet/domain"
)

func managedCredentialFixture(t *testing.T) (ManagedDirectCredentialIssue, []byte, []byte) {
	t.Helper()
	pop, host, _ := managedPoPFixture(t)
	proof, err := ConfirmManagedEndpointHostCustody(pop, host, pop.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	server := bytes.Repeat([]byte{0x53}, 32)
	key, _ := ecdh.X25519().NewPrivateKey(server)
	issue, err := NewManagedDirectCredentialIssue(ManagedDirectCredentialIssue{
		CredentialID: domain.ID("10000000-0000-4000-8000-00000000001b"), ChannelGeneration: 2,
		Nonce:                 base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x64}, 32)),
		ServerEphemeralX25519: hex.EncodeToString(key.PublicKey().Bytes()),
		IssuedAt:              pop.IssuedAt, InstallExpiresAt: pop.ExpiresAt,
		CredentialExpiresAt: pop.IssuedAt.Add(4 * time.Minute),
		Budget:              ManagedDirectCredentialBudgetReference{AgreementID: domain.ID("10000000-0000-4000-8000-00000000001c"), AcceptedRevision: 3, TermsDigest: strings.Repeat("ef", 32), ExpiresAt: pop.IssuedAt.Add(5 * time.Minute)},
	}, pop, proof)
	if err != nil {
		t.Fatal(err)
	}
	return issue, host, server
}

func TestManagedDirectCredentialGolden(t *testing.T) {
	issue, host, server := managedCredentialFixture(t)
	raw, err := issue.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secret, ack, err := DeriveManagedDirectCredentialHost(issue, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	ackRaw, err := ack.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	transcript, credentialHash, verifier, err := DeriveManagedDirectCredentialVerifier(issue, server, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, digest, err := DecodeManagedDirectCredentialACKVerifier(ackRaw)
	if err != nil || decoded != ack || digest != verifier || ack.TranscriptHash != transcript {
		t.Fatal("ACK verifier mismatch", err)
	}
	gotHash, err := ManagedDirectCredentialHash(transcript, secret)
	if err != nil || gotHash != credentialHash {
		t.Fatal("credential hash mismatch", err)
	}
	// Derive independently from the documented wire bytes and primitive operations.
	th := sha256.Sum256(append([]byte("pagnet/managed-direct-credential/transcript/v1/"), raw...))
	sk, _ := ecdh.X25519().NewPrivateKey(server)
	hk, _ := ecdh.X25519().NewPrivateKey(host)
	shared, err := sk.ECDH(hk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(shared)
	nonce, _ := base64.StdEncoding.DecodeString(issue.Nonce)
	wantSecret, err := hkdf.Key(sha256.New, shared, nonce, "pagnet/managed-direct-credential/credential-secret/v1/"+string(th[:]), 32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wantSecret)
	install, err := hkdf.Key(sha256.New, shared, nonce, "pagnet/managed-direct-credential/install-key/v1/"+string(th[:]), 32)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(install)
	mac := hmac.New(sha256.New, install)
	mac.Write([]byte("pagnet/managed-direct-credential/host-install/v1/"))
	mac.Write(th[:])
	if !hmac.Equal(secret, wantSecret) || transcript != hex.EncodeToString(th[:]) || ack.HostConfirmation != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("independent derivation mismatch")
	}
	for name, got := range map[string][]byte{"issue.json": raw, "ack.json": ackRaw, "transcript_hash.txt": []byte(transcript), "credential_hash.txt": []byte(credentialHash), "install_verifier.txt": []byte(verifier)} {
		path := filepath.Join("testdata", "managed_direct_credential_v1", name)
		if os.Getenv("UPDATE_MANAGED_CREDENTIAL_GOLDEN") == "1" {
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, got, 0644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("golden %s mismatch: %v", name, err)
		}
	}
	if _, err := DecodeManagedDirectCredentialIssue(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeManagedDirectCredentialACK(ackRaw); err != nil {
		t.Fatal(err)
	}
}

func TestManagedDirectCredentialStrictJSON(t *testing.T) {
	issue, host, _ := managedCredentialFixture(t)
	raw, _ := issue.CanonicalBytes()
	secret, ack, err := DeriveManagedDirectCredentialHost(issue, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	ackRaw, _ := ack.CanonicalBytes()
	failure := ManagedDirectCredentialFailureACK{ProtocolVersion: ManagedDirectCredentialProtocol, CredentialID: issue.CredentialID, Error: ManagedDirectCredentialInstallFailure}
	failureRaw, err := failure.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		limit  int
		decode func([]byte) error
	}{
		{"issue", raw, 96 * 1024, func(b []byte) error { _, e := DecodeManagedDirectCredentialIssue(b); return e }},
		{"ack", ackRaw, 1024, func(b []byte) error { _, e := DecodeManagedDirectCredentialACK(b); return e }},
		{"ack-verifier", ackRaw, 1024, func(b []byte) error { _, _, e := DecodeManagedDirectCredentialACKVerifier(b); return e }},
		{"failure", failureRaw, 1024, func(b []byte) error { _, e := DecodeManagedDirectCredentialFailureACK(b); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.decode(tc.raw); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(tc.raw, &fields)
			for key, value := range fields {
				quoted, _ := json.Marshal(key)
				duplicate := append(append(append(append([]byte("{"), quoted...), ':'), append(value, ',')...), tc.raw[1:]...)
				if tc.decode(duplicate) == nil {
					t.Fatal("accepted duplicate", key)
				}
				var missing map[string]json.RawMessage
				json.Unmarshal(tc.raw, &missing)
				delete(missing, key)
				b, _ := json.Marshal(missing)
				if tc.decode(b) == nil {
					t.Fatal("accepted missing", key)
				}
			}
			for _, bad := range [][]byte{append([]byte(" "), tc.raw...), append(append([]byte{}, tc.raw...), '\n'), append(append([]byte{}, tc.raw...), []byte("{}")...), append([]byte("{\"unknown\":null,"), tc.raw[1:]...), bytes.Replace(tc.raw, []byte("v1"), []byte("v\\ud800"), 1), append([]byte("{\"invalid\":\"\xff\","), tc.raw[1:]...), bytes.Repeat([]byte(" "), tc.limit+1)} {
				if tc.decode(bad) == nil {
					t.Fatal("accepted noncanonical input")
				}
			}
		})
	}
}

func TestManagedDirectCredentialRejects(t *testing.T) {
	issue, host, server := managedCredentialFixture(t)
	for name, mutate := range map[string]func(*ManagedDirectCredentialIssue){
		"reused-pop-key": func(p *ManagedDirectCredentialIssue) { p.ServerEphemeralX25519 = p.PoP.ServerEphemeralX25519 },
		"protocol":       func(p *ManagedDirectCredentialIssue) { p.ProtocolVersion = "other" },
		"suite":          func(p *ManagedDirectCredentialIssue) { p.Suite = "other" },
		"generation":     func(p *ManagedDirectCredentialIssue) { p.ChannelGeneration = 0 },
		"nonce-hex":      func(p *ManagedDirectCredentialIssue) { p.Nonce = strings.Repeat("ab", 32) },
		"nonce-short":    func(p *ManagedDirectCredentialIssue) { p.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 31)) },
		"key-case": func(p *ManagedDirectCredentialIssue) {
			p.ServerEphemeralX25519 = strings.ToUpper(p.ServerEphemeralX25519)
		},
		"issued-before-pop":       func(p *ManagedDirectCredentialIssue) { p.IssuedAt = p.PoP.IssuedAt.Add(-time.Second) },
		"install-after-pop":       func(p *ManagedDirectCredentialIssue) { p.InstallExpiresAt = p.PoP.ExpiresAt.Add(time.Second) },
		"install-empty":           func(p *ManagedDirectCredentialIssue) { p.InstallExpiresAt = p.IssuedAt },
		"credential-empty":        func(p *ManagedDirectCredentialIssue) { p.CredentialExpiresAt = p.IssuedAt },
		"credential-after-budget": func(p *ManagedDirectCredentialIssue) { p.Budget.ExpiresAt = p.CredentialExpiresAt.Add(-time.Second) },
		"credential-after-authorization": func(p *ManagedDirectCredentialIssue) {
			p.CredentialExpiresAt = p.PoP.Authorization.ExpiresAt.Add(time.Second)
		},
		"receipt-challenge":  func(p *ManagedDirectCredentialIssue) { p.PoPReceipt.ChallengeID = p.CredentialID },
		"receipt-transcript": func(p *ManagedDirectCredentialIssue) { p.PoPReceipt.TranscriptHash = strings.Repeat("01", 32) },
		"budget-revision":    func(p *ManagedDirectCredentialIssue) { p.Budget.AcceptedRevision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			q := issue
			mutate(&q)
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted invalid issue")
			}
		})
	}
	for _, now := range []time.Time{issue.IssuedAt.Add(-time.Nanosecond), issue.InstallExpiresAt, issue.InstallExpiresAt.Add(time.Second)} {
		if _, _, err := DeriveManagedDirectCredentialHost(issue, host, now); err == nil {
			t.Fatal("host accepted invalid time")
		}
		if _, _, _, err := DeriveManagedDirectCredentialVerifier(issue, server, now); err == nil {
			t.Fatal("server accepted invalid time")
		}
	}
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33), bytes.Repeat([]byte{7}, 32)} {
		if _, _, err := DeriveManagedDirectCredentialHost(issue, key, issue.IssuedAt); err == nil {
			t.Fatal("host accepted invalid key")
		}
		if _, _, _, err := DeriveManagedDirectCredentialVerifier(issue, key, issue.IssuedAt); err == nil {
			t.Fatal("server accepted invalid key")
		}
	}
	for _, key := range []string{strings.Repeat("00", 32), "01" + strings.Repeat("00", 31), "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", "ec" + strings.Repeat("ff", 30) + "7f", "ed" + strings.Repeat("ff", 30) + "7f", strings.Repeat("ff", 32)} {
		for _, nested := range []bool{false, true} {
			q := issue
			if nested {
				q.PoP.ServerEphemeralX25519 = key
			} else {
				q.ServerEphemeralX25519 = key
			}
			if _, err := q.CanonicalBytes(); err == nil {
				t.Fatal("accepted invalid public key")
			}
		}
	}
}

func TestManagedDirectCredentialRetryBinding(t *testing.T) {
	issue, host, server := managedCredentialFixture(t)
	original, ack, err := DeriveManagedDirectCredentialHost(issue, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(original)
	retry, retryACK, err := DeriveManagedDirectCredentialHost(issue, host, issue.InstallExpiresAt.Add(-time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(retry)
	if !hmac.Equal(original, retry) || ack != retryACK {
		t.Fatal("retry changed credential")
	}
	for name, mutate := range map[string]func(*ManagedDirectCredentialIssue){
		"nonce": func(p *ManagedDirectCredentialIssue) {
			p.Nonce = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x65}, 32))
		},
		"generation":        func(p *ManagedDirectCredentialIssue) { p.ChannelGeneration++ },
		"credential-id":     func(p *ManagedDirectCredentialIssue) { p.CredentialID = p.Budget.AgreementID },
		"budget":            func(p *ManagedDirectCredentialIssue) { p.Budget.AcceptedRevision++ },
		"credential-expiry": func(p *ManagedDirectCredentialIssue) { p.CredentialExpiresAt = p.CredentialExpiresAt.Add(-time.Second) },
		"install-expiry":    func(p *ManagedDirectCredentialIssue) { p.InstallExpiresAt = p.InstallExpiresAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			q := issue
			mutate(&q)
			secret, changed, err := DeriveManagedDirectCredentialHost(q, host, q.IssuedAt)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(secret)
			if hmac.Equal(original, secret) || changed.TranscriptHash == ack.TranscriptHash || changed.HostConfirmation == ack.HostConfirmation {
				t.Fatal("field not bound")
			}
			_, hash, verifier, err := DeriveManagedDirectCredentialVerifier(q, server, q.IssuedAt)
			if err != nil || hash == "" || verifier == "" {
				t.Fatal("server derivation", err)
			}
		})
	}
}

func TestManagedDirectCredentialProofReceipt(t *testing.T) {
	issue, host, _ := managedCredentialFixture(t)
	proof, err := ConfirmManagedEndpointHostCustody(issue.PoP, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ManagedEndpointPoPProof){func(p *ManagedEndpointPoPProof) { p.ChallengeID = issue.CredentialID }, func(p *ManagedEndpointPoPProof) { p.TranscriptHash = strings.Repeat("01", 32) }} {
		changed := proof
		change(&changed)
		if _, err := NewManagedDirectCredentialIssue(issue, issue.PoP, changed); err == nil {
			t.Fatal("accepted inconsistent proof")
		}
	}
	// Structurally valid confirmation evidence is retained, not authenticated here.
	proof.HostConfirmation = strings.Repeat("02", 32)
	changed, err := NewManagedDirectCredentialIssue(issue, issue.PoP, proof)
	if err != nil {
		t.Fatal(err)
	}
	proofRaw, _ := proof.CanonicalBytes()
	digest := sha256.Sum256(proofRaw)
	if changed.PoPReceipt.ProofDigest != hex.EncodeToString(digest[:]) || changed.PoPReceipt.ProofDigest == issue.PoPReceipt.ProofDigest {
		t.Fatal("proof digest not retained")
	}
}

func TestManagedDirectCredentialACKBindingAndHashInputs(t *testing.T) {
	issue, host, server := managedCredentialFixture(t)
	secret, ack, err := DeriveManagedDirectCredentialHost(issue, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	transcript, _, verifier, err := DeriveManagedDirectCredentialVerifier(issue, server, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ManagedDirectCredentialACK){
		"id":           func(a *ManagedDirectCredentialACK) { a.CredentialID = issue.Budget.AgreementID },
		"transcript":   func(a *ManagedDirectCredentialACK) { a.TranscriptHash = strings.Repeat("01", 32) },
		"confirmation": func(a *ManagedDirectCredentialACK) { a.HostConfirmation = strings.Repeat("02", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			q := ack
			mutate(&q)
			raw, err := q.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			got, digest, err := DecodeManagedDirectCredentialACKVerifier(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.CredentialID == issue.CredentialID && got.TranscriptHash == transcript && digest == verifier {
				t.Fatal("tampered ACK matches retained state")
			}
		})
	}
	for _, th := range []string{"", strings.Repeat("0", 63), strings.Repeat("AB", 32), strings.Repeat("zz", 32)} {
		if got, err := ManagedDirectCredentialHash(th, secret); err == nil || got != "" {
			t.Fatal("accepted malformed transcript")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if got, err := ManagedDirectCredentialHash(transcript, bad); err == nil || got != "" {
			t.Fatal("accepted malformed secret")
		}
	}
	bad := issue
	bad.ServerEphemeralX25519 = strings.Repeat("00", 32)
	if value, ack, err := DeriveManagedDirectCredentialHost(bad, host, issue.IssuedAt); err == nil || len(value) != 0 || ack != (ManagedDirectCredentialACK{}) {
		t.Fatal("host failure returned material")
	}
	if th, ch, iv, err := DeriveManagedDirectCredentialVerifier(bad, server, issue.IssuedAt); err == nil || th != "" || ch != "" || iv != "" {
		t.Fatal("server failure returned material")
	}
}

func TestManagedDirectCredentialNestedHostLowOrder(t *testing.T) {
	issue, _, _ := managedCredentialFixture(t)
	issue.PoP.ACK.Reservation.X25519 = "01" + strings.Repeat("00", 31)
	issue.PoP.ACK.Reservation.EnrollmentDigest, _ = issue.PoP.ACK.Reservation.Digest()
	issue.PoP.Receipt, _ = NewManagedEndpointPrepareReceiptReference(issue.PoP.ACK)
	// Refresh the transcript reference so stale evidence cannot mask key rejection.
	raw, _ := json.Marshal(issue.PoP)
	sum := sha256.Sum256(append([]byte("pagnet/managed-endpoint-host-custody-pop/transcript/v1/"), raw...))
	issue.PoPReceipt.TranscriptHash = hex.EncodeToString(sum[:])
	if _, err := issue.CanonicalBytes(); err == nil {
		t.Fatal("accepted nested low-order host key")
	}
}

func TestManagedDirectCredentialDomainSeparation(t *testing.T) {
	issue, host, server := managedCredentialFixture(t)
	raw, _ := issue.CanonicalBytes()
	th := sha256.Sum256(append([]byte("pagnet/managed-direct-credential/transcript/v1/"), raw...))
	sk, _ := ecdh.X25519().NewPrivateKey(server)
	hk, _ := ecdh.X25519().NewPrivateKey(host)
	shared, err := sk.ECDH(hk.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(shared)
	nonce, _ := base64.StdEncoding.DecodeString(issue.Nonce)
	derive := func(info string) []byte {
		key, err := hkdf.Key(sha256.New, shared, nonce, info+string(th[:]), 32)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	credential := derive("pagnet/managed-direct-credential/credential-secret/v1/")
	defer clear(credential)
	install := derive("pagnet/managed-direct-credential/install-key/v1/")
	defer clear(install)
	if hmac.Equal(credential, install) {
		t.Fatal("credential and installation keys collide")
	}
	for _, purpose := range []string{"pagnet/managed-endpoint-host-custody-pop/key/v1/", "pagnet/sdk-pair/readiness/v1", "credential-secret/v1/", "install-key/v1/"} {
		other := derive(purpose)
		if hmac.Equal(other, credential) || hmac.Equal(other, install) {
			t.Fatal("KDF domain separation")
		}
		clear(other)
	}
	mac := func(key []byte, prefix string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(prefix))
		h.Write(th[:])
		return h.Sum(nil)
	}
	confirmation := mac(install, "pagnet/managed-direct-credential/host-install/v1/")
	for _, prefix := range []string{"host-install/v1/", "pagnet/managed-direct-credential/install-key/v1/", "pagnet/managed-endpoint-host-custody-pop/confirm/v1/"} {
		if hmac.Equal(confirmation, mac(install, prefix)) {
			t.Fatal("confirmation domain separation")
		}
	}
	if hmac.Equal(confirmation, mac(credential, "pagnet/managed-direct-credential/host-install/v1/")) {
		t.Fatal("confirmation key separation")
	}
	digest := func(prefix string, value []byte) string {
		h := sha256.New()
		h.Write([]byte(prefix))
		h.Write(th[:])
		h.Write(value)
		return hex.EncodeToString(h.Sum(nil))
	}
	_, credentialHash, verifier, err := DeriveManagedDirectCredentialVerifier(issue, server, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if credentialHash != digest("pagnet/managed-direct-credential/credential-hash/v1/", credential) || verifier != digest("pagnet/managed-direct-credential/install-verifier/v1/", confirmation) {
		t.Fatal("independent digest mismatch")
	}
	if credentialHash == digest("credential-hash/v1/", credential) || verifier == digest("install-verifier/v1/", confirmation) || credentialHash == digest("pagnet/managed-direct-credential/install-verifier/v1/", credential) || verifier == digest("pagnet/managed-direct-credential/credential-hash/v1/", confirmation) {
		t.Fatal("digest domain separation")
	}
}

func TestManagedDirectCredentialEveryFieldBound(t *testing.T) {
	p, host, _ := managedCredentialFixture(t)
	raw, _ := p.CanonicalBytes()
	secret, original, err := DeriveManagedDirectCredentialHost(p, host, p.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	count := 0
	var visit func(any, []any)
	visit = func(node any, path []any) {
		switch v := node.(type) {
		case map[string]any:
			for k, child := range v {
				visit(child, append(append([]any{}, path...), k))
			}
		case []any:
			for i, child := range v {
				visit(child, append(append([]any{}, path...), i))
			}
		default:
			count++
			var changed map[string]any
			json.Unmarshal(raw, &changed)
			var container any = changed
			for _, part := range path[:len(path)-1] {
				switch key := part.(type) {
				case string:
					container = container.(map[string]any)[key]
				case int:
					container = container.([]any)[key]
				}
			}
			var replacement any = "tampered"
			switch value := v.(type) {
			case string:
				replacement = value + "x"
			case float64:
				replacement = value + 1
			}
			switch key := path[len(path)-1].(type) {
			case string:
				container.(map[string]any)[key] = replacement
			case int:
				container.([]any)[key] = replacement
			}
			altered, _ := json.Marshal(changed)
			var challenge ManagedDirectCredentialIssue
			json.Unmarshal(altered, &challenge)
			secret, proof, err := DeriveManagedDirectCredentialHost(challenge, host, p.IssuedAt)
			clear(secret)
			if err == nil && proof.HostConfirmation == original.HostConfirmation {
				t.Fatalf("unbound field %v", path)
			}
		}
	}
	visit(root, nil)
	if count != 115 {
		t.Fatalf("unexpected field coverage %d", count)
	}
	t.Logf("checked %d bound leaves", count)
}

func TestManagedDirectCredentialOwnsEvidenceAndCanonicalConcurrent(t *testing.T) {
	issue, host, _ := managedCredentialFixture(t)
	pop := issue.PoP
	network := pop.Authorization.NetworkID
	generation := pop.Authorization.Target.AuthorityGeneration
	pop.Authorization.Target.NetworkID = &network
	pop.Authorization.Target.MembershipAuthorityGeneration = &generation
	pop.AuthorizationDigest, _ = pop.Authorization.Digest()
	proof, err := ConfirmManagedEndpointHostCustody(pop, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := NewManagedDirectCredentialIssue(issue, pop, proof)
	if err != nil {
		t.Fatal(err)
	}
	want, err := owned.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	pop.Authorization.SelectedSources[0].PrincipalID = pop.Authorization.Target.PrincipalID
	*pop.Authorization.Target.NetworkID = issue.CredentialID
	*pop.Authorization.Target.MembershipAuthorityGeneration = string(issue.CredentialID)
	got, err := owned.CanonicalBytes()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("constructor retained nested evidence alias", err)
	}
	// Verify ownership in the reverse direction with both slices and pointers.
	reversePop := owned.PoP
	reverseProof, err := ConfirmManagedEndpointHostCustody(reversePop, host, issue.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := NewManagedDirectCredentialIssue(issue, reversePop, reverseProof)
	if err != nil {
		t.Fatal(err)
	}
	inputBefore, err := json.Marshal(reversePop)
	if err != nil {
		t.Fatal(err)
	}
	reverse.PoP.Authorization.SelectedSources[0].PrincipalID = reverse.PoP.Authorization.Target.PrincipalID
	*reverse.PoP.Authorization.Target.NetworkID = issue.CredentialID
	*reverse.PoP.Authorization.Target.MembershipAuthorityGeneration = string(issue.CredentialID)
	inputAfter, err := json.Marshal(reversePop)
	if err != nil || !bytes.Equal(inputBefore, inputAfter) {
		t.Fatal("returned evidence aliases constructor input", err)
	}
	zone := time.FixedZone("fixture", 3600)
	owned.IssuedAt = owned.IssuedAt.In(zone)
	owned.InstallExpiresAt = owned.InstallExpiresAt.In(zone)
	owned.CredentialExpiresAt = owned.CredentialExpiresAt.In(zone)
	owned.Budget.ExpiresAt = owned.Budget.ExpiresAt.In(zone)
	owned.PoP.IssuedAt = owned.PoP.IssuedAt.In(zone)
	owned.PoP.Authorization.CreatedAt = owned.PoP.Authorization.CreatedAt.In(zone)
	before, err := json.Marshal(owned)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				got, err := owned.CanonicalBytes()
				if err != nil || !bytes.Equal(got, want) {
					t.Error("concurrent canonicalization changed issue", err)
				}
			}
		}()
	}
	wg.Wait()
	after, err := json.Marshal(owned)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("canonicalization mutated caller issue", err)
	}
}
