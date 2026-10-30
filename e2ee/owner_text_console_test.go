package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
)

func consoleDescriptor(t *testing.T) (OwnerTextConsoleDescriptor, []byte, ed25519.PrivateKey) {
	m, priv, signer := ownerMailboxTestDescriptor(t)
	return OwnerTextConsoleDescriptor{
		OwnershipScope: "personal", Role: "sender", ProjectContract: "owner_text_project_v1",
		TenantID: m.TenantID, OwnerUserID: m.OwnerUserID, ProjectID: m.InstallationID, NetworkID: m.ServiceID, SessionID: m.SessionID,
		ProjectVersion: "9007199254740993", PolicyHash: strings.Repeat("ab", 32), ProjectDescriptorHash: bytes.Repeat([]byte{0x55}, 32),
		SenderPrincipalID: m.OwnerUserID, SenderInstallationID: m.InstallationID, ResponderPrincipalID: m.ServiceID, ResponderInstallationID: m.InstallationID,
		HostID: m.HostID, RunnerID: m.RunnerID, RunnerEpoch: "2026-10-22T12:34:56.123456000Z", HostCredentialID: m.HostCredentialID,
		SenderGeneration: "9223372036854775807", SenderClaimID: m.TenantID, SenderEndpointID: m.ServiceID, SenderEndpointCredentialID: m.HostCredentialID,
		SenderEndpointStartedAt: "2026-10-22T12:34:56.000000000Z", SenderProofID: m.RunnerID,
		BrowserX25519Pub: m.BrowserX25519Pub, HostX25519Pub: m.HostX25519Pub, HostEd25519Pub: m.HostEd25519Pub,
		IssuedAtUnixSeconds: m.IssuedAtUnixSeconds, ExpiresAtUnixSeconds: m.ExpiresAtUnixSeconds,
	}, priv, signer
}

type consoleVector struct {
	Descriptor                 OwnerTextConsoleDescriptor `json:"descriptor"`
	BrowserPrivateHex          string                     `json:"browserPrivateHex"`
	HostSigningSeedHex         string                     `json:"hostSigningSeedHex"`
	HPKERandomnessHex          string                     `json:"hpkeRandomnessHex"`
	DirectionalKeysHex         string                     `json:"directionalKeysHex"`
	BHex                       string                     `json:"BHex"`
	THex                       string                     `json:"THex"`
	InfoHex                    string                     `json:"infoHex"`
	EncHex                     string                     `json:"encHex"`
	CTHex                      string                     `json:"ctHex"`
	SignatureHex               string                     `json:"signatureHex"`
	TranscriptHash             string                     `json:"transcriptHash"`
	ClientConfirmHex           string                     `json:"clientConfirmHex"`
	HostConfirmHex             string                     `json:"hostConfirmHex"`
	ClientConfirmCiphertextHex string                     `json:"clientConfirmCiphertextHex"`
	HostConfirmCiphertextHex   string                     `json:"hostConfirmCiphertextHex"`
	FrameSequence              uint64                     `json:"frameSequence"`
	FramePlaintextHex          string                     `json:"framePlaintextHex"`
	FrameNonceHex              string                     `json:"frameNonceHex"`
	C2HFrameAADHex             string                     `json:"c2hFrameAADHex"`
	H2CFrameAADHex             string                     `json:"h2cFrameAADHex"`
	C2HFrameCiphertextHex      string                     `json:"c2hFrameCiphertextHex"`
	H2CFrameCiphertextHex      string                     `json:"h2cFrameCiphertextHex"`
}

// Deterministic entropy and these synthetic private keys are public fixtures,
// never production inputs.
func consoleSyntheticVector(t *testing.T) consoleVector {
	t.Helper()
	d, priv, signer := consoleDescriptor(t)
	b, err := EncodeOwnerTextConsoleDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 64)
	for i := range material {
		material[i] = byte(i)
	}
	randomness := bytes.Repeat([]byte{0x44}, 32)
	pk, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(d.BrowserX25519Pub)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := hpkeSuite.NewSender(pk, []byte(OwnerTextConsoleHPKEInfo))
	if err != nil {
		t.Fatal(err)
	}
	enc, sealer, err := sender.Setup(bytes.NewReader(randomness))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sealer.Seal(material, b)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := OwnerTextConsoleBootstrapTranscript(d, enc, ct)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(transcript)
	hashText := base64.StdEncoding.EncodeToString(hash[:])
	s := OwnerTextConsoleSession{transcriptHash: hashText}
	clientConfirm, hostConfirm := s.confirmation(false), s.confirmation(true)
	clientCT, _ := SealOwnerTextConsoleFrame(d, material[:32], 0, 0, clientConfirm)
	hostCT, _ := SealOwnerTextConsoleFrame(d, material[32:], 1, 0, hostConfirm)
	const seq = 1
	plain := []byte("synthetic owner text console operation")
	c2hAAD, _ := OwnerTextConsoleFrameAAD(d, 0, seq)
	h2cAAD, _ := OwnerTextConsoleFrameAAD(d, 1, seq)
	c2h, _ := SealOwnerTextConsoleFrame(d, material[:32], 0, seq, plain)
	h2c, _ := SealOwnerTextConsoleFrame(d, material[32:], 1, seq, plain)
	return consoleVector{d, hex.EncodeToString(priv), hex.EncodeToString(signer.Seed()), hex.EncodeToString(randomness), hex.EncodeToString(material), hex.EncodeToString(b), hex.EncodeToString(transcript), hex.EncodeToString([]byte(OwnerTextConsoleHPKEInfo)), hex.EncodeToString(enc), hex.EncodeToString(ct), hex.EncodeToString(ed25519.Sign(signer, transcript)), hashText, hex.EncodeToString(clientConfirm), hex.EncodeToString(hostConfirm), hex.EncodeToString(clientCT), hex.EncodeToString(hostCT), seq, hex.EncodeToString(plain), "000000000000000000000001", hex.EncodeToString(c2hAAD), hex.EncodeToString(h2cAAD), hex.EncodeToString(c2h), hex.EncodeToString(h2c)}
}

func TestOwnerTextConsoleGolden(t *testing.T) {
	vector := consoleSyntheticVector(t)
	data, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if os.Getenv("UPDATE_OWNER_TEXT_CONSOLE_VECTOR") == "1" {
		if err = os.WriteFile("testdata/owner_text_console_v1.json", data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile("testdata/owner_text_console_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, golden) {
		t.Fatal("console golden fixture changed")
	}
	var decoded consoleVector
	if err = json.Unmarshal(golden, &decoded); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		v, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	keys, err := VerifyOwnerTextConsoleBootstrap(decoded.Descriptor, decoded.Descriptor, OwnerTextConsoleBootstrap{unhex(decoded.EncHex), unhex(decoded.CTHex), unhex(decoded.SignatureHex)}, unhex(decoded.BrowserPrivateHex))
	if err != nil {
		t.Fatal(err)
	}
	material := append(keys.ClientToHost[:], keys.HostToClient[:]...)
	if hex.EncodeToString(material) != decoded.DirectionalKeysHex {
		t.Fatal("directional key mismatch")
	}
}

func TestOwnerTextConsoleDescriptorParsing(t *testing.T) {
	d, _, _ := consoleDescriptor(t)
	data, _ := json.Marshal(d)
	for name, mutate := range map[string]func(*OwnerTextConsoleDescriptor){
		"scope": func(d *OwnerTextConsoleDescriptor) { d.OwnershipScope = "project" }, "role": func(d *OwnerTextConsoleDescriptor) { d.Role = "responder" }, "contract": func(d *OwnerTextConsoleDescriptor) { d.ProjectContract = "other" },
		"uuid":    func(d *OwnerTextConsoleDescriptor) { d.ProjectID = strings.ToUpper(d.ProjectID[:30]) + "AB" },
		"decimal": func(d *OwnerTextConsoleDescriptor) { d.ProjectVersion = "01" }, "overflow version": func(d *OwnerTextConsoleDescriptor) { d.ProjectVersion = "9223372036854775808" }, "generation": func(d *OwnerTextConsoleDescriptor) { d.SenderGeneration = "0" },
		"policy": func(d *OwnerTextConsoleDescriptor) { d.PolicyHash = strings.ToUpper(d.PolicyHash) }, "hash": func(d *OwnerTextConsoleDescriptor) { d.ProjectDescriptorHash = nil }, "key": func(d *OwnerTextConsoleDescriptor) { d.HostEd25519Pub = nil },
		"epoch": func(d *OwnerTextConsoleDescriptor) { d.RunnerEpoch = "2026-10-22T12:34:56Z" }, "offset": func(d *OwnerTextConsoleDescriptor) { d.SenderEndpointStartedAt = "2026-10-22T13:34:56.000000000+01:00" },
		"zero lifetime": func(d *OwnerTextConsoleDescriptor) { d.ExpiresAtUnixSeconds = d.IssuedAtUnixSeconds }, "long lifetime": func(d *OwnerTextConsoleDescriptor) { d.ExpiresAtUnixSeconds++ }, "unsafe": func(d *OwnerTextConsoleDescriptor) {
			d.IssuedAtUnixSeconds = 1 << 53
			d.ExpiresAtUnixSeconds = d.IssuedAtUnixSeconds + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := d
			mutate(&bad)
			if _, err := EncodeOwnerTextConsoleDescriptor(bad); err == nil {
				t.Fatal("accepted invalid descriptor")
			}
		})
	}
	for _, bad := range []string{
		strings.Replace(string(data), `"role":"sender"`, `"role":"sender","role":"sender"`, 1),
		strings.Replace(string(data), `"role":"sender"`, `"role":"sender","extra":1`, 1),
		strings.Replace(string(data), `"role":"sender"`, `"Role":"sender"`, 1),
		strings.Replace(string(data), `"role":"sender"`, `"role":"sender","Role":"sender"`, 1),
		strings.Replace(string(data), `"issuedAtUnixSeconds":1792672496,`, ``, 1),
		strings.Replace(string(data), `"issuedAtUnixSeconds":1792672496`, `"issuedAtUnixSeconds":null`, 1),
		string(data) + ` {}`, strings.Replace(string(data), `"issuedAtUnixSeconds":1792672496`, `"issuedAtUnixSeconds":1792672496.0`, 1),
		strings.Replace(string(data), base64.StdEncoding.EncodeToString(d.BrowserX25519Pub), base64.StdEncoding.EncodeToString(d.BrowserX25519Pub)+`\n`, 1),
	} {
		var parsed OwnerTextConsoleDescriptor
		if err := json.Unmarshal([]byte(bad), &parsed); err == nil {
			t.Fatalf("accepted invalid wire %s", bad)
		}
	}
	d.ExpiresAtUnixSeconds = d.IssuedAtUnixSeconds + 1
	if _, err := EncodeOwnerTextConsoleDescriptor(d); err != nil {
		t.Fatal("rejected short lifetime", err)
	}
}

func consoleSessionPair(t *testing.T) (*OwnerTextConsoleSession, *OwnerTextConsoleSession) {
	t.Helper()
	d, priv, signer := consoleDescriptor(t)
	b, hostKeys, err := CreateOwnerTextConsoleBootstrap(d, signer)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := VerifyOwnerTextConsoleBootstrap(d, d, b, priv)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Unix(int64(d.IssuedAtUnixSeconds), 0) }
	client, err := NewOwnerTextConsoleSession(d, b, keys, false, clock)
	if err != nil {
		t.Fatal(err)
	}
	host, err := NewOwnerTextConsoleSession(d, b, hostKeys, true, clock)
	if err != nil {
		t.Fatal(err)
	}
	return client, host
}
func confirmConsolePair(t *testing.T, client, host *OwnerTextConsoleSession) {
	t.Helper()
	ct, err := client.SealConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	if err = host.OpenConfirmation(0, ct); err != nil {
		t.Fatal(err)
	}
	ct, err = host.SealConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	if err = client.OpenConfirmation(0, ct); err != nil {
		t.Fatal(err)
	}
}
func TestOwnerTextConsoleSession(t *testing.T) {
	client, host := consoleSessionPair(t)
	if _, _, err := client.Seal(nil); err == nil {
		t.Fatal("operation before confirmation")
	}
	if _, err := host.SealConfirmation(); err == nil {
		t.Fatal("host confirmed before client")
	}
	confirmConsolePair(t, client, host)
	for _, pair := range [][2]*OwnerTextConsoleSession{{client, host}, {host, client}} {
		seq, ct, err := pair[0].Seal([]byte("operation"))
		if err != nil || seq != 1 {
			t.Fatal("first operation sequence", seq, err)
		}
		plain, err := pair[1].Open(seq, ct)
		if err != nil || string(plain) != "operation" {
			t.Fatal("operation", err)
		}
	}
	if _, err := host.Open(1, nil); err == nil {
		t.Fatal("replay accepted")
	}
	if _, _, err := host.Seal(nil); err == nil {
		t.Fatal("session survived bad receive")
	}
}
func TestOwnerTextConsoleSessionFailures(t *testing.T) {
	for _, kind := range []string{"tamper", "skip", "wrong type", "wrong transcript", "duplicate JSON", "preconfirm operation"} {
		t.Run(kind, func(t *testing.T) {
			client, host := consoleSessionPair(t)
			ct, err := client.SealConfirmation()
			if err != nil {
				t.Fatal(err)
			}
			seq := uint64(0)
			switch kind {
			case "tamper":
				ct[0] ^= 1
			case "skip":
				seq = 1
			case "wrong type", "wrong transcript", "duplicate JSON":
				plain := client.confirmation(false)
				if kind == "wrong type" {
					plain = client.confirmation(true)
				}
				if kind == "wrong transcript" {
					plain = bytes.Replace(plain, []byte(client.transcriptHash), []byte(strings.Repeat("A", 43)+"="), 1)
				}
				if kind == "duplicate JSON" {
					plain = bytes.Replace(plain, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
				}
				ct, err = SealOwnerTextConsoleFrame(client.descriptor, client.keys.ClientToHost[:], 0, 0, plain)
				if err != nil {
					t.Fatal(err)
				}
			case "preconfirm operation":
				if _, err = host.Open(1, ct); err == nil {
					t.Fatal("accepted preconfirmation operation")
				}
				return
			}
			if err = host.OpenConfirmation(seq, ct); err == nil {
				t.Fatal("accepted invalid confirm")
			}
			if err = host.OpenConfirmation(0, ct); err == nil {
				t.Fatal("failed session reopened")
			}
		})
	}
	t.Run("expiry", func(t *testing.T) {
		client, host := consoleSessionPair(t)
		confirmConsolePair(t, client, host)
		client.clock = func() time.Time { return time.Unix(int64(client.descriptor.ExpiresAtUnixSeconds), 0) }
		if _, _, err := client.Seal(nil); err == nil {
			t.Fatal("expired session accepted")
		}
	})
	t.Run("limit", func(t *testing.T) {
		client, host := consoleSessionPair(t)
		confirmConsolePair(t, client, host)
		client.sendSeq = OwnerTextConsoleSequenceLimit - 1
		host.receiveSeq = client.sendSeq
		seq, ct, err := client.Seal(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = host.Open(seq, ct); err != nil {
			t.Fatal(err)
		}
		if _, _, err = client.Seal(nil); err == nil {
			t.Fatal("accepted sequence limit")
		}
	})
	t.Run("concurrent send", func(t *testing.T) {
		client, host := consoleSessionPair(t)
		confirmConsolePair(t, client, host)
		var wg sync.WaitGroup
		seqs := make(chan uint64, 16)
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				seq, _, err := client.Seal(nil)
				if err != nil {
					t.Error(err)
				}
				seqs <- seq
			}()
		}
		wg.Wait()
		close(seqs)
		seen := map[uint64]bool{}
		for seq := range seqs {
			if seen[seq] {
				t.Fatal("reused sequence")
			}
			seen[seq] = true
		}
	})
}

func TestOwnerTextConsoleBootstrapAndFrames(t *testing.T) {
	d, priv, signer := consoleDescriptor(t)
	bootstrap, keys, err := CreateOwnerTextConsoleBootstrap(d, signer)
	if err != nil {
		t.Fatal(err)
	}
	expected := d
	expected.ProjectVersion = "1"
	if _, err = VerifyOwnerTextConsoleBootstrap(expected, d, bootstrap, priv); err == nil {
		t.Fatal("accepted context mismatch")
	}
	for _, field := range []string{"enc", "ct", "signature"} {
		bad := OwnerTextConsoleBootstrap{bytes.Clone(bootstrap.Enc), bytes.Clone(bootstrap.Ciphertext), bytes.Clone(bootstrap.Signature)}
		switch field {
		case "enc":
			bad.Enc[0] ^= 1
		case "ct":
			bad.Ciphertext[0] ^= 1
		case "signature":
			bad.Signature[0] ^= 1
		}
		if _, err = VerifyOwnerTextConsoleBootstrap(d, d, bad, priv); err == nil {
			t.Fatal("accepted bootstrap tamper", field)
		}
	}
	for _, direction := range []byte{0, 1} {
		for _, size := range []int{0, OwnerTextConsoleMaxPlaintext} {
			plain := make([]byte, size)
			ct, err := SealOwnerTextConsoleFrame(d, keys.ClientToHost[:], direction, OwnerTextConsoleSequenceLimit-1, plain)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := OpenOwnerTextConsoleFrame(d, keys.ClientToHost[:], direction, OwnerTextConsoleSequenceLimit-1, ct)
			if err != nil || !bytes.Equal(opened, plain) {
				t.Fatal("frame", err)
			}
		}
	}
	for _, seq := range []uint64{OwnerTextConsoleSequenceLimit, ^uint64(0)} {
		if _, err = SealOwnerTextConsoleFrame(d, keys.ClientToHost[:], 0, seq, nil); err == nil {
			t.Fatal("accepted sequence")
		}
	}
	if _, err = SealOwnerTextConsoleFrame(d, keys.ClientToHost[:], 2, 1, nil); err == nil {
		t.Fatal("accepted direction")
	}
	if _, err = SealOwnerTextConsoleFrame(d, keys.ClientToHost[:], 0, 1, make([]byte, OwnerTextConsoleMaxPlaintext+1)); err == nil {
		t.Fatal("accepted oversize")
	}
	ct, _ := SealOwnerTextConsoleFrame(d, keys.ClientToHost[:], 0, 1, []byte("hello"))
	if _, err = OpenOwnerTextConsoleFrame(d, keys.ClientToHost[:], 1, 1, ct); err == nil {
		t.Fatal("accepted wrong direction")
	}
	if _, err = OpenOwnerTextConsoleFrame(d, keys.ClientToHost[:], 0, 2, ct); err == nil {
		t.Fatal("accepted wrong sequence")
	}
	mailbox, _, _ := ownerMailboxTestDescriptor(t)
	if _, err = OpenOwnerMailboxFrame(mailbox, keys.ClientToHost[:], 0, 1, ct); err == nil {
		t.Fatal("console ciphertext accepted as mailbox")
	}
}
