package crypto

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func currentEpochFixture(t *testing.T) (*NKA, *HostIdentity, CurrentEpochPackageContext) {
	t.Helper()
	host, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyring(testNetworkID)
	if _, err := ring.Activate(testTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := ring.Rotate(testTime().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	current, err := ring.Rotate(testTime().Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return &NKA{TenantID: testTenantID, NetworkID: testNetworkID, keyring: ring}, host, CurrentEpochPackageContext{
		OwnerTenantID: testTenantID, NetworkID: testNetworkID, GrantID: "grant-one",
		GrantGeneration: 2, NetworkTransitionGeneration: 3, RecipientID: testNewHost,
		RecipientPublicKey: host.X25519Pub, EpochID: current.ID,
	}
}

func TestCurrentEpochPackageRoundTrip(t *testing.T) {
	n, host, c := currentEpochFixture(t)
	before, err := json.Marshal(n.keyring)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := n.BuildCurrentEpochKeyPackage(c)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the public wire representation as well as the in-memory API.
	wire, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var received CurrentEpochKeyPackage
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}
	ring, err := OpenCurrentEpochKeyPackage(&received, host.X25519Priv, c)
	if err != nil {
		t.Fatal(err)
	}
	if ring.NetworkID != c.NetworkID || len(ring.Epochs) != 1 || !reflect.DeepEqual(ring.Epochs[0], n.keyring.Epochs[2]) {
		t.Fatal("package did not contain exactly the current epoch")
	}
	for _, old := range n.keyring.Epochs[:2] {
		if _, ok := ring.EpochByID(old.ID); ok {
			t.Fatal("package disclosed historical epoch")
		}
	}
	ring.Epochs[0].Key[0] ^= 1
	after, err := json.Marshal(n.keyring)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("building/opening package changed source keyring")
	}
}

func TestCurrentEpochPackageExpectedContext(t *testing.T) {
	n, host, c := currentEpochFixture(t)
	pkg, err := n.BuildCurrentEpochKeyPackage(c)
	if err != nil {
		t.Fatal(err)
	}
	otherHost, err := NewHostIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*CurrentEpochPackageContext){
		"missing owner":        func(c *CurrentEpochPackageContext) { c.OwnerTenantID = "" },
		"owner":                func(c *CurrentEpochPackageContext) { c.OwnerTenantID = "other-tenant" },
		"network":              func(c *CurrentEpochPackageContext) { c.NetworkID = "other-network" },
		"grant":                func(c *CurrentEpochPackageContext) { c.GrantID = "other-grant" },
		"grant generation":     func(c *CurrentEpochPackageContext) { c.GrantGeneration++ },
		"network generation":   func(c *CurrentEpochPackageContext) { c.NetworkTransitionGeneration++ },
		"recipient":            func(c *CurrentEpochPackageContext) { c.RecipientID = "other-host" },
		"recipient public key": func(c *CurrentEpochPackageContext) { c.RecipientPublicKey = otherHost.X25519Pub },
		"epoch":                func(c *CurrentEpochPackageContext) { c.EpochID = n.keyring.Epochs[0].ID },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			expected := c
			mutate(&expected)
			if _, err := OpenCurrentEpochKeyPackage(pkg, host.X25519Priv, expected); err == nil {
				t.Fatal("opened package with mismatched expected context")
			}
		})
	}
	if _, err := OpenCurrentEpochKeyPackage(pkg, otherHost.X25519Priv, c); err == nil {
		t.Fatal("wrong private key opened package")
	}
}

func TestCurrentEpochPackageBuilderRejectsInvalidAuthority(t *testing.T) {
	cases := map[string]func(*NKA, *CurrentEpochPackageContext){
		"missing owner":              func(_ *NKA, c *CurrentEpochPackageContext) { c.OwnerTenantID = "" },
		"missing network":            func(_ *NKA, c *CurrentEpochPackageContext) { c.NetworkID = "" },
		"missing grant":              func(_ *NKA, c *CurrentEpochPackageContext) { c.GrantID = "" },
		"missing recipient":          func(_ *NKA, c *CurrentEpochPackageContext) { c.RecipientID = "" },
		"missing epoch":              func(_ *NKA, c *CurrentEpochPackageContext) { c.EpochID = "" },
		"missing grant generation":   func(_ *NKA, c *CurrentEpochPackageContext) { c.GrantGeneration = 0 },
		"missing network generation": func(_ *NKA, c *CurrentEpochPackageContext) { c.NetworkTransitionGeneration = 0 },
		"malformed recipient key":    func(_ *NKA, c *CurrentEpochPackageContext) { c.RecipientPublicKey = []byte{1} },
		"owner mismatch":             func(n *NKA, _ *CurrentEpochPackageContext) { n.TenantID = "other" },
		"network mismatch":           func(n *NKA, _ *CurrentEpochPackageContext) { n.NetworkID = "other" },
		"keyring mismatch":           func(n *NKA, _ *CurrentEpochPackageContext) { n.keyring.NetworkID = "other" },
		"historical epoch":           func(n *NKA, c *CurrentEpochPackageContext) { c.EpochID = n.keyring.Epochs[0].ID },
		"revoked epoch":              func(n *NKA, _ *CurrentEpochPackageContext) { n.keyring.Epochs[2].State = EpochRevoked },
		"malformed current key":      func(n *NKA, _ *CurrentEpochPackageContext) { n.keyring.Epochs[2].Key = []byte{1} },
		"malformed historical key":   func(n *NKA, _ *CurrentEpochPackageContext) { n.keyring.Epochs[0].Key = nil },
		"ambiguous active epochs":    func(n *NKA, _ *CurrentEpochPackageContext) { n.keyring.Epochs[0].State = EpochActive },
		"duplicate epoch": func(n *NKA, _ *CurrentEpochPackageContext) {
			n.keyring.Epochs = append(n.keyring.Epochs, n.keyring.Epochs[2])
		},
		"no keyring": func(n *NKA, _ *CurrentEpochPackageContext) { n.keyring = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			n, _, c := currentEpochFixture(t)
			mutate(n, &c)
			if _, err := n.BuildCurrentEpochKeyPackage(c); err == nil {
				t.Fatal("built package from invalid context or authority")
			}
		})
	}
}

func TestCurrentEpochPackageRejectsPayloads(t *testing.T) {
	n, host, c := currentEpochFixture(t)
	info, err := currentEpochPackageInfo(c)
	if err != nil {
		t.Fatal(err)
	}
	valid := Keyring{NetworkID: c.NetworkID, Epochs: []KeyEpoch{n.keyring.Epochs[2]}}
	cases := map[string]func(*Keyring){
		"extra epochs":    func(r *Keyring) { r.Epochs = append(r.Epochs, n.keyring.Epochs[0]) },
		"no epochs":       func(r *Keyring) { r.Epochs = nil },
		"wrong network":   func(r *Keyring) { r.NetworkID = "other" },
		"wrong epoch":     func(r *Keyring) { r.Epochs[0].ID = "other" },
		"rotated epoch":   func(r *Keyring) { r.Epochs[0].State = EpochRotated },
		"revoked epoch":   func(r *Keyring) { r.Epochs[0].State = EpochRevoked },
		"short key":       func(r *Keyring) { r.Epochs[0].Key = make([]byte, 31) },
		"long key":        func(r *Keyring) { r.Epochs[0].Key = make([]byte, 33) },
		"absent creation": func(r *Keyring) { r.Epochs[0].CreatedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ring := Keyring{NetworkID: valid.NetworkID, Epochs: append([]KeyEpoch(nil), valid.Epochs...)}
			mutate(&ring)
			raw, err := json.Marshal(ring)
			if err != nil {
				t.Fatal(err)
			}
			assertCurrentEpochPayloadRejected(t, host, c, info, raw)
		})
	}
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("unknown fields", func(t *testing.T) {
		assertCurrentEpochPayloadRejected(t, host, c, info, append([]byte(`{"history":[],`), raw[1:]...))
	})
	t.Run("trailing payload", func(t *testing.T) { assertCurrentEpochPayloadRejected(t, host, c, info, append(raw, []byte(` {}`)...)) })
}

func assertCurrentEpochPayloadRejected(t *testing.T, host *HostIdentity, c CurrentEpochPackageContext, info, raw []byte) {
	t.Helper()
	enc, ct, err := WrapKey(c.RecipientPublicKey, info, nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCurrentEpochKeyPackage(&CurrentEpochKeyPackage{Version: 1, Enc: enc, Ciphertext: ct}, host.X25519Priv, c); err == nil {
		t.Fatal("opened malformed payload")
	}
}

func TestCurrentEpochPackageRejectsLegacyAndWireTampering(t *testing.T) {
	n, host, c := currentEpochFixture(t)
	legacy, err := n.BuildKeyPackage(host.X25519Pub)
	if err != nil {
		t.Fatal(err)
	}
	// Even relabeling a legacy package with the new version cannot cross the
	// HPKE domain boundary, including when legacy history has only one epoch.
	for _, count := range []int{3, 1} {
		if count == 1 {
			n.keyring.Epochs = n.keyring.Epochs[2:]
			legacy, err = n.BuildKeyPackage(host.X25519Pub)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := OpenCurrentEpochKeyPackage(&CurrentEpochKeyPackage{Version: 1, Enc: legacy.Enc, Ciphertext: legacy.Ciphertext}, host.X25519Priv, c); err == nil {
			t.Fatal("opened legacy package")
		}
	}
	pkg, err := n.BuildCurrentEpochKeyPackage(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{0, 2} {
		bad := *pkg
		bad.Version = version
		if _, err := OpenCurrentEpochKeyPackage(&bad, host.X25519Priv, c); err == nil {
			t.Fatal("opened unsupported version")
		}
	}
	pkg.Ciphertext[0] ^= 1
	if _, err := OpenCurrentEpochKeyPackage(pkg, host.X25519Priv, c); err == nil {
		t.Fatal("opened tampered ciphertext")
	}
	if _, err := OpenCurrentEpochKeyPackage(nil, host.X25519Priv, c); err == nil {
		t.Fatal("opened nil package")
	}
	if _, err := (*NKA)(nil).BuildCurrentEpochKeyPackage(c); err == nil {
		t.Fatal("built from nil authority")
	}
}

// JSON replaces invalid UTF-8 with U+FFFD. Reject such IDs before encoding so
// different raw identities cannot collapse to the same authenticated context.
func TestCurrentEpochPackageRejectsInvalidUTF8(t *testing.T) {
	n, host, c := currentEpochFixture(t)
	pkg, err := n.BuildCurrentEpochKeyPackage(c)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*CurrentEpochPackageContext){
		"owner":     func(c *CurrentEpochPackageContext) { c.OwnerTenantID += "\xff" },
		"network":   func(c *CurrentEpochPackageContext) { c.NetworkID += "\xff" },
		"grant":     func(c *CurrentEpochPackageContext) { c.GrantID += "\xff" },
		"recipient": func(c *CurrentEpochPackageContext) { c.RecipientID += "\xff" },
		"epoch":     func(c *CurrentEpochPackageContext) { c.EpochID += "\xff" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			invalid := c
			mutate(&invalid)
			if _, err := currentEpochPackageInfo(invalid); err == nil {
				t.Fatal("encoded invalid UTF-8 context")
			}
			if _, err := n.BuildCurrentEpochKeyPackage(invalid); err == nil {
				t.Fatal("built package with invalid UTF-8 context")
			}
			if _, err := OpenCurrentEpochKeyPackage(pkg, host.X25519Priv, invalid); err == nil {
				t.Fatal("opened package with invalid UTF-8 context")
			}
		})
	}
	t.Run("grant encoding collision", func(t *testing.T) {
		sender, expected := c, c
		sender.GrantID = "grant\xff"
		expected.GrantID = "grant\xfe"
		senderJSON, err := json.Marshal(sender)
		if err != nil {
			t.Fatal(err)
		}
		expectedJSON, err := json.Marshal(expected)
		if err != nil {
			t.Fatal(err)
		}
		if sender.GrantID == expected.GrantID || !bytes.Equal(senderJSON, expectedJSON) {
			t.Fatal("fixture does not demonstrate JSON identity collision")
		}
		// Simulate a package produced before UTF-8 validation was added.
		raw, err := json.Marshal(&Keyring{NetworkID: c.NetworkID, Epochs: []KeyEpoch{n.keyring.Epochs[2]}})
		if err != nil {
			t.Fatal(err)
		}
		info := append([]byte("pagnet/e2ee/current-epoch-keypackage/v1/"), senderJSON...)
		assertCurrentEpochPayloadRejected(t, host, expected, info, raw)
	})
}
