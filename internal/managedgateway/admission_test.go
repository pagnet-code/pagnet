package managedgateway

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validAdmission() GatewayAdmission {
	digest := strings.Repeat("a", 64)
	return GatewayAdmission{
		Source: SourceGateway, OperationID: "operation", OwnerID: "owner",
		TenantID: "tenant", HostID: "host", InstallationID: "installation",
		InstallationGeneration: "generation", ExecutableGrantID: "grant",
		ExecutableGrantVersion: "version", V2ProjectID: "project", PolicyHash: digest,
		ServiceID: "service", SenderID: "sender", ASKID: "ask", ASKWireDigest: digest,
		InputDigest: digest, TargetDefinitionID: "target", TargetDefinitionRevision: "revision",
		TargetDefinitionFingerprint: digest, WorkerInstanceID: "worker", WorkerIncarnation: "incarnation",
		ConfigurationFingerprint: digest, IsolationFingerprint: digest,
		Deadline:      time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		MaxInputBytes: 1 << 20, MaxResultBytes: 1 << 20, MaxConcurrency: 1,
	}
}

func TestGatewayAdmissionStructuralCompleteness(t *testing.T) {
	a := validAdmission()
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	// A map key makes comparability a compile-time requirement.
	_ = map[GatewayAdmission]bool{a: true}
	typ := reflect.TypeOf(a)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		t.Run(field.Name, func(t *testing.T) {
			if field.Tag.Get("json") == "" {
				t.Fatal("missing explicit JSON name")
			}
			changed := a
			reflect.ValueOf(&changed).Elem().Field(i).SetZero()
			if err := changed.Validate(); err == nil {
				t.Fatal("accepted missing field")
			}
		})
	}
}

func TestGatewayAdmissionDigest(t *testing.T) {
	a := validAdmission()
	want, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if want != sha256.Sum256(data) {
		t.Fatal("digest does not bind canonical JSON")
	}
	if got, err := a.Digest(); err != nil || got != want {
		t.Fatalf("unstable digest: %v", err)
	}
	typ := reflect.TypeOf(a)
	for i := 1; i < typ.NumField(); i++ {
		t.Run(typ.Field(i).Name, func(t *testing.T) {
			changed := a
			field := reflect.ValueOf(&changed).Elem().Field(i)
			switch field.Kind() {
			case reflect.String:
				if len(field.String()) == 64 {
					field.SetString(strings.Repeat("b", 64))
				} else {
					field.SetString(field.String() + "2")
				}
			case reflect.Int64:
				field.SetInt(field.Int() - 1)
			case reflect.Int:
				// The dormant concurrency value has no second valid value.
				field.SetInt(2)
			case reflect.Struct:
				field.Set(reflect.ValueOf(a.Deadline.Add(time.Second)))
			}
			got, err := changed.Digest()
			if typ.Field(i).Name == "MaxConcurrency" {
				if err == nil || got != [32]byte{} {
					t.Fatal("digest accepted invalid concurrency")
				}
				return
			}
			if err != nil || got == want {
				t.Fatalf("mutation not bound by digest: %v", err)
			}
		})
	}
}

func TestGatewayAdmissionRejectsMalformedValues(t *testing.T) {
	cases := []struct {
		name string
		edit func(*GatewayAdmission)
	}{
		{"wrong source", func(a *GatewayAdmission) { a.Source = "native" }},
		{"invalid UTF8 identity", func(a *GatewayAdmission) { a.OwnerID = string([]byte{0xff}) }},
		{"long identity", func(a *GatewayAdmission) { a.OwnerID = strings.Repeat("x", 257) }},
		{"non UTC deadline", func(a *GatewayAdmission) { a.Deadline = a.Deadline.In(time.FixedZone("offset", 3600)) }},
		{"negative input", func(a *GatewayAdmission) { a.MaxInputBytes = -1 }},
		{"large input", func(a *GatewayAdmission) { a.MaxInputBytes = 1<<20 + 1 }},
		{"negative result", func(a *GatewayAdmission) { a.MaxResultBytes = -1 }},
		{"large result", func(a *GatewayAdmission) { a.MaxResultBytes = 1<<20 + 1 }},
		{"negative concurrency", func(a *GatewayAdmission) { a.MaxConcurrency = -1 }},
		{"parallel concurrency", func(a *GatewayAdmission) { a.MaxConcurrency = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAdmission()
			tc.edit(&a)
			if _, err := a.Digest(); err == nil {
				t.Fatal("accepted malformed admission")
			}
		})
	}
	for _, name := range []string{"PolicyHash", "ASKWireDigest", "InputDigest", "TargetDefinitionFingerprint", "ConfigurationFingerprint", "IsolationFingerprint"} {
		for _, value := range []string{strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
			t.Run(name+"/"+value, func(t *testing.T) {
				a := validAdmission()
				reflect.ValueOf(&a).Elem().FieldByName(name).SetString(value)
				if err := a.Validate(); err == nil {
					t.Fatal("accepted malformed SHA256")
				}
			})
		}
	}
	a := validAdmission()
	a.OwnerID = strings.Repeat("x", 256)
	a.MaxInputBytes, a.MaxResultBytes = 1, 1
	if err := a.Validate(); err != nil {
		t.Fatalf("rejected valid lower byte limits or identity boundary: %v", err)
	}
}

func TestGatewayReceiptDescriptor(t *testing.T) {
	for _, state := range []ReceiptState{ReceiptCompleted, ReceiptFailed, ReceiptUnknown} {
		r := GatewayReceipt{State: state}
		if _, err := json.Marshal(r); err != nil {
			t.Fatal(err)
		}
	}
	typ := reflect.TypeOf(GatewayReceipt{})
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Tag.Get("json") == "" {
			t.Fatalf("missing JSON name for %s", typ.Field(i).Name)
		}
	}
}
