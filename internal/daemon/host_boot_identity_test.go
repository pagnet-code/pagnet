package daemon

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/pagnet-code/pagnet/internal/proc"
)

func TestHostBootIdentityUnavailablePreservesHostRegistration(t *testing.T) {
	query := url.Values{"boot_id": {"ordinary-runner"}, "native_ownership": {"supported"}, "os_boot_identity": {"injected"}, "os_boot_source": {"injected"}, "os_boot_quality": {"injected"}}
	setHostBootIdentity(query, func() (proc.BootIdentity, error) { return proc.BootIdentity{}, errors.New("kernel unavailable") })
	for _, key := range []string{"os_boot_identity", "os_boot_source", "os_boot_quality"} {
		if query.Has(key) {
			t.Fatalf("unavailable kernel accepted configured evidence %s", key)
		}
	}
	if query.Get("boot_id") != "ordinary-runner" || query.Get("native_ownership") != "supported" {
		t.Fatal("ordinary host registration was disabled")
	}
}

func TestHostBootIdentityQuery(t *testing.T) {
	identity := proc.BootIdentity{ID: "linux-boot-id:11111111-1111-4111-8111-111111111111", Source: "/proc/sys/kernel/random/boot_id", Quality: "boot_uuid"}
	query := url.Values{}
	setHostBootIdentity(query, func() (proc.BootIdentity, error) { return identity, nil })
	if query.Get("os_boot_identity") != identity.ID || query.Get("os_boot_source") != identity.Source || query.Get("os_boot_quality") != identity.Quality {
		t.Fatal("kernel boot evidence omitted")
	}
	setHostBootIdentity(query, func() (proc.BootIdentity, error) { return proc.BootIdentity{ID: identity.ID}, nil })
	if query.Has("os_boot_identity") || query.Has("os_boot_source") || query.Has("os_boot_quality") {
		t.Fatal("partial kernel evidence advertised")
	}
}

func TestHostBootIdentityWSURLUsesKernelIdentity(t *testing.T) {
	d := &Daemon{Config: Config{ServerURL: "https://example.test/pagnet?os_boot_identity=injected&os_boot_source=injected&os_boot_quality=injected"}, bootID: "ordinary-runner"}
	parsed, err := url.Parse(d.wsURL(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme != "wss" || parsed.Path != "/pagnet/api/v1/hosts/ws" || query.Get("boot_id") != d.bootID {
		t.Fatal("ordinary host URL changed")
	}
	identity, err := proc.ReadBootIdentity()
	if err != nil {
		if query.Has("os_boot_identity") || query.Has("os_boot_source") || query.Has("os_boot_quality") {
			t.Fatal("kernel read failure advertised boot evidence")
		}
		return
	}
	if query.Get("os_boot_identity") != identity.ID || query.Get("os_boot_source") != identity.Source || query.Get("os_boot_quality") != identity.Quality {
		t.Fatal("WS URL did not use kernel evidence")
	}
}
