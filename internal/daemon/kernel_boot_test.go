package daemon

import "testing"

func TestKernelBootUUIDNormalization(t *testing.T) {
	got, err := kernelBootUUID("  ABCDEFAB-1234-4234-8234-ABCDEFABCDEF\n", "darwin_bootsessionuuid")
	if err != nil || got.Identity != "abcdefab-1234-4234-8234-abcdefabcdef" || !got.Valid() {
		t.Fatalf("normalization failed: %+v %v", got, err)
	}
	for _, value := range []string{"", "daemon-restarted", "00000000-0000-0000-0000-000000000000"} {
		if _, err := kernelBootUUID(value, "linux_boot_id"); err == nil {
			t.Fatal("unavailable UUID accepted")
		}
	}
}
