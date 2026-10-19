package daemon

import "testing"

func TestCollectKernelBootEvidence(t *testing.T) {
	first, err := CollectKernelBootEvidence()
	if err != nil {
		t.Fatal(err)
	}
	second, err := CollectKernelBootEvidence()
	if err != nil || first != second || !first.Valid() || first.Source != "linux_boot_id" || first.Quality != "boot_uuid" {
		t.Fatalf("kernel boot unstable or invalid: %+v %+v %v", first, second, err)
	}
}
