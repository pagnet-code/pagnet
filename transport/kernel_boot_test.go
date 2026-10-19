package transport

import "testing"

func TestKernelBootEvidence(t *testing.T) {
	first := KernelBootEvidence{Identity: "11111111-1111-4111-8111-111111111111", Source: "linux_boot_id", Quality: "boot_uuid"}
	next := first
	next.Identity = "22222222-2222-4222-8222-222222222222"
	if !first.Valid() || !next.ProvesNewBoot(first) || first.ProvesNewBoot(first) {
		t.Fatal("UUID boot comparison failed")
	}
	for _, change := range []func(*KernelBootEvidence){
		func(b *KernelBootEvidence) { b.Identity = "" },
		func(b *KernelBootEvidence) { b.Identity = "daemon-start" },
		func(b *KernelBootEvidence) { b.Identity = "00000000-0000-0000-0000-000000000000" },
		func(b *KernelBootEvidence) { b.Quality = "boot_time" },
		func(b *KernelBootEvidence) { b.Source = "daemon_pid" },
	} {
		invalid := first
		change(&invalid)
		if invalid.Valid() || invalid.ProvesNewBoot(first) {
			t.Fatalf("invalid evidence accepted: %+v", invalid)
		}
	}
	bootTime := KernelBootEvidence{Identity: "1710000000.123456", Source: "darwin_boottime", Quality: "boot_time"}
	if !bootTime.Valid() {
		t.Fatal("valid boot time inventory rejected")
	}
	newerTime := bootTime
	newerTime.Identity = "1710000100.123456"
	if newerTime.ProvesNewBoot(bootTime) {
		t.Fatal("boot time authorized recovery")
	}
	darwin := next
	darwin.Source = "darwin_bootsessionuuid"
	if !darwin.Valid() || darwin.ProvesNewBoot(first) {
		t.Fatal("different source authorized recovery")
	}
}
