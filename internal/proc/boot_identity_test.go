package proc

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

const testBootUUID = "b0d87be4-4d89-4b10-a7f2-e97f4f998f15"

func TestBootIdentityUUIDParsing(t *testing.T) {
	for _, raw := range []string{testBootUUID, strings.ToUpper(testBootUUID) + "\n", " \t" + testBootUUID + "\n"} {
		got, err := parseBootUUID(raw, "linux-boot-id:", linuxBootIDPath)
		if err != nil || got.ID != "linux-boot-id:"+testBootUUID || got.Source != linuxBootIDPath || got.Quality != "boot_uuid" {
			t.Fatalf("canonical kernel UUID: got=%+v err=%v", got, err)
		}
	}
	for name, raw := range map[string]string{
		"empty": "", "nil": "00000000-0000-0000-0000-000000000000",
		"compact":     strings.ReplaceAll(testBootUUID, "-", ""),
		"invalid-hex": "z" + testBootUUID[1:], "injected": testBootUUID + "\nother",
		"nul": testBootUUID + "\x00", "oversized": strings.Repeat(" ", 65) + testBootUUID,
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := parseBootUUID(raw, "linux-boot-id:", linuxBootIDPath); err == nil || got != (BootIdentity{}) {
				t.Fatalf("accepted invalid boot UUID: %+v err=%v", got, err)
			}
		})
	}
}

func TestBootIdentityLinuxRead(t *testing.T) {
	reader := func(path string) ([]byte, error) {
		if path != linuxBootIDPath {
			t.Fatalf("unexpected kernel path %q", path)
		}
		return []byte(testBootUUID + "\n"), nil
	}
	first, err := readLinuxBootIdentity(reader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := readLinuxBootIdentity(reader)
	if err != nil || first != second {
		t.Fatalf("same boot changed identity: %+v %+v err=%v", first, second, err)
	}
	sentinel := errors.New("unavailable")
	if got, err := readLinuxBootIdentity(func(string) ([]byte, error) { return nil, sentinel }); !errors.Is(err, sentinel) || got != (BootIdentity{}) {
		t.Fatalf("read error did not fail closed: %+v err=%v", got, err)
	}
	if got, err := readLinuxBootIdentity(func(string) ([]byte, error) { return []byte("malformed"), nil }); err == nil || got != (BootIdentity{}) {
		t.Fatalf("malformed read did not fail closed: %+v err=%v", got, err)
	}
}

func TestBootIdentityDarwinPrefersUUID(t *testing.T) {
	got, err := readDarwinBootIdentity(func(name string) (string, error) {
		if name != "kern.bootsessionuuid" {
			t.Fatalf("unexpected sysctl %q", name)
		}
		return strings.ToUpper(testBootUUID), nil
	}, func(string) (int64, int64, error) { t.Fatal("boot time queried despite valid UUID"); return 0, 0, nil })
	if err != nil || got.ID != "darwin-boot-session:"+testBootUUID || got.Source != "kern.bootsessionuuid" || got.Quality != "boot_uuid" {
		t.Fatalf("UUID preference: %+v err=%v", got, err)
	}
}

func TestBootIdentityDarwinBootTimeFallback(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		readUUID := func(string) (string, error) {
			if malformed {
				return "malformed", nil
			}
			return "", errors.New("unsupported sysctl")
		}
		readTime := func(name string) (int64, int64, error) {
			if name != "kern.boottime" {
				t.Fatalf("unexpected sysctl %q", name)
			}
			return 1700000000, 123456, nil
		}
		got, err := readDarwinBootIdentity(readUUID, readTime)
		if err != nil || got.ID != "darwin-boot-time:1700000000:123456" || got.Source != "kern.boottime" || got.Quality != "boot_time" {
			t.Fatalf("boot time fallback: %+v err=%v", got, err)
		}
		again, err := readDarwinBootIdentity(readUUID, readTime)
		if err != nil || again != got {
			t.Fatalf("unstable boot time identity: %+v err=%v", again, err)
		}
		changed, err := readDarwinBootIdentity(readUUID, func(string) (int64, int64, error) { return 1700000000, 123457, nil })
		if err != nil || changed.ID == got.ID {
			t.Fatalf("distinct boot timeval collided: %+v err=%v", changed, err)
		}
	}
}

func TestBootIdentityDarwinInvalidTimeFailsClosed(t *testing.T) {
	for _, pair := range [][2]int64{{0, 0}, {-1, 0}, {253402300800, 0}, {1700000000, -1}, {1700000000, 1000000}} {
		got, err := readDarwinBootIdentity(func(string) (string, error) { return "invalid", nil }, func(string) (int64, int64, error) { return pair[0], pair[1], nil })
		if err == nil || got != (BootIdentity{}) {
			t.Fatalf("invalid timeval %v accepted: %+v err=%v", pair, got, err)
		}
	}
	sentinel := errors.New("unreadable timeval")
	got, err := readDarwinBootIdentity(func(string) (string, error) { return "", errors.New("no uuid") }, func(string) (int64, int64, error) { return 0, 0, sentinel })
	if !errors.Is(err, sentinel) || got != (BootIdentity{}) {
		t.Fatalf("time read error did not fail closed: %+v err=%v", got, err)
	}
}

func TestBootIdentityKernelStable(t *testing.T) {
	first, err := ReadBootIdentity()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		if err == nil || first != (BootIdentity{}) {
			t.Fatalf("unsupported platform did not fail closed: %+v err=%v", first, err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReadBootIdentity()
	if err != nil || first != second || first.ID == "" || len(first.ID) >= 128 || first.Source == "" || first.Quality == "" {
		t.Fatalf("invalid/unstable kernel identity: first=%+v second=%+v err=%v", first, second, err)
	}
}
