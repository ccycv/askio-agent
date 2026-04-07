//go:build linux

package agent

import "testing"

func TestParseMountInfoLine(t *testing.T) {
	// Simplified mountinfo line.
	line := "27 23 8:1 / / rw,relatime - ext4 /dev/sda1 rw"
	mp, src, fs, err := parseMountInfoLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if mp != "/" {
		t.Fatalf("mountpoint=%q", mp)
	}
	if src != "/dev/sda1" {
		t.Fatalf("source=%q", src)
	}
	if fs != "ext4" {
		t.Fatalf("fstype=%q", fs)
	}
}

func TestBlockDeviceBase(t *testing.T) {
	if got := blockDeviceBase("/dev/sda1"); got != "/dev/sda" {
		t.Fatalf("got %q", got)
	}
	if got := blockDeviceBase("/dev/nvme0n1p2"); got != "/dev/nvme0n1" {
		t.Fatalf("got %q", got)
	}
}

func TestParseUint(t *testing.T) {
	v, err := parseUint("123")
	if err != nil || v != 123 {
		t.Fatalf("%v %d", err, v)
	}
	_, err = parseUint("12a")
	if err == nil {
		t.Fatalf("expected error")
	}
}
