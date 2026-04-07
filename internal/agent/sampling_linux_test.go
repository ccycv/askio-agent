//go:build linux

package agent

import "testing"

func TestIsPartitionName(t *testing.T) {
	cases := map[string]bool{
		"sda":        false,
		"sda1":       true,
		"nvme0n1":    false,
		"nvme0n1p1":  true,
		"mmcblk0":    false,
		"mmcblk0p1":  true,
		"vda":        false,
		"vda2":       true,
		"xvda":       false,
		"xvda1":      true,
		"md0":        false,
		"dm-0":       false,
	}
	for name, want := range cases {
		if got := isPartitionName(name); got != want {
			t.Fatalf("%s got=%v want=%v", name, got, want)
		}
	}
}
