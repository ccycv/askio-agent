//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type DiskUsage struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	FSType      string  `json:"fs_type"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

type NetworkInterface struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac,omitempty"`
	IsUp  bool     `json:"is_up"`
	IPv4  []string `json:"ipv4"`
	IPv6  []string `json:"ipv6"`
}

type NetworkCounter struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

func getNetworkCounters() ([]NetworkCounter, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []NetworkCounter
	s := bufio.NewScanner(f)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		// skip headers
		if lineNo <= 2 || line == "" {
			continue
		}
		// format: <iface>: <rx bytes> ... <tx bytes> ...
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 9 {
			continue
		}
		rx, err1 := parseUint(fields[0])
		tx, err2 := parseUint(fields[8])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, NetworkCounter{Name: name, RxBytes: rx, TxBytes: tx})
	}
	return out, nil
}

func parseUint(s string) (uint64, error) {
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid uint")
		}
		v = v*10 + uint64(c-'0')
	}
	return v, nil
}

func getNetworkInterfaces() ([]NetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]NetworkInterface, 0, len(ifaces))
	for _, nic := range ifaces {
		addrs, _ := nic.Addrs()
		ipv4 := []string{}
		ipv6 := []string{}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				ipv4 = append(ipv4, ip.String())
			} else {
				ipv6 = append(ipv6, ip.String())
			}
		}
		out = append(out, NetworkInterface{
			Name: nic.Name,
			MAC:  nic.HardwareAddr.String(),
			IsUp: nic.Flags&net.FlagUp != 0,
			IPv4: ipv4,
			IPv6: ipv6,
		})
	}
	return out, nil
}

// getDiskUsage returns disk usage for "real" disks only.
//
// We parse /proc/self/mountinfo to discover mountpoints and filter out pseudo-fs.
// Then we use Statfs to compute total/used bytes.
func getDiskUsage() ([]DiskUsage, bool, *float64, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, false, nil, err
	}
	defer f.Close()

	skipFSTypes := map[string]bool{
		"tmpfs": true, "devtmpfs": true, "proc": true, "sysfs": true, "cgroup": true,
		"cgroup2": true, "overlay": true, "squashfs": true, "ramfs": true, "autofs": true,
		"mqueue": true, "debugfs": true, "tracefs": true, "fusectl": true,
		"securityfs": true, "pstore": true, "configfs": true, "bpf": true,
	}

	// For multi-disk detection: count distinct base block devices.
	devices := map[string]bool{}

	seenMount := map[string]bool{}
	seenDevMount := map[string]bool{}

	var out []DiskUsage
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		mp, src, fs, err := parseMountInfoLine(line)
		if err != nil {
			continue
		}
		if mp == "" || src == "" || fs == "" {
			continue
		}
		if skipFSTypes[fs] {
			continue
		}
		// skip container mounts
		if strings.Contains(mp, "/var/lib/docker/") || strings.Contains(mp, "/var/lib/containerd/") {
			continue
		}
		// skip snap
		if strings.HasPrefix(mp, "/snap/") {
			continue
		}
		// prefer only "real" mounts backed by block devices (heuristic)
		if !strings.HasPrefix(src, "/dev/") {
			continue
		}

		if seenMount[mp] {
			continue
		}
		seenMount[mp] = true
		key := src + "|" + mp
		if seenDevMount[key] {
			continue
		}
		seenDevMount[key] = true

		var st syscall.Statfs_t
		if err := syscall.Statfs(mp, &st); err != nil {
			continue
		}
		// Some pseudo mounts might still slip through; ignore zero-sized.
		total := uint64(st.Blocks) * uint64(st.Bsize)
		if total == 0 {
			continue
		}
		free := uint64(st.Bavail) * uint64(st.Bsize)
		used := total - free
		pct := float64(used) / float64(total) * 100.0
		pct = round1(pct)

		out = append(out, DiskUsage{
			Device:      src,
			Mountpoint:  mp,
			FSType:      fs,
			TotalBytes:  total,
			UsedBytes:   used,
			UsedPercent: pct,
		})

		devices[blockDeviceBase(src)] = true
	}

	var rootPct *float64
	for _, d := range out {
		if d.Mountpoint == "/" {
			v := d.UsedPercent
			rootPct = &v
			break
		}
	}

	hasMulti := len(devices) > 1
	return out, hasMulti, rootPct, nil
}

func parseMountInfoLine(line string) (mountpoint, source, fstype string, _ error) {
	// mountinfo format:
	// <id> <parent> <major:minor> <root> <mountpoint> <options> ... - <fstype> <source> <super>
	// We need mountpoint (field 5) and after the " - " separator, fstype and source.
	sep := strings.Index(line, " - ")
	if sep < 0 {
		return "", "", "", fmt.Errorf("no separator")
	}
	pre := strings.Fields(line[:sep])
	post := strings.Fields(line[sep+3:])
	if len(pre) < 5 || len(post) < 2 {
		return "", "", "", fmt.Errorf("bad mountinfo")
	}
	mp := pre[4]
	mp = strings.ReplaceAll(mp, "\\040", " ")
	mp = filepath.Clean(mp)
	fs := post[0]
	src := post[1]
	return mp, src, fs, nil
}

func blockDeviceBase(dev string) string {
	// /dev/sda1 -> /dev/sda, /dev/nvme0n1p2 -> /dev/nvme0n1
	// best-effort heuristic
	base := dev
	// trim trailing digits
	for len(base) > 0 {
		c := base[len(base)-1]
		if c >= '0' && c <= '9' {
			base = base[:len(base)-1]
			continue
		}
		break
	}
	// nvme partitions: ...pX
	if strings.HasSuffix(base, "p") {
		base = strings.TrimSuffix(base, "p")
	}
	return base
}
