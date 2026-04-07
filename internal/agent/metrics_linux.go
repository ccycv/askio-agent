//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type cpuTimes struct {
	Idle  uint64
	Total uint64
}

func getSystemCPUPercent(sample time.Duration) (*float64, error) {
	if sample <= 0 {
		sample = time.Second
	}
	// Sample CPU times twice and compute utilization.
	a, err := readCPUTimes()
	if err != nil {
		return nil, err
	}
	time.Sleep(sample)
	b, err := readCPUTimes()
	if err != nil {
		return nil, err
	}

	dTotal := float64(b.Total - a.Total)
	if dTotal <= 0 {
		v := 0.0
		return &v, nil
	}
	dIdle := float64(b.Idle - a.Idle)
	used := (dTotal - dIdle) / dTotal * 100.0
	used = round1(used)
	return &used, nil
}

func readCPUTimes() (cpuTimes, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	line, err := br.ReadString('\n')
	if err != nil {
		// still try to parse what we got
	}
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuTimes{}, fmt.Errorf("unexpected /proc/stat format")
	}
	var nums []uint64
	for _, f := range fields[1:] {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return cpuTimes{}, err
		}
		nums = append(nums, n)
	}
	var total uint64
	for _, n := range nums {
		total += n
	}
	idle := nums[3]
	if len(nums) > 4 {
		idle += nums[4] // iowait
	}
	return cpuTimes{Idle: idle, Total: total}, nil
}

func getSystemMemoryPercent() (*float64, error) {
	// Use MemTotal and MemAvailable.
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var totalKB uint64
	var availKB uint64
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			v, err := parseMeminfoKB(line)
			if err == nil {
				totalKB = v
			}
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			v, err := parseMeminfoKB(line)
			if err == nil {
				availKB = v
			}
		}
		if totalKB > 0 && availKB > 0 {
			break
		}
	}
	if totalKB == 0 {
		return nil, fmt.Errorf("memtotal not found")
	}
	if availKB == 0 {
		return nil, fmt.Errorf("memavailable not found")
	}

	used := float64(totalKB-availKB) / float64(totalKB) * 100.0
	used = round1(used)
	return &used, nil
}

type MemoryBreakdown struct {
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	CachedBytes    uint64  `json:"cached_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

func getSystemMemoryBreakdown() (*MemoryBreakdown, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var totalKB uint64
	var availKB uint64
	var cachedKB uint64
	var buffersKB uint64

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			v, _ := parseMeminfoKB(line)
			totalKB = v
		case strings.HasPrefix(line, "MemAvailable:"):
			v, _ := parseMeminfoKB(line)
			availKB = v
		case strings.HasPrefix(line, "Cached:"):
			v, _ := parseMeminfoKB(line)
			cachedKB = v
		case strings.HasPrefix(line, "Buffers:"):
			v, _ := parseMeminfoKB(line)
			buffersKB = v
		}
		if totalKB > 0 && availKB > 0 && cachedKB > 0 {
			// buffers is optional
			break
		}
	}
	if totalKB == 0 || availKB == 0 {
		return nil, fmt.Errorf("meminfo missing MemTotal/MemAvailable")
	}
	// We count buffers as part of "cached" for UI purposes.
	cachedKB += buffersKB
	usedKB := totalKB - availKB
	usedPct := round1(float64(usedKB) / float64(totalKB) * 100.0)

	return &MemoryBreakdown{
		TotalBytes:     totalKB * 1024,
		UsedBytes:      usedKB * 1024,
		AvailableBytes: availKB * 1024,
		CachedBytes:    cachedKB * 1024,
		UsedPercent:    usedPct,
	}, nil
}

func parseMeminfoKB(line string) (uint64, error) {
	// e.g. "MemTotal:       16384256 kB"
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, fmt.Errorf("invalid meminfo line")
	}
	return strconv.ParseUint(fields[1], 10, 64)
}

func round1(v float64) float64 {
	// round to 1 decimal
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	return float64(int(v*10+0.5)) / 10
}
