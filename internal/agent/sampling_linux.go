//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type DiskLatency struct {
	Device         string   `json:"device"` // e.g. /dev/sda
	ReadLatencyMS  *float64 `json:"read_latency_ms,omitempty"`
	WriteLatencyMS *float64 `json:"write_latency_ms,omitempty"`
	ReadIOPS       *float64 `json:"read_iops,omitempty"`
	WriteIOPS      *float64 `json:"write_iops,omitempty"`
}

type TopProcess struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	State      string  `json:"state"` // R/S/D/Z/T/...
	CPUPercent float64 `json:"cpu_percent"`
	RSSBytes   uint64  `json:"rss_bytes"`
}

type sampleResult struct {
	CPUPercent *float64
	Disk       []DiskLatency
	DiskAvg    map[string]*float64
	TopCPU     []TopProcess
	TopMem     []TopProcess
}

// sampleHostResources collects time-delta based metrics in a single sampling window.
// deviceBases is a set of base devices (e.g. /dev/sda, /dev/nvme0n1) to include.
func sampleHostResources(sample time.Duration, deviceBases map[string]bool) (*sampleResult, error) {
	if sample <= 0 {
		sample = 800 * time.Millisecond
	}

	// CPU times
	cpuA, err := readCPUTimes()
	if err != nil {
		return nil, err
	}

	// Disk stats
	diskA, err := readDiskstats()
	if err != nil {
		// tolerate
		diskA = map[string]diskStats{}
	}

	// Process snapshots
	procsA := readProcSnapshot()

	time.Sleep(sample)

	cpuB, err := readCPUTimes()
	if err != nil {
		return nil, err
	}
	diskB, err := readDiskstats()
	if err != nil {
		diskB = map[string]diskStats{}
	}
	procsB := readProcSnapshot()

	// system CPU percent
	dTotal := float64(cpuB.Total - cpuA.Total)
	var cpuPct *float64
	if dTotal > 0 {
		dIdle := float64(cpuB.Idle - cpuA.Idle)
		used := (dTotal - dIdle) / dTotal * 100
		used = round1(used)
		cpuPct = &used
	}

	sec := sample.Seconds()
	if sec <= 0 {
		sec = 1
	}

	// disk latency per device
	var lat []DiskLatency
	var sumReadMs, sumWriteMs uint64
	var sumReads, sumWrites uint64
	for dev, b := range diskB {
		a, ok := diskA[dev]
		if !ok {
			continue
		}
		base := "/dev/" + dev
		if len(deviceBases) > 0 && !deviceBases[base] {
			continue
		}
		dReads := b.ReadsCompleted - a.ReadsCompleted
		dReadMs := b.ReadMs - a.ReadMs
		dWrites := b.WritesCompleted - a.WritesCompleted
		dWriteMs := b.WriteMs - a.WriteMs

		var readLat *float64
		var writeLat *float64
		var readIops *float64
		var writeIops *float64
		if dReads > 0 {
			v := float64(dReadMs) / float64(dReads)
			v = round1(v)
			readLat = &v
			x := float64(dReads) / sec
			x = round1(x)
			readIops = &x
		}
		if dWrites > 0 {
			v := float64(dWriteMs) / float64(dWrites)
			v = round1(v)
			writeLat = &v
			x := float64(dWrites) / sec
			x = round1(x)
			writeIops = &x
		}
		lat = append(lat, DiskLatency{
			Device:         base,
			ReadLatencyMS:  readLat,
			WriteLatencyMS: writeLat,
			ReadIOPS:       readIops,
			WriteIOPS:      writeIops,
		})
		sumReadMs += dReadMs
		sumReads += dReads
		sumWriteMs += dWriteMs
		sumWrites += dWrites
	}
	// stable ordering
	sort.Slice(lat, func(i, j int) bool { return lat[i].Device < lat[j].Device })

	avg := map[string]*float64{}
	if sumReads > 0 {
		v := round1(float64(sumReadMs) / float64(sumReads))
		avg["read_latency_ms"] = &v
	}
	if sumWrites > 0 {
		v := round1(float64(sumWriteMs) / float64(sumWrites))
		avg["write_latency_ms"] = &v
	}

	// top processes
	dSys := float64(cpuB.Total - cpuA.Total)
	if dSys <= 0 {
		dSys = 1
	}
	procs := make([]TopProcess, 0, len(procsB))
	for pid, pb := range procsB {
		pa, ok := procsA[pid]
		if !ok {
			continue
		}
		dProc := float64(pb.CPUTicks - pa.CPUTicks)
		if dProc < 0 {
			continue
		}
		pct := dProc / dSys * 100.0
		// On some systems users expect percent of a single CPU; but for dashboards we
		// keep percent of total capacity.
		pct = round1(pct)
		procs = append(procs, TopProcess{PID: pid, Name: pb.Name, State: pb.State, CPUPercent: pct, RSSBytes: pb.RSSBytes})
	}
	// top by cpu
	topCPU := append([]TopProcess(nil), procs...)
	sort.Slice(topCPU, func(i, j int) bool { return topCPU[i].CPUPercent > topCPU[j].CPUPercent })
	if len(topCPU) > 5 {
		topCPU = topCPU[:5]
	}
	// top by mem
	topMem := append([]TopProcess(nil), procs...)
	sort.Slice(topMem, func(i, j int) bool { return topMem[i].RSSBytes > topMem[j].RSSBytes })
	if len(topMem) > 5 {
		topMem = topMem[:5]
	}

	_ = runtime.NumCPU() // keep import stable if we later change cpu percent semantics
	return &sampleResult{CPUPercent: cpuPct, Disk: lat, DiskAvg: avg, TopCPU: topCPU, TopMem: topMem}, nil
}

type diskStats struct {
	ReadsCompleted  uint64
	ReadMs          uint64
	WritesCompleted uint64
	WriteMs         uint64
}

func readDiskstats() (map[string]diskStats, error) {
	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]diskStats{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		// ignore partitions (heuristic): names ending in digits are partitions, except nvme which uses pN
		if isPartitionName(name) {
			continue
		}
		reads, err1 := strconv.ParseUint(fields[3], 10, 64)
		readMs, err2 := strconv.ParseUint(fields[6], 10, 64)
		writes, err3 := strconv.ParseUint(fields[7], 10, 64)
		writeMs, err4 := strconv.ParseUint(fields[10], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			continue
		}
		out[name] = diskStats{ReadsCompleted: reads, ReadMs: readMs, WritesCompleted: writes, WriteMs: writeMs}
	}
	return out, nil
}

func isPartitionName(name string) bool {
	// nvme base devices end with digits too (nvme0n1). Partitions have a trailing pN.
	if strings.HasPrefix(name, "nvme") {
		idx := strings.LastIndex(name, "p")
		if idx > 0 {
			suf := name[idx+1:]
			if suf != "" {
				_, err := strconv.Atoi(suf)
				return err == nil
			}
		}
		return false
	}
	// mmcblk base devices end with digits too (mmcblk0). Partitions have a trailing pN.
	if strings.HasPrefix(name, "mmcblk") {
		idx := strings.LastIndex(name, "p")
		if idx > 0 {
			suf := name[idx+1:]
			if suf != "" {
				_, err := strconv.Atoi(suf)
				return err == nil
			}
		}
		return false
	}
	// dm-0 and md0 are full virtual block devices, not partitions.
	if strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "md") {
		return false
	}
	// sda1, vda2, xvda1
	last := name[len(name)-1]
	return last >= '0' && last <= '9'
}

type procSnap struct {
	Name     string
	State    string
	CPUTicks uint64
	RSSBytes uint64
}

func readProcSnapshot() map[int]procSnap {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := map[int]procSnap{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		name, state, cpuTicks, err := readProcStat(pid)
		if err != nil {
			continue
		}
		rss, _ := readProcRSS(pid)
		out[pid] = procSnap{Name: name, State: state, CPUTicks: cpuTicks, RSSBytes: rss}
	}
	return out
}

func readProcStat(pid int) (name string, state string, cpuTicks uint64, _ error) {
	b, err := os.ReadFile(filepath.Join("/proc", fmt.Sprint(pid), "stat"))
	if err != nil {
		return "", "", 0, err
	}
	s := string(b)
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close < 0 || close <= open {
		return "", "", 0, fmt.Errorf("bad stat")
	}
	name = s[open+1 : close]
	rest := strings.Fields(strings.TrimSpace(s[close+1:]))
	if len(rest) < 13 {
		return "", "", 0, fmt.Errorf("short stat")
	}
	state = rest[0]
	utime, err1 := strconv.ParseUint(rest[11], 10, 64)
	stime, err2 := strconv.ParseUint(rest[12], 10, 64)
	if err1 != nil || err2 != nil {
		return "", "", 0, fmt.Errorf("parse ticks")
	}
	return name, state, utime + stime, nil
}

func readProcRSS(pid int) (uint64, error) {
	f, err := os.Open(filepath.Join("/proc", fmt.Sprint(pid), "status"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return kb * 1024, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found")
}
