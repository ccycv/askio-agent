# Resource telemetry / Heartbeat payload (developer docs)

The agent sends a periodic heartbeat:

`POST {api_url}/monitor-agent-heartbeat`

Implementation: `internal/agent/daemon.go: postHeartbeat()`.

This document focuses on **resource-related** heartbeat fields and how they’re computed.

> Note: backend should treat the heartbeat schema as **append-only** and ignore unknown keys.

## CPU

Field:

- `cpu_percent`: float

Linux implementation:

- `internal/agent/metrics_linux.go: getSystemCPUPercent()`
- samples `/proc/stat` twice (default ~800ms) and computes utilization.

## Memory

Fields:

- `memory_percent`: float
- `memory`: object (breakdown)

Breakdown (`internal/agent/metrics_linux.go: getSystemMemoryBreakdown()`):

```json
"memory": {
  "total_bytes": 0,
  "used_bytes": 0,
  "available_bytes": 0,
  "cached_bytes": 0,
  "used_percent": 0
}
```

Computed from `/proc/meminfo`:

- `MemTotal`
- `MemAvailable`
- `Cached`
- `Buffers` (counted as part of `cached_bytes` for UI purposes)

## Disks (capacity)

Fields:

- `has_multiple_disks`: bool
- `disk_used_percent_root`: float|null
- `disks`: array

Linux implementation:

- `internal/agent/resources_linux.go: getDiskUsage()`
- parses `/proc/self/mountinfo` to find real mounts, filters pseudo FS, then uses `syscall.Statfs`.

Disk entry:

```json
{
  "device": "/dev/sda1",
  "mountpoint": "/",
  "fs_type": "ext4",
  "total_bytes": 0,
  "used_bytes": 0,
  "used_percent": 0
}
```

## Disk latency (I/O)

Fields:

- `disk_latency`: array (per device)
- `disk_latency_avg`: object (aggregate)

Linux implementation:

- `internal/agent/sampling_linux.go: sampleHostResources()`
- samples `/proc/diskstats` twice over a short window (default ~800ms).

Per device entry:

```json
{
  "device": "/dev/sda",
  "read_latency_ms": 12.4,
  "write_latency_ms": 48.2,
  "read_iops": 10.5,
  "write_iops": 2.1
}
```

Aggregate:

```json
"disk_latency_avg": {
  "read_latency_ms": 8.1,
  "write_latency_ms": 3.2
}
```

How it’s computed:

- `avg_read_latency_ms ≈ delta(read_time_ms) / delta(reads_completed)`
- `avg_write_latency_ms ≈ delta(write_time_ms) / delta(writes_completed)`

Limitations:

- This is a **windowed average** over the sample duration.
- It’s a good dashboard signal, not a full IO profiler.

## Network

Fields:

- `network_interfaces`: array (IPs, MAC, up/down)
- `network_counters`: array (rx/tx counters)

Linux implementation:

- `internal/agent/resources_linux.go: getNetworkInterfaces()` via `net.Interfaces()`.
- `internal/agent/resources_linux.go: getNetworkCounters()` parses `/proc/net/dev`.

Counters entry:

```json
{"name":"eth0","rx_bytes":123,"tx_bytes":456}
```

Backend/UI can compute throughput by taking deltas:

- `rx_rate = (rx_bytes_now - rx_bytes_prev) / dt_seconds`
- `tx_rate = (tx_bytes_now - tx_bytes_prev) / dt_seconds`

## Top processes

Fields:

- `top_processes_cpu`: array (top 5)
- `top_processes_mem`: array (top 5)

Linux implementation:

- `internal/agent/sampling_linux.go`
- scans `/proc/<pid>/stat` (CPU ticks) and `/proc/<pid>/status` (VmRSS).
- CPU% computed using deltas vs system CPU ticks over the same sampling window.

Entry:

```json
{
  "pid": 1234,
  "name": "postgres",
  "state": "R",
  "cpu_percent": 24.2,
  "rss_bytes": 4200000000
}
```

## Capabilities

Heartbeat includes:

- `capabilities.handlers`: list of Operations Platform handler IDs
- `capabilities.playbooks`: list of remediation playbooks
- `capabilities.operations_config`: info about `command.run` gating

See `docs/OPERATIONS.md`.
