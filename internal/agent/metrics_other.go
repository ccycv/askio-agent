//go:build !linux

package agent

import "time"

func getSystemCPUPercent(sample time.Duration) (*float64, error) { return nil, nil }
func getSystemMemoryPercent() (*float64, error)                { return nil, nil }
func getSystemMemoryBreakdown() (*MemoryBreakdown, error)      { return nil, nil }
