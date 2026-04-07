//go:build !linux

package agent

import "time"

func sampleHostResources(sample time.Duration, deviceBases map[string]bool) (*sampleResult, error) {
	return nil, nil
}

