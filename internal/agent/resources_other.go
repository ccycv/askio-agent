//go:build !linux

package agent

func getDiskUsage() ([]DiskUsage, bool, *float64, error) { return nil, false, nil, nil }
func getNetworkInterfaces() ([]NetworkInterface, error)  { return nil, nil }
func getNetworkCounters() ([]NetworkCounter, error)      { return nil, nil }
