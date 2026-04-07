package agent

import (
	"bufio"
	"os"
	"runtime"
	"strings"
)

type OSInfo struct {
	Distro  string `json:"distro"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

func detectOS() *OSInfo {
	// Best-effort OS detection.
	info := &OSInfo{Arch: runtime.GOARCH}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return info
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, "\"")
		switch k {
		case "ID":
			info.Distro = v
		case "VERSION_ID":
			info.Version = v
		}
		if info.Distro != "" && info.Version != "" {
			break
		}
	}
	return info
}
