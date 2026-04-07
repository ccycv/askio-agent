package agent

import "os/exec"

// detectCapabilities returns best-effort capabilities detected on the host.
//
// These are meant to power UX decisions (e.g. show "Ansible already installed").
// Detection is intentionally simple (LookPath) and should not error if something fails.
func detectCapabilities() map[string]bool {
	caps := map[string]bool{}
	setIfFound := func(key string, binaries ...string) {
		for _, b := range binaries {
			if _, err := exec.LookPath(b); err == nil {
				caps[key] = true
				return
			}
		}
		caps[key] = false
	}

	setIfFound("ansible", "ansible")
	setIfFound("docker", "docker")
	setIfFound("podman", "podman")

	return caps
}
