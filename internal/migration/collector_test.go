package migration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerClientVersionDoesNotRequireDaemonAccess(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "docker")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" != \"--version\" ]; then echo 28.5.2; exit 1; fi\n" +
		"printf 'Docker version 28.5.2, build synthetic\\n'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatalf("write synthetic Docker client: %v", err)
	}

	version, ok := dockerClientVersion(context.Background(), []string{binary})
	if !ok {
		t.Fatal("static Docker client version probe unexpectedly required daemon access")
	}
	if version != "Docker version 28.5.2, build synthetic" {
		t.Fatalf("unexpected Docker client version %q", version)
	}
}
