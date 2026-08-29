package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicReplaceFileInterruptionNeverLeavesPartialContent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is part of the installer contract")
	}
	steps := []string{
		"temporary-created",
		"content-written",
		"ownership-applied",
		"file-synced",
		"file-closed",
		"file-renamed",
		"directory-synced",
	}
	oldContent := []byte("old-complete\n")
	newContent := []byte("new-complete\n")
	for _, interruptedAt := range steps {
		t.Run(interruptedAt, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "fence.conf")
			if err := os.WriteFile(target, oldContent, 0o644); err != nil {
				t.Fatal(err)
			}
			err := atomicReplaceFile(target, newContent, 0o644, func(step string) error {
				if step == interruptedAt {
					return errors.New("injected installer interruption")
				}
				return nil
			})
			if err == nil {
				t.Fatal("injected interruption was not returned")
			}
			content, readErr := os.ReadFile(target)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(content) != string(oldContent) && string(content) != string(newContent) {
				t.Fatalf("interruption exposed partial content: %q", content)
			}
			if interruptedAt != "file-renamed" && interruptedAt != "directory-synced" && string(content) != string(oldContent) {
				t.Fatalf("target changed before atomic rename: %q", content)
			}
		})
	}
}

func TestActiveWriterFenceDropInIsNeverReplaced(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is part of the installer contract")
	}
	root := t.TempDir()
	unitRoot := filepath.Join(root, "units")
	markerRoot := filepath.Join(root, "markers")
	service := "database.service"
	directory := filepath.Join(unitRoot, service+".d")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(markerRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(markerRoot, service+".fenced")
	if err := os.WriteFile(marker, []byte("fenced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "90-askio-migration-fence.conf")
	expected := "[Unit]\nRequires=askio-migration-broker.service\nAfter=askio-migration-broker.service\nConditionPathExists=!" + marker + "\n"
	if err := os.WriteFile(target, []byte(expected), 0o644); err != nil {
		t.Fatal(err)
	}
	hookCalled := false
	if err := writeMigrationFenceDropIn(unitRoot, markerRoot, service, func(string) error {
		hookCalled = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if hookCalled {
		t.Fatal("active-fence drop-in entered the replacement path")
	}

	if err := os.WriteFile(target, []byte("truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeMigrationFenceDropIn(unitRoot, markerRoot, service, nil); err == nil {
		t.Fatal("changed active-fence drop-in was accepted")
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "truncated" {
		t.Fatalf("active-fence drop-in was mutated: %q", content)
	}
}
