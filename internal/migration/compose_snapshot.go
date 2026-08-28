package migration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"gopkg.in/yaml.v3"
)

const defaultBrokerComposeSnapshotRoot = "/run/askio-migration-broker/compose"

type immutableComposeSnapshotMetadata struct {
	SchemaVersion  string   `json:"schema_version"`
	Project        string   `json:"project"`
	SourceRoot     string   `json:"source_root"`
	ApprovedDigest string   `json:"approved_digest"`
	SnapshotDigest string   `json:"snapshot_digest"`
	ComposeFile    string   `json:"compose_file"`
	SecretNames    []string `json:"secret_names"`
	PublishedPorts []int    `json:"published_ports"`
	NamedVolumes   []string `json:"named_volumes"`
	NetworkNames   []string `json:"network_names"`
	ServiceCount   int      `json:"service_count"`
}

type immutableComposeSnapshot struct {
	Directory string
	FilePath  string
	Metadata  immutableComposeSnapshotMetadata
}

func (b *Broker) composeSnapshotRoot() string {
	if b.config.ComposeSnapshotRoot != "" {
		return b.config.ComposeSnapshotRoot
	}
	return defaultBrokerComposeSnapshotRoot
}

func requireOwnedDirectory(path string, permission os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != permission {
		return errors.New("root-owned Compose snapshot directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && int(stat.Uid) != os.Geteuid() {
		return errors.New("root-owned Compose snapshot directory has the wrong owner")
	}
	return nil
}

func readStableRegularFile(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.New("Compose snapshot input is missing or unsafe")
	}
	file, err := openNoSymlink(path)
	if err != nil {
		return nil, errors.New("Compose snapshot input could not be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() < 1 || opened.Size() > maximum {
		return nil, errors.New("Compose snapshot input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != opened.Size() || int64(len(data)) > maximum {
		zeroBytes(data)
		return nil, errors.New("Compose snapshot input changed while reading")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || after.ModTime() != opened.ModTime() {
		zeroBytes(data)
		return nil, errors.New("Compose snapshot input changed while reading")
	}
	return data, nil
}

func writeRootOwnedFile(path string, data []byte, permission os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permission)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(permission); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func cloneComposeDocument(document composeDocument) composeDocument {
	clone := document
	clone.Secrets = make(map[string]composeSecret, len(document.Secrets))
	for name, secret := range document.Secrets {
		clone.Secrets[name] = secret
	}
	return clone
}

func (b *Broker) createImmutableComposeSnapshot(root, project string, policy composePolicyResult) (immutableComposeSnapshot, error) {
	snapshotRoot := b.composeSnapshotRoot()
	if err := os.MkdirAll(snapshotRoot, 0o700); err != nil {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot root is unavailable")
	}
	if err := os.Chmod(snapshotRoot, 0o700); err != nil || requireOwnedDirectory(snapshotRoot, 0o700) != nil {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot root is unsafe")
	}
	finalDirectory := filepath.Join(snapshotRoot, project)
	if _, err := os.Lstat(finalDirectory); err == nil {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot collision")
	} else if !os.IsNotExist(err) {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot collision probe failed")
	}
	temporaryDirectory, err := os.MkdirTemp(snapshotRoot, "."+project+"-")
	if err != nil {
		return immutableComposeSnapshot{}, err
	}
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = os.RemoveAll(temporaryDirectory)
		}
	}()
	if err := os.Chmod(temporaryDirectory, 0o700); err != nil {
		return immutableComposeSnapshot{}, err
	}

	document := cloneComposeDocument(policy.Document)
	secretNames := make([]string, 0, len(policy.SecretFiles))
	for name := range policy.SecretFiles {
		secretNames = append(secretNames, name)
	}
	sort.Strings(secretNames)
	for _, name := range secretNames {
		data, err := readStableRegularFile(policy.SecretFiles[name], 16*1024)
		if err != nil {
			return immutableComposeSnapshot{}, err
		}
		snapshotPath := filepath.Join(temporaryDirectory, "secret-"+name)
		writeErr := writeRootOwnedFile(snapshotPath, data, 0o444)
		zeroBytes(data)
		if writeErr != nil {
			return immutableComposeSnapshot{}, errors.New("Compose secret snapshot failed")
		}
		document.Secrets[name] = composeSecret{File: filepath.Join(finalDirectory, "secret-"+name)}
	}

	composeData, err := yaml.Marshal(document)
	if err != nil || len(composeData) < 1 || len(composeData) > 256*1024 || bytes.Contains(composeData, []byte("${")) {
		return immutableComposeSnapshot{}, errors.New("immutable Compose snapshot is invalid")
	}
	composeFile := "compose.yaml"
	if err := writeRootOwnedFile(filepath.Join(temporaryDirectory, composeFile), composeData, 0o400); err != nil {
		return immutableComposeSnapshot{}, errors.New("immutable Compose snapshot write failed")
	}
	metadata := immutableComposeSnapshotMetadata{
		SchemaVersion: "operations.migration.compose-snapshot.v1", Project: project, SourceRoot: root,
		ApprovedDigest: policy.Digest, SnapshotDigest: digestBytes(composeData), ComposeFile: composeFile,
		SecretNames: secretNames, PublishedPorts: append([]int{}, policy.PublishedPorts...),
		NamedVolumes: append([]string{}, policy.NamedVolumes...), NetworkNames: append([]string{}, policy.NetworkNames...),
		ServiceCount: len(policy.Document.Services),
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil || writeRootOwnedFile(filepath.Join(temporaryDirectory, "metadata.json"), metadataData, 0o400) != nil {
		return immutableComposeSnapshot{}, errors.New("immutable Compose snapshot metadata failed")
	}
	directory, err := os.Open(temporaryDirectory)
	if err != nil {
		return immutableComposeSnapshot{}, err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return immutableComposeSnapshot{}, err
	}
	if err := directory.Close(); err != nil {
		return immutableComposeSnapshot{}, err
	}
	if err := os.Rename(temporaryDirectory, finalDirectory); err != nil {
		return immutableComposeSnapshot{}, err
	}
	cleanupTemporary = false
	return immutableComposeSnapshot{Directory: finalDirectory, FilePath: filepath.Join(finalDirectory, composeFile), Metadata: metadata}, nil
}

func (b *Broker) loadImmutableComposeSnapshot(project, approvedDigest string) (immutableComposeSnapshot, error) {
	directory := filepath.Join(b.composeSnapshotRoot(), project)
	if err := requireOwnedDirectory(directory, 0o700); err != nil {
		return immutableComposeSnapshot{}, err
	}
	metadataData, err := readStableRegularFile(filepath.Join(directory, "metadata.json"), 64*1024)
	if err != nil {
		return immutableComposeSnapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(metadataData))
	decoder.DisallowUnknownFields()
	var metadata immutableComposeSnapshotMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot metadata is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot metadata has trailing data")
	}
	if metadata.SchemaVersion != "operations.migration.compose-snapshot.v1" || metadata.Project != project || metadata.ApprovedDigest != approvedDigest || metadata.ComposeFile != "compose.yaml" {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot identity changed")
	}
	composePath := filepath.Join(directory, metadata.ComposeFile)
	composeData, err := readStableRegularFile(composePath, 256*1024)
	if err != nil || digestBytes(composeData) != metadata.SnapshotDigest {
		return immutableComposeSnapshot{}, errors.New("Compose snapshot digest changed")
	}
	return immutableComposeSnapshot{Directory: directory, FilePath: composePath, Metadata: metadata}, nil
}

func (b *Broker) removeImmutableComposeSnapshot(snapshot immutableComposeSnapshot) error {
	for _, name := range snapshot.Metadata.SecretNames {
		path := filepath.Join(snapshot.Directory, "secret-"+name)
		if err := wipeAndRemoveComposeSecret(path); err != nil {
			return err
		}
	}
	for _, name := range []string{"compose.yaml", "metadata.json"} {
		path := filepath.Join(snapshot.Directory, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	entries, err := os.ReadDir(snapshot.Directory)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("Compose snapshot contains unexpected residual files")
	}
	if err := os.Remove(snapshot.Directory); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
