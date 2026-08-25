package migration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	fileManifestSchema     = "operations.migration.file-manifest.v1"
	maximumManifestEntries = 250_000
	maximumManifestBytes   = int64(500 * 1024 * 1024 * 1024)
	transferChunkSize      = int64(4 * 1024 * 1024)
	fileSyncReserveBytes   = int64(16 * 1024 * 1024)
	fileSyncReservePercent = int64(15)
	maximumSignedInt64     = int64(1<<63 - 1)
)

var fileDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var errMigrationDiskCapacity = errors.New("migration storage capacity preflight failed")

type FileManifestEntry struct {
	Relative         string `json:"relative"`
	Type             string `json:"type"`
	SizeBytes        int64  `json:"size_bytes"`
	Mode             uint32 `json:"mode"`
	ModifiedUnixNano int64  `json:"modified_unix_nano"`
	SHA256           string `json:"sha256,omitempty"`
}

type FileManifest struct {
	SchemaVersion string              `json:"schema_version"`
	Entries       []FileManifestEntry `json:"entries"`
}

type FileManifestSummary struct {
	Manifest       FileManifest
	Digest         string
	FileCount      int
	DirectoryCount int
	TotalBytes     int64
}

func openRegularNoFollow(path string) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, errors.New("file descriptor conversion failed")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, errors.New("migration file changed to an unsupported type")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink > 1 {
		file.Close()
		return nil, nil, errors.New("hard-linked files require an explicit future policy")
	}
	return file, info, nil
}

func hashOpenFile(file *os.File) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func buildFileManifest(ctx context.Context, root string, progress func(int64) error) (FileManifestSummary, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return FileManifestSummary{}, errors.New("migration file root is unavailable or unsafe")
	}
	summary := FileManifestSummary{Manifest: FileManifest{SchemaVersion: fileManifestSchema, Entries: []FileManifestEntry{}}}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if len(summary.Manifest.Entries) >= maximumManifestEntries {
			return errors.New("file manifest exceeded the 250000-entry safety limit")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || strings.ContainsRune(relative, '\x00') {
			return errors.New("file manifest relative path is invalid")
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlinks require an explicit future policy and are blocked")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		manifestEntry := FileManifestEntry{Relative: relative, Mode: uint32(info.Mode().Perm()), ModifiedUnixNano: info.ModTime().Unix() * int64(time.Second)}
		switch {
		case info.IsDir():
			manifestEntry.Type = "directory"
			summary.DirectoryCount++
		case info.Mode().IsRegular():
			file, openedInfo, err := openRegularNoFollow(path)
			if err != nil {
				return err
			}
			digest, hashErr := hashOpenFile(file)
			closeErr := file.Close()
			if hashErr != nil {
				return hashErr
			}
			if closeErr != nil {
				return closeErr
			}
			manifestEntry.Type = "file"
			manifestEntry.SizeBytes = openedInfo.Size()
			manifestEntry.Mode = uint32(openedInfo.Mode().Perm())
			manifestEntry.ModifiedUnixNano = openedInfo.ModTime().Unix() * int64(time.Second)
			manifestEntry.SHA256 = digest
			summary.FileCount++
			summary.TotalBytes += openedInfo.Size()
			if summary.TotalBytes > maximumManifestBytes {
				return errors.New("file manifest exceeded the 500 GiB safety limit")
			}
		default:
			return errors.New("devices, sockets, pipes, and special files are unsupported")
		}
		summary.Manifest.Entries = append(summary.Manifest.Entries, manifestEntry)
		if progress != nil && len(summary.Manifest.Entries)%1000 == 0 {
			return progress(int64(len(summary.Manifest.Entries)))
		}
		return nil
	})
	if err != nil {
		return FileManifestSummary{}, err
	}
	sort.Slice(summary.Manifest.Entries, func(i, j int) bool {
		return summary.Manifest.Entries[i].Relative < summary.Manifest.Entries[j].Relative
	})
	summary.Digest, err = Digest(summary.Manifest)
	if err != nil {
		return FileManifestSummary{}, err
	}
	return summary, nil
}

type fileTransferCheckpoint struct {
	SchemaVersion  string                       `json:"schema_version"`
	ManifestDigest string                       `json:"manifest_digest"`
	Chunks         map[string]map[string]string `json:"chunks"`
}

type fileSyncMarker struct {
	SchemaVersion    string `json:"schema_version"`
	MigrationID      string `json:"migration_id"`
	TargetRootHandle string `json:"target_root_handle"`
	TargetRelative   string `json:"target_relative_handle"`
	State            string `json:"state"`
	ActiveDigest     string `json:"active_digest,omitempty"`
	PendingDigest    string `json:"pending_digest,omitempty"`
	ApplyName        string `json:"apply_name,omitempty"`
	BackupName       string `json:"backup_name,omitempty"`
	UpdatedAt        string `json:"updated_at"`
}

func validateTransferredManifest(manifest FileManifest, expectedDigest string, maximumBytes int64) (FileManifestSummary, error) {
	if manifest.SchemaVersion != fileManifestSchema || len(manifest.Entries) > maximumManifestEntries {
		return FileManifestSummary{}, errors.New("direct file manifest contract is invalid")
	}
	summary := FileManifestSummary{Manifest: manifest}
	previous := ""
	pathTypes := map[string]string{}
	for _, entry := range manifest.Entries {
		if entry.Relative == "" || entry.Relative <= previous || strings.Contains(entry.Relative, `\`) || entry.Mode > 0o777 || entry.ModifiedUnixNano < 0 {
			return FileManifestSummary{}, errors.New("direct file manifest ordering or metadata is invalid")
		}
		clean, err := cleanRelative(filepath.FromSlash(entry.Relative))
		if err != nil || clean == "." || filepath.ToSlash(clean) != entry.Relative {
			return FileManifestSummary{}, errors.New("direct file manifest path is unsafe")
		}
		for parent := filepath.Dir(clean); parent != "."; parent = filepath.Dir(parent) {
			if pathTypes[filepath.ToSlash(parent)] == "file" {
				return FileManifestSummary{}, errors.New("direct file manifest places an entry below a file")
			}
		}
		switch entry.Type {
		case "directory":
			if entry.SizeBytes != 0 || entry.SHA256 != "" {
				return FileManifestSummary{}, errors.New("direct directory manifest entry is invalid")
			}
			summary.DirectoryCount++
		case "file":
			if entry.SizeBytes < 0 || !fileDigestPattern.MatchString(entry.SHA256) {
				return FileManifestSummary{}, errors.New("direct file manifest digest is invalid")
			}
			summary.FileCount++
			summary.TotalBytes += entry.SizeBytes
			if summary.TotalBytes > maximumBytes || summary.TotalBytes > maximumManifestBytes {
				return FileManifestSummary{}, errors.New("direct file manifest exceeds the signed byte limit")
			}
		default:
			return FileManifestSummary{}, errors.New("direct file manifest contains an unsupported entry type")
		}
		pathTypes[entry.Relative] = entry.Type
		previous = entry.Relative
	}
	digest, err := Digest(manifest)
	if err != nil || digest != expectedDigest {
		return FileManifestSummary{}, errors.New("direct file manifest digest mismatch")
	}
	summary.Digest = digest
	return summary, nil
}

func safeManifestJoin(root, relative string) (string, error) {
	clean, err := cleanRelative(filepath.FromSlash(relative))
	if err != nil || clean == "." || filepath.ToSlash(clean) != relative {
		return "", errors.New("file manifest path is unsafe")
	}
	target := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("file manifest path escaped its staging root")
	}
	return target, nil
}

func atomicJSONFile(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".state-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func loadJSONFile(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	return nil
}

func (e *NativeExecutor) fileSyncMarkerPath(handle, relative string) string {
	digest := sha256.Sum256([]byte(handle + "\x00" + relative))
	return filepath.Join(e.stateDir, "file-sync-markers", hex.EncodeToString(digest[:16])+".json")
}

func (e *NativeExecutor) transferCachePath(task TaskEnvelope, manifestDigest string) string {
	digest := sha256.Sum256([]byte(task.MigrationID + "\x00" + manifestDigest))
	return filepath.Join(e.stateDir, "transfer-cache", hex.EncodeToString(digest[:16]))
}

func (e *NativeExecutor) removeTransferCache(cacheRoot string) error {
	parent := filepath.Join(e.stateDir, "transfer-cache")
	base := filepath.Base(cacheRoot)
	if filepath.Dir(cacheRoot) != parent || len(base) != 32 {
		return errors.New("transfer cache cleanup scope is invalid")
	}
	if _, err := hex.DecodeString(base); err != nil {
		return errors.New("transfer cache cleanup scope is invalid")
	}
	if err := os.RemoveAll(cacheRoot); err != nil {
		return errors.New("transfer cache cleanup failed")
	}
	return nil
}

func saturatedFileSystemBytes(blocks, blockSize uint64) int64 {
	if blocks == 0 || blockSize == 0 {
		return 0
	}
	if blocks > uint64(maximumSignedInt64)/blockSize {
		return maximumSignedInt64
	}
	return int64(blocks * blockSize)
}

func capacityReserve(totalBytes int64) int64 {
	reserve := (totalBytes/100)*fileSyncReservePercent + ((totalBytes%100)*fileSyncReservePercent)/100
	if reserve < fileSyncReserveBytes {
		return fileSyncReserveBytes
	}
	return reserve
}

func hasFileSystemCapacity(availableBytes, totalBytes, requiredBytes int64) bool {
	if availableBytes < 0 || totalBytes <= 0 || requiredBytes < 0 {
		return false
	}
	reserve := capacityReserve(totalBytes)
	if requiredBytes > maximumSignedInt64-reserve {
		return false
	}
	return availableBytes >= requiredBytes+reserve
}

func ensureFileSystemCapacity(path string, requiredBytes int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return errMigrationDiskCapacity
	}
	totalBytes := saturatedFileSystemBytes(uint64(stat.Blocks), uint64(stat.Bsize))
	availableBytes := saturatedFileSystemBytes(uint64(stat.Bavail), uint64(stat.Bsize))
	if !hasFileSystemCapacity(availableBytes, totalBytes, requiredBytes) {
		return errMigrationDiskCapacity
	}
	return nil
}

func allocatedTransferCacheBytes(root string) (int64, error) {
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("transfer cache state is unsafe")
	}
	var allocated int64
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("transfer cache contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, statErr := os.Lstat(path)
		if statErr != nil || !fileInfo.Mode().IsRegular() {
			return errors.New("transfer cache contains an unsupported entry")
		}
		stat, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Blocks < 0 {
			return errors.New("transfer cache allocation metadata is unavailable")
		}
		entryBytes := saturatedFileSystemBytes(uint64(stat.Blocks), 512)
		if allocated > maximumSignedInt64-entryBytes {
			allocated = maximumSignedInt64
		} else {
			allocated += entryBytes
		}
		return nil
	})
	return allocated, err
}

func parseDataPlaneTicketInput(inputs map[string]any) (DataPlaneTicket, error) {
	raw, ok := inputs["transfer_ticket"]
	if !ok || raw == nil {
		return DataPlaneTicket{}, errors.New("signed direct-transfer ticket is required")
	}
	data, err := CanonicalJSON(raw)
	if err != nil || len(data) > 32*1024 {
		return DataPlaneTicket{}, errors.New("signed direct-transfer ticket is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var ticket DataPlaneTicket
	if err := decoder.Decode(&ticket); err != nil {
		return DataPlaneTicket{}, errors.New("signed direct-transfer ticket is invalid")
	}
	return ticket, nil
}

func (e *NativeExecutor) validateTargetTicket(task TaskEnvelope, bindingID string, ticket DataPlaneTicket, inputs map[string]any) error {
	if e.identity == nil || e.agentID == "" || e.backendKeyID == "" || len(e.backendPublic) != ed25519.PublicKeySize {
		return errors.New("direct-transfer agent identity is unavailable")
	}
	if err := validateDataPlaneTicket(ticket, e.backendKeyID, e.backendPublic); err != nil {
		return err
	}
	sourceRootHandle, err := stringInput(inputs, "source_root_handle")
	if err != nil {
		return err
	}
	sourceRelative := "."
	if value, ok := inputs["source_relative_handle"].(string); ok && value != "" {
		sourceRelative = value
	}
	expectedManifest, err := stringInput(inputs, "manifest_digest")
	if err != nil {
		return err
	}
	maximumBytes, err := boundedIntegerInput(inputs, "maximum_bytes", 0, maximumManifestBytes)
	if err != nil {
		return err
	}
	if ticket.MigrationID != task.MigrationID || ticket.AttemptID != task.AttemptID || ticket.FencingToken != task.FencingToken ||
		ticket.BindingID != bindingID || ticket.TargetAgentID != e.agentID || ticket.TargetSigningKeyID != e.identity.SigningKeyID ||
		ticket.SourceRootHandle != sourceRootHandle || ticket.SourceRelativeHandle != sourceRelative || ticket.ManifestDigest != expectedManifest ||
		ticket.MaximumBytes != maximumBytes {
		return errors.New("direct-transfer ticket does not match the signed task")
	}
	targetPublic, err := parseEd25519PublicKey(ticket.TargetSigningPublicPEM)
	localPublic, localErr := parseEd25519PublicKey(e.identity.SigningPublicKeyPEM)
	if err != nil || localErr != nil || !bytes.Equal(targetPublic, localPublic) {
		return errors.New("direct-transfer target key does not match the enrolled identity")
	}
	return nil
}

func loadTransferCheckpoint(path, manifestDigest string) fileTransferCheckpoint {
	checkpoint := fileTransferCheckpoint{SchemaVersion: "operations.migration.file-transfer-checkpoint.v1", ManifestDigest: manifestDigest, Chunks: map[string]map[string]string{}}
	var stored fileTransferCheckpoint
	if loadJSONFile(path, &stored) == nil && stored.SchemaVersion == checkpoint.SchemaVersion && stored.ManifestDigest == manifestDigest && stored.Chunks != nil {
		return stored
	}
	return checkpoint
}

func hashFileRegion(file *os.File, offset, length int64) (string, error) {
	section := io.NewSectionReader(file, offset, length)
	hash := sha256.New()
	if _, err := io.Copy(hash, section); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func waitForTransferRate(ctx context.Context, started time.Time, bytesDownloaded, bytesPerSecond int64) error {
	if bytesDownloaded <= 0 || bytesPerSecond <= 0 {
		return nil
	}
	expected := time.Duration(float64(bytesDownloaded) / float64(bytesPerSecond) * float64(time.Second))
	remaining := expected - time.Since(started)
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (e *NativeExecutor) downloadManifestTree(ctx context.Context, task TaskEnvelope, client *dataPlaneClient, summary FileManifestSummary, bytesPerSecond int64, progress func(string, int64, *int64) error) (string, error) {
	cacheRoot := e.transferCachePath(task, summary.Digest)
	treeRoot := filepath.Join(cacheRoot, "tree")
	checkpointPath := filepath.Join(cacheRoot, "checkpoint.json")
	if err := os.MkdirAll(treeRoot, 0o700); err != nil {
		return "", err
	}
	checkpoint := loadTransferCheckpoint(checkpointPath, summary.Digest)
	started := time.Now()
	lastProgress := time.Time{}
	var completedBytes, downloadedBytes int64
	totalBytes := summary.TotalBytes
	for _, entry := range summary.Manifest.Entries {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		path, err := safeManifestJoin(treeRoot, entry.Relative)
		if err != nil {
			return "", err
		}
		if entry.Type == "directory" {
			if info, err := os.Lstat(path); err == nil && !info.IsDir() {
				return "", errors.New("transfer cache directory collision")
			}
			if err := os.MkdirAll(path, os.FileMode(entry.Mode)); err != nil {
				return "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return "", err
		}
		if digest, size, err := fileSHA256(path); err == nil && digest == entry.SHA256 && size == entry.SizeBytes {
			completedBytes += size
			if lastProgress.IsZero() || time.Since(lastProgress) >= 5*time.Second || completedBytes == totalBytes {
				if err := progress("file_transfer_resume", completedBytes, &totalBytes); err != nil {
					return "", err
				}
				lastProgress = time.Now()
			}
			continue
		}
		partialPath := path + ".partial"
		partial, err := os.OpenFile(partialPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return "", err
		}
		if err := partial.Truncate(entry.SizeBytes); err != nil {
			partial.Close()
			return "", err
		}
		chunks := checkpoint.Chunks[entry.Relative]
		if chunks == nil {
			chunks = map[string]string{}
			checkpoint.Chunks[entry.Relative] = chunks
		}
		chunkCount := (entry.SizeBytes + transferChunkSize - 1) / transferChunkSize
		for chunkIndex := int64(0); chunkIndex < chunkCount; chunkIndex++ {
			offset := chunkIndex * transferChunkSize
			length := transferChunkSize
			if entry.SizeBytes-offset < length {
				length = entry.SizeBytes - offset
			}
			key := strconv.FormatInt(chunkIndex, 10)
			if expected := chunks[key]; expected != "" {
				actual, hashErr := hashFileRegion(partial, offset, length)
				if hashErr == nil && actual == expected {
					completedBytes += length
					continue
				}
				delete(chunks, key)
			}
			data, chunkDigest, err := client.chunk(ctx, entry.Relative, chunkIndex, entry.SHA256)
			if err != nil || int64(len(data)) != length {
				zeroBytes(data)
				partial.Close()
				return "", errors.New("direct file chunk transfer failed")
			}
			if _, err := partial.WriteAt(data, offset); err != nil {
				zeroBytes(data)
				partial.Close()
				return "", err
			}
			zeroBytes(data)
			if err := partial.Sync(); err != nil {
				partial.Close()
				return "", err
			}
			chunks[key] = chunkDigest
			if err := atomicJSONFile(checkpointPath, checkpoint); err != nil {
				partial.Close()
				return "", err
			}
			completedBytes += length
			downloadedBytes += length
			if lastProgress.IsZero() || time.Since(lastProgress) >= 5*time.Second || completedBytes == totalBytes {
				if err := progress("file_transfer", completedBytes, &totalBytes); err != nil {
					partial.Close()
					return "", err
				}
				lastProgress = time.Now()
			}
			if err := waitForTransferRate(ctx, started, downloadedBytes, bytesPerSecond); err != nil {
				partial.Close()
				return "", err
			}
		}
		if err := partial.Close(); err != nil {
			return "", err
		}
		digest, size, err := fileSHA256(partialPath)
		if err != nil || digest != entry.SHA256 || size != entry.SizeBytes {
			return "", errors.New("assembled file digest verification failed")
		}
		if err := os.Chmod(partialPath, os.FileMode(entry.Mode)); err != nil {
			return "", err
		}
		modified := time.Unix(0, entry.ModifiedUnixNano)
		if err := os.Chtimes(partialPath, modified, modified); err != nil {
			return "", err
		}
		if err := os.Rename(partialPath, path); err != nil {
			return "", err
		}
	}
	for index := len(summary.Manifest.Entries) - 1; index >= 0; index-- {
		entry := summary.Manifest.Entries[index]
		if entry.Type != "directory" {
			continue
		}
		path, _ := safeManifestJoin(treeRoot, entry.Relative)
		if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
			return "", err
		}
		modified := time.Unix(0, entry.ModifiedUnixNano)
		if err := os.Chtimes(path, modified, modified); err != nil {
			return "", err
		}
	}
	verified, err := buildFileManifest(ctx, treeRoot, nil)
	if err != nil || verified.Digest != summary.Digest {
		return "", errors.New("downloaded file tree manifest verification failed")
	}
	return treeRoot, nil
}

func copyManifestTree(source, target string, manifest FileManifest) error {
	if err := os.Mkdir(target, 0o700); err != nil {
		return err
	}
	for _, entry := range manifest.Entries {
		sourcePath, err := safeManifestJoin(source, entry.Relative)
		if err != nil {
			return err
		}
		targetPath, err := safeManifestJoin(target, entry.Relative)
		if err != nil {
			return err
		}
		if entry.Type == "directory" {
			if err := os.MkdirAll(targetPath, os.FileMode(entry.Mode)); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
			return err
		}
		input, info, err := openRegularNoFollow(sourcePath)
		if err != nil || info.Size() != entry.SizeBytes {
			if input != nil {
				input.Close()
			}
			return errors.New("transfer cache file changed before apply")
		}
		output, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		syncErr := output.Sync()
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		if copyErr != nil || syncErr != nil || closeOutputErr != nil || closeInputErr != nil {
			return errors.New("file tree apply copy failed")
		}
		if err := os.Chmod(targetPath, os.FileMode(entry.Mode)); err != nil {
			return err
		}
		modified := time.Unix(0, entry.ModifiedUnixNano)
		if err := os.Chtimes(targetPath, modified, modified); err != nil {
			return err
		}
	}
	for index := len(manifest.Entries) - 1; index >= 0; index-- {
		entry := manifest.Entries[index]
		if entry.Type != "directory" {
			continue
		}
		path, _ := safeManifestJoin(target, entry.Relative)
		if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
			return err
		}
		modified := time.Unix(0, entry.ModifiedUnixNano)
		if err := os.Chtimes(path, modified, modified); err != nil {
			return err
		}
	}
	return nil
}

func safeRemoveSwapPath(parent, path, prefix string) error {
	if filepath.Dir(path) != parent || !strings.HasPrefix(filepath.Base(path), prefix) {
		return errors.New("file sync swap path is unsafe")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("file sync swap path is not a safe directory")
	}
	return os.RemoveAll(path)
}

func (e *NativeExecutor) recoverFileSwap(ctx context.Context, markerPath, target, parent string, marker fileSyncMarker) (fileSyncMarker, error) {
	if marker.State != "swapping" {
		return marker, nil
	}
	applyPath := filepath.Join(parent, marker.ApplyName)
	backupPath := filepath.Join(parent, marker.BackupName)
	if info, err := os.Lstat(target); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		current, manifestErr := buildFileManifest(ctx, target, nil)
		if manifestErr == nil && current.Digest == marker.PendingDigest {
			if err := safeRemoveSwapPath(parent, backupPath, ".askio-backup-"); err != nil {
				return marker, err
			}
			_ = safeRemoveSwapPath(parent, applyPath, ".askio-apply-")
			marker.State = "active"
			marker.ActiveDigest = marker.PendingDigest
			marker.PendingDigest, marker.ApplyName, marker.BackupName = "", "", ""
			marker.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			return marker, atomicJSONFile(markerPath, marker)
		}
		if marker.ActiveDigest != "" && manifestErr == nil && current.Digest == marker.ActiveDigest {
			_ = safeRemoveSwapPath(parent, applyPath, ".askio-apply-")
			_ = safeRemoveSwapPath(parent, backupPath, ".askio-backup-")
			marker.State = "active"
			marker.PendingDigest, marker.ApplyName, marker.BackupName = "", "", ""
			return marker, atomicJSONFile(markerPath, marker)
		}
		return marker, errors.New("file sync target changed during swap recovery")
	} else if !os.IsNotExist(err) {
		return marker, errors.New("file sync target swap state is unsafe")
	}
	if info, err := os.Lstat(applyPath); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		if err := os.Rename(applyPath, target); err != nil {
			return marker, err
		}
		return e.recoverFileSwap(ctx, markerPath, target, parent, marker)
	}
	if info, err := os.Lstat(backupPath); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
		if err := os.Rename(backupPath, target); err != nil {
			return marker, err
		}
		marker.State = "active"
		marker.PendingDigest, marker.ApplyName, marker.BackupName = "", "", ""
		return marker, atomicJSONFile(markerPath, marker)
	}
	return marker, errors.New("file sync swap recovery has no valid target, apply tree, or backup")
}

func (e *NativeExecutor) applyFileTree(ctx context.Context, task TaskEnvelope, targetHandle, targetRelative, downloadedRoot string, summary FileManifestSummary) (bool, error) {
	target, err := e.resolver.Resolve(targetHandle, targetRelative, true)
	if err != nil {
		return false, err
	}
	parent := filepath.Dir(target)
	if target == parent || !fileNamePattern.MatchString(filepath.Base(target)) {
		return false, errors.New("file sync target must be one fixed leaf below a configured root")
	}
	markerPath := e.fileSyncMarkerPath(targetHandle, targetRelative)
	marker := fileSyncMarker{}
	markerErr := loadJSONFile(markerPath, &marker)
	if markerErr == nil {
		if marker.SchemaVersion != "operations.migration.file-sync-marker.v1" || marker.MigrationID != task.MigrationID || marker.TargetRootHandle != targetHandle || marker.TargetRelative != targetRelative {
			return false, errors.New("file sync target ownership marker belongs to another scope")
		}
		marker, err = e.recoverFileSwap(ctx, markerPath, target, parent, marker)
		if err != nil {
			return false, err
		}
	} else if !os.IsNotExist(markerErr) {
		return false, errors.New("file sync target ownership marker is unreadable")
	}
	targetExists := false
	currentTargetDigest := ""
	if info, statErr := os.Lstat(target); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("file sync target collides with a non-directory")
		}
		targetExists = true
		current, manifestErr := buildFileManifest(ctx, target, nil)
		if manifestErr != nil {
			return false, manifestErr
		}
		currentTargetDigest = current.Digest
		if markerErr != nil {
			if len(current.Manifest.Entries) != 0 {
				return false, errors.New("initial file sync requires a new or empty target directory")
			}
		} else if current.Digest != marker.ActiveDigest {
			return false, errors.New("file sync target changed outside the migration lineage")
		}
		if markerErr == nil && marker.ActiveDigest == summary.Digest && current.Digest == summary.Digest {
			return true, nil
		}
	} else if !os.IsNotExist(statErr) {
		return false, statErr
	} else if markerErr == nil && marker.ActiveDigest != "" {
		return false, errors.New("file sync target disappeared after ownership was established")
	}
	if err := e.ensureCapacity(parent, summary.TotalBytes); err != nil {
		return false, err
	}
	tokenMaterial := sha256.Sum256([]byte(task.MigrationID + summary.Digest))
	token := hex.EncodeToString(tokenMaterial[:8])
	applyName := ".askio-apply-" + token
	backupName := ".askio-backup-" + token
	applyPath := filepath.Join(parent, applyName)
	backupPath := filepath.Join(parent, backupName)
	if _, err := os.Lstat(applyPath); err == nil {
		return false, errors.New("file sync apply directory collision")
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if _, err := os.Lstat(backupPath); err == nil {
		return false, errors.New("file sync backup directory collision")
	} else if !os.IsNotExist(err) {
		return false, err
	}
	if err := copyManifestTree(downloadedRoot, applyPath, summary.Manifest); err != nil {
		_ = safeRemoveSwapPath(parent, applyPath, ".askio-apply-")
		return false, err
	}
	verified, err := buildFileManifest(ctx, applyPath, nil)
	if err != nil || verified.Digest != summary.Digest {
		_ = safeRemoveSwapPath(parent, applyPath, ".askio-apply-")
		return false, errors.New("file sync apply tree failed manifest verification")
	}
	activeDigest := ""
	if markerErr == nil {
		activeDigest = marker.ActiveDigest
	} else if targetExists {
		activeDigest = currentTargetDigest
	}
	marker = fileSyncMarker{
		SchemaVersion: "operations.migration.file-sync-marker.v1", MigrationID: task.MigrationID,
		TargetRootHandle: targetHandle, TargetRelative: targetRelative, State: "swapping",
		ActiveDigest: activeDigest, PendingDigest: summary.Digest, ApplyName: applyName, BackupName: backupName,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := atomicJSONFile(markerPath, marker); err != nil {
		_ = safeRemoveSwapPath(parent, applyPath, ".askio-apply-")
		return false, err
	}
	if targetExists {
		if err := os.Rename(target, backupPath); err != nil {
			return false, err
		}
	}
	if err := os.Rename(applyPath, target); err != nil {
		if targetExists {
			_ = os.Rename(backupPath, target)
		}
		return false, err
	}
	marker.State = "active"
	marker.ActiveDigest = summary.Digest
	marker.PendingDigest, marker.ApplyName, marker.BackupName = "", "", ""
	marker.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := atomicJSONFile(markerPath, marker); err != nil {
		return false, err
	}
	if targetExists {
		if err := safeRemoveSwapPath(parent, backupPath, ".askio-backup-"); err != nil {
			return false, err
		}
	}
	return false, nil
}

func (e *NativeExecutor) filesSync(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, err := stringInput(inputs, "transfer_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(bindingID) {
		return nil, errors.New("transfer binding identifier is invalid")
	}
	raw, err := e.resolveBinding(ctx, task, bindingID)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(raw)
	binding, err := parseTransferBinding(raw)
	if err != nil {
		return nil, err
	}
	ticket, err := parseDataPlaneTicketInput(inputs)
	if err != nil {
		return nil, err
	}
	if err := e.validateTargetTicket(task, bindingID, ticket, inputs); err != nil {
		return nil, err
	}
	var refresh []func(context.Context, DataPlaneTicket) (DataPlaneTicket, error)
	if e.tickets != nil {
		refresh = append(refresh, func(refreshContext context.Context, _ DataPlaneTicket) (DataPlaneTicket, error) {
			refreshed, refreshErr := e.tickets(refreshContext, task)
			if refreshErr != nil {
				return DataPlaneTicket{}, refreshErr
			}
			if validationErr := e.validateTargetTicket(task, bindingID, refreshed, inputs); validationErr != nil {
				return DataPlaneTicket{}, validationErr
			}
			return refreshed, nil
		})
	}
	client, err := newDataPlaneClient(binding.SourceAddress, e.identity, ticket, refresh...)
	if err != nil {
		return nil, err
	}
	manifest, err := client.manifest(ctx)
	if err != nil {
		return nil, errors.New("direct source manifest transfer failed")
	}
	summary, err := validateTransferredManifest(manifest, ticket.ManifestDigest, ticket.MaximumBytes)
	if err != nil {
		return nil, err
	}
	transferMiB, err := boundedIntegerInput(inputs, "transfer_mib_per_second", 1, 1024)
	if err != nil {
		return nil, err
	}
	cacheRoot := e.transferCachePath(task, summary.Digest)
	allocatedCacheBytes, err := allocatedTransferCacheBytes(cacheRoot)
	if err != nil {
		return nil, err
	}
	if allocatedCacheBytes > summary.TotalBytes {
		allocatedCacheBytes = summary.TotalBytes
	}
	if err := e.ensureCapacity(e.stateDir, summary.TotalBytes-allocatedCacheBytes); err != nil {
		return nil, err
	}
	downloadedRoot, err := e.downloadManifestTree(ctx, task, client, summary, transferMiB*1024*1024, progress)
	if err != nil {
		return nil, err
	}
	targetHandle, err := stringInput(inputs, "target_root_handle")
	if err != nil {
		return nil, err
	}
	targetRelative, err := stringInput(inputs, "target_relative_handle")
	if err != nil || strings.Contains(targetRelative, "/") || !fileNamePattern.MatchString(targetRelative) {
		return nil, errors.New("file sync target relative handle is invalid")
	}
	resumed, err := e.applyFileTree(ctx, task, targetHandle, targetRelative, downloadedRoot, summary)
	if err != nil {
		return nil, err
	}
	if err := e.removeTransferCache(cacheRoot); err != nil {
		return nil, err
	}
	return map[string]any{
		"manifest_digest": summary.Digest, "file_count": summary.FileCount, "directory_count": summary.DirectoryCount,
		"total_bytes": summary.TotalBytes, "chunk_size_bytes": transferChunkSize, "resumed": resumed,
		"target_relative_handle": targetRelative, "transport": "migration.direct.mtls-chunks.v1", "transfer_cache_removed": true,
	}, nil
}
