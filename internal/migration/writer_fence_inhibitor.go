package migration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	defaultServiceFenceMarkerRoot = "/var/lib/askio-migration-broker/service-fences"
	defaultServiceUnitRoot        = "/etc/systemd/system"
)

func (b *Broker) serviceFenceMarkerRoot() string {
	if b.config.ServiceFenceMarkerRoot != "" {
		return b.config.ServiceFenceMarkerRoot
	}
	return defaultServiceFenceMarkerRoot
}

func (b *Broker) serviceUnitRoot() string {
	if b.config.ServiceUnitRoot != "" {
		return b.config.ServiceUnitRoot
	}
	return defaultServiceUnitRoot
}

func (b *Broker) serviceFenceMarker(service string) string {
	return filepath.Join(b.serviceFenceMarkerRoot(), service+".fenced")
}

func (b *Broker) expectedServiceFenceMarkers() (map[string]struct{}, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	expected := map[string]struct{}{}
	for _, fence := range b.state.WriterFences {
		if !fence.Active && fence.Phase != writerFenceReleaseAuthorized {
			continue
		}
		for _, service := range fence.Services {
			if !serviceNamePattern.MatchString(service) {
				return nil, errors.New("writer-fence state contains an invalid service handle")
			}
			if _, allowed := b.allowedServices[service]; !allowed {
				return nil, errors.New("writer-fence state contains an unconfigured service handle")
			}
			expected[service] = struct{}{}
		}
	}
	return expected, nil
}

// validateServiceFenceMarkers makes a marker without matching durable broker
// ownership a startup and attestation failure. In particular, a crash after
// marker creation but before intent persistence must never be reported as an
// empty writer-fence set.
func (b *Broker) validateServiceFenceMarkers() error {
	expected, err := b.expectedServiceFenceMarkers()
	if err != nil {
		return err
	}
	root := b.serviceFenceMarkerRoot()
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("writer-fence inhibitor directory is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("writer-fence inhibitor directory has the wrong owner")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".fenced") {
			return errors.New("writer-fence inhibitor directory contains an unknown entry")
		}
		service := strings.TrimSuffix(name, ".fenced")
		if !serviceNamePattern.MatchString(service) {
			return errors.New("writer-fence inhibitor marker has an invalid service handle")
		}
		if _, allowed := b.allowedServices[service]; !allowed {
			return errors.New("writer-fence inhibitor marker is not preconfigured")
		}
		markerInfo, statErr := os.Lstat(filepath.Join(root, name))
		if statErr != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 || markerInfo.Mode().Perm() != 0o600 {
			return errors.New("writer-fence inhibitor marker is unsafe")
		}
		markerStat, statOK := markerInfo.Sys().(*syscall.Stat_t)
		if !statOK || markerStat.Uid != uint32(os.Geteuid()) {
			return errors.New("writer-fence inhibitor marker has the wrong owner")
		}
		data, readErr := os.ReadFile(filepath.Join(root, name))
		if readErr != nil || string(data) != "fenced\n" {
			return errors.New("writer-fence inhibitor marker content is invalid")
		}
		if err := b.verifyServiceFenceDropIn(service); err != nil {
			return err
		}
		if _, owned := expected[service]; !owned {
			return errors.New("orphan writer-fence inhibitor requires reviewed recovery")
		}
	}
	return nil
}

func (b *Broker) expectedServiceFenceDropIn(service string) string {
	return "[Unit]\nRequires=askio-migration-broker.service\nAfter=askio-migration-broker.service\nConditionPathExists=!" + b.serviceFenceMarker(service) + "\n"
}

func (b *Broker) verifyServiceFenceDropIn(service string) error {
	path := filepath.Join(b.serviceUnitRoot(), service+".d", "90-askio-migration-fence.conf")
	data, err := os.ReadFile(path)
	if err != nil || string(data) != b.expectedServiceFenceDropIn(service) {
		return fmt.Errorf("persistent writer-fence inhibitor is missing for %s", service)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("persistent writer-fence inhibitor is unsafe for %s", service)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("persistent writer-fence inhibitor has the wrong owner for %s", service)
	}
	return nil
}

func (b *Broker) activateServiceFenceInhibitors(services []string) error {
	for _, service := range services {
		if err := b.verifyServiceFenceDropIn(service); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(b.serviceFenceMarkerRoot(), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(b.serviceFenceMarkerRoot(), 0o700); err != nil {
		return err
	}
	if err := requireOwnedDirectory(b.serviceFenceMarkerRoot(), 0o700); err != nil {
		return err
	}
	for _, service := range services {
		path := b.serviceFenceMarker(service)
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
				return errors.New("writer-fence inhibitor marker is unsafe")
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != uint32(os.Geteuid()) {
				return errors.New("writer-fence inhibitor marker has the wrong owner")
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(path, []byte("fenced\n"), 0o600); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
	}
	directory, err := os.Open(b.serviceFenceMarkerRoot())
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (b *Broker) releaseServiceFenceInhibitors(services []string) error {
	for _, service := range services {
		if err := b.verifyServiceFenceDropIn(service); err != nil {
			return err
		}
		if err := os.Remove(b.serviceFenceMarker(service)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if directory, err := os.Open(b.serviceFenceMarkerRoot()); err == nil {
		defer directory.Close()
		return directory.Sync()
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func intersectsServices(left, right []string) bool {
	for _, leftService := range left {
		for _, rightService := range right {
			if strings.EqualFold(leftService, rightService) {
				return true
			}
		}
	}
	return false
}
