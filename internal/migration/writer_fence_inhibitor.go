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
