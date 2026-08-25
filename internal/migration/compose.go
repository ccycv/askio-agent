package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const composePolicySchema = "operations.migration.compose-policy.v2"

const composeRuntimeSecretsBindingSchema = "operations.migration.compose-runtime-secrets.v1"

const composeRuntimeSecretsRoot = "/run/askio-monitor/migration-secrets"

var (
	composeNamePattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}$`)
	composeProjectPattern        = regexp.MustCompile(`^askio_mig_[a-z0-9][a-z0-9_-]{1,31}$`)
	composeImagePattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{1,255}@sha256:[a-f0-9]{64}$`)
	composeDurationPattern       = regexp.MustCompile(`^[1-9][0-9]{0,2}s$`)
	composeEnvironmentKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	composeRuntimeSecretPattern  = regexp.MustCompile(`^/run/askio-monitor/migration-secrets/askio_mig_[a-z0-9][a-z0-9_-]{1,31}/[a-z0-9][a-z0-9_-]{1,62}$`)
)

type composeDependsOn struct {
	Condition string `yaml:"condition,omitempty"`
	Restart   bool   `yaml:"restart,omitempty"`
	Required  *bool  `yaml:"required,omitempty"`
}

type composeLogging struct {
	Driver  string            `yaml:"driver,omitempty"`
	Options map[string]string `yaml:"options,omitempty"`
}

type composeService struct {
	Image           string                           `yaml:"image"`
	User            string                           `yaml:"user"`
	ReadOnly        bool                             `yaml:"read_only"`
	Init            bool                             `yaml:"init"`
	Restart         string                           `yaml:"restart,omitempty"`
	Environment     map[string]string                `yaml:"environment,omitempty"`
	DependsOn       map[string]composeDependsOn      `yaml:"depends_on,omitempty"`
	Volumes         []string                         `yaml:"volumes,omitempty"`
	Ports           []string                         `yaml:"ports,omitempty"`
	Networks        map[string]composeServiceNetwork `yaml:"networks,omitempty"`
	Secrets         []string                         `yaml:"secrets,omitempty"`
	Tmpfs           []string                         `yaml:"tmpfs,omitempty"`
	CapDrop         []string                         `yaml:"cap_drop"`
	SecurityOpt     []string                         `yaml:"security_opt"`
	CPUs            string                           `yaml:"cpus"`
	MemoryLimit     string                           `yaml:"mem_limit"`
	PidsLimit       int                              `yaml:"pids_limit"`
	StopGracePeriod string                           `yaml:"stop_grace_period,omitempty"`
	Logging         *composeLogging                  `yaml:"logging,omitempty"`
}

type composeServiceNetwork struct {
	IPv4Address string `yaml:"ipv4_address"`
}

type composeIPAMConfig struct {
	Subnet  string `yaml:"subnet"`
	Gateway string `yaml:"gateway"`
}

type composeIPAM struct {
	Config []composeIPAMConfig `yaml:"config"`
}

type composeNetwork struct {
	Driver   string       `yaml:"driver,omitempty"`
	Internal bool         `yaml:"internal"`
	IPAM     *composeIPAM `yaml:"ipam"`
}

type composeVolume struct {
	Driver string `yaml:"driver,omitempty"`
}

type composeSecret struct {
	File string `yaml:"file"`
}

type composeDocument struct {
	Version  string                    `yaml:"version,omitempty"`
	Services map[string]composeService `yaml:"services"`
	Networks map[string]composeNetwork `yaml:"networks"`
	Volumes  map[string]composeVolume  `yaml:"volumes,omitempty"`
	Secrets  map[string]composeSecret  `yaml:"secrets,omitempty"`
}

type composePolicyResult struct {
	Document       composeDocument
	CanonicalYAML  []byte
	Digest         string
	PublishedPorts []int
	NamedVolumes   []string
	NetworkNames   []string
	BindMountRoots []string
	SecretFiles    map[string]string
}

type composeRuntimeSecretsBinding struct {
	SchemaVersion string            `json:"schema_version"`
	Secrets       map[string]string `json:"secrets"`
}

func (binding *composeRuntimeSecretsBinding) clear() {
	for name := range binding.Secrets {
		binding.Secrets[name] = ""
	}
}

func parseComposeRuntimeSecretsBinding(raw []byte) (composeRuntimeSecretsBinding, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var binding composeRuntimeSecretsBinding
	if err := decoder.Decode(&binding); err != nil {
		return composeRuntimeSecretsBinding{}, errors.New("Compose runtime secret binding is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return composeRuntimeSecretsBinding{}, errors.New("Compose runtime secret binding contains trailing data")
	}
	if binding.SchemaVersion != composeRuntimeSecretsBindingSchema || len(binding.Secrets) == 0 || len(binding.Secrets) > 32 {
		return composeRuntimeSecretsBinding{}, errors.New("Compose runtime secret binding contract is unsupported")
	}
	total := 0
	for name, value := range binding.Secrets {
		if !composeNamePattern.MatchString(name) || len(value) == 0 || len(value) > 16*1024 || strings.ContainsRune(value, '\x00') {
			binding.clear()
			return composeRuntimeSecretsBinding{}, errors.New("Compose runtime secret value is invalid")
		}
		total += len(value)
	}
	if total > 64*1024 {
		binding.clear()
		return composeRuntimeSecretsBinding{}, errors.New("Compose runtime secret binding exceeds its limit")
	}
	return binding, nil
}

func rejectYAMLAliases(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("Compose aliases and anchors are not supported")
	}
	if node.Tag != "" && !strings.HasPrefix(node.Tag, "!!") {
		return errors.New("Compose custom YAML tags are not supported")
	}
	for _, child := range node.Content {
		if err := rejectYAMLAliases(child); err != nil {
			return err
		}
	}
	return nil
}

func parseCPU(value string) (float64, error) {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0.05 || parsed > 16 {
		return 0, errors.New("Compose service CPU limit must be between 0.05 and 16")
	}
	return parsed, nil
}

func parseMemoryMiB(value string) (int64, error) {
	lower := strings.ToLower(strings.TrimSpace(value))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(lower, "m"):
		lower = strings.TrimSuffix(lower, "m")
	case strings.HasSuffix(lower, "mb"):
		lower = strings.TrimSuffix(lower, "mb")
	case strings.HasSuffix(lower, "g"):
		lower = strings.TrimSuffix(lower, "g")
		multiplier = 1024
	case strings.HasSuffix(lower, "gb"):
		lower = strings.TrimSuffix(lower, "gb")
		multiplier = 1024
	default:
		return 0, errors.New("Compose memory limit must use M, MB, G, or GB")
	}
	amount, err := strconv.ParseInt(lower, 10, 64)
	if err != nil || amount*multiplier < 16 || amount*multiplier > 64*1024 {
		return 0, errors.New("Compose memory limit must be between 16 MiB and 64 GiB")
	}
	return amount * multiplier, nil
}

func validateContainerPath(value string) error {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" || strings.ContainsRune(value, '\x00') {
		return errors.New("Compose container path is unsafe")
	}
	return nil
}

func validateBindMount(value string) (string, error) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return "", errors.New("Compose volume uses an unsupported short syntax")
	}
	source, target := parts[0], parts[1]
	if source == "" || target == "" {
		return "", errors.New("Compose volume source and target are required")
	}
	if err := validateContainerPath(target); err != nil {
		return "", err
	}
	if len(parts) == 3 && parts[2] != "ro" && parts[2] != "rw" {
		return "", errors.New("Compose bind mount permits only ro or rw mode")
	}
	if composeNamePattern.MatchString(source) {
		return "named:" + source, nil
	}
	if filepath.IsAbs(source) || strings.ContainsRune(source, '\x00') {
		return "", errors.New("Compose bind mounts must use a relative path inside the migration root")
	}
	clean := filepath.Clean(source)
	clean = strings.TrimPrefix(clean, "."+string(filepath.Separator))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("Compose bind mount escaped the migration root")
	}
	return "bind:" + filepath.ToSlash(clean), nil
}

func validatePublishedPort(value string) (int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 || parts[0] != "127.0.0.1" {
		return 0, errors.New("Compose published ports must bind explicitly to 127.0.0.1")
	}
	hostPort, err := strconv.Atoi(parts[1])
	if err != nil || hostPort < 1024 || hostPort > 65535 {
		return 0, errors.New("Compose host port must be an unprivileged fixed port")
	}
	containerPort := strings.TrimSuffix(parts[2], "/tcp")
	if strings.Contains(containerPort, "/") {
		return 0, errors.New("Compose UDP and unknown port protocols are unsupported")
	}
	parsedContainerPort, err := strconv.Atoi(containerPort)
	if err != nil || parsedContainerPort < 1 || parsedContainerPort > 65535 {
		return 0, errors.New("Compose container port is invalid")
	}
	return hostPort, nil
}

func validateEnvironment(environment map[string]string, serviceSecrets map[string]struct{}) error {
	if len(environment) > 128 {
		return errors.New("Compose environment exceeds the 128-entry limit")
	}
	for key, value := range environment {
		if !composeEnvironmentKeyPattern.MatchString(key) || len(value) > 4096 || strings.ContainsRune(value, '\x00') {
			return errors.New("Compose environment contains an invalid bounded literal")
		}
		lower := strings.ToLower(key)
		secretShaped := strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "private_key") || strings.Contains(lower, "api_key")
		secretFile := false
		if secretShaped && strings.HasSuffix(key, "_FILE") && strings.HasPrefix(value, "/run/secrets/") {
			_, secretFile = serviceSecrets[strings.TrimPrefix(value, "/run/secrets/")]
		}
		if secretShaped && !secretFile {
			return errors.New("Compose environment cannot embed secret-shaped fields")
		}
		if strings.Contains(value, "${") {
			return errors.New("Compose variable interpolation is disabled")
		}
	}
	return nil
}

type composeNetworkScope struct {
	subnet  *net.IPNet
	gateway net.IP
}

func parseComposeNetworkScope(network composeNetwork) (composeNetworkScope, error) {
	if network.IPAM == nil || len(network.IPAM.Config) != 1 {
		return composeNetworkScope{}, errors.New("Compose isolated networks require exactly one fixed IPv4 IPAM range")
	}
	config := network.IPAM.Config[0]
	parsed, subnet, err := net.ParseCIDR(config.Subnet)
	if err != nil || parsed.To4() == nil || subnet == nil {
		return composeNetworkScope{}, errors.New("Compose isolated network subnet is invalid")
	}
	ones, bits := subnet.Mask.Size()
	base := subnet.IP.To4()
	if bits != 32 || ones != 24 || !parsed.Equal(base) || !base.IsPrivate() || config.Subnet != base.String()+"/24" {
		return composeNetworkScope{}, errors.New("Compose isolated networks require canonical private IPv4 /24 subnets")
	}
	gateway := net.ParseIP(config.Gateway)
	if gateway == nil || gateway.To4() == nil || gateway.String() != config.Gateway || !subnet.Contains(gateway) {
		return composeNetworkScope{}, errors.New("Compose isolated network gateway is invalid")
	}
	expectedGateway := append(net.IP(nil), base...)
	expectedGateway[3]++
	if !gateway.Equal(expectedGateway) {
		return composeNetworkScope{}, errors.New("Compose isolated network gateway must be the first address in its /24")
	}
	return composeNetworkScope{subnet: subnet, gateway: gateway.To4()}, nil
}

func validateComposeStaticIPv4(value string, scope composeNetworkScope) (string, error) {
	address := net.ParseIP(value)
	if address == nil || address.To4() == nil || address.String() != value || !address.IsPrivate() || !scope.subnet.Contains(address) {
		return "", errors.New("Compose service static IPv4 address is outside its approved private network")
	}
	address = address.To4()
	if address.Equal(scope.subnet.IP) || address.Equal(scope.gateway) || address[3] == 255 {
		return "", errors.New("Compose service static IPv4 address is reserved")
	}
	return address.String(), nil
}

func validateComposeDocument(document composeDocument) (composePolicyResult, error) {
	if len(document.Services) == 0 || len(document.Services) > 64 || len(document.Networks) == 0 || len(document.Networks) > 16 || len(document.Volumes) > 64 || len(document.Secrets) > 32 {
		return composePolicyResult{}, errors.New("Compose document exceeds the supported service/network/volume bounds")
	}
	result := composePolicyResult{Document: document, PublishedPorts: []int{}, NamedVolumes: []string{}, NetworkNames: []string{}, BindMountRoots: []string{}, SecretFiles: map[string]string{}}
	usedNetworks := map[string]struct{}{}
	usedVolumes := map[string]struct{}{}
	usedSecrets := map[string]struct{}{}
	networkScopes := map[string]composeNetworkScope{}
	subnetSet := map[string]struct{}{}
	for name, network := range document.Networks {
		if !composeNamePattern.MatchString(name) || !network.Internal || (network.Driver != "" && network.Driver != "bridge") {
			return composePolicyResult{}, errors.New("Compose networks must be named internal bridge networks")
		}
		scope, err := parseComposeNetworkScope(network)
		if err != nil {
			return composePolicyResult{}, err
		}
		subnet := scope.subnet.String()
		if _, duplicate := subnetSet[subnet]; duplicate {
			return composePolicyResult{}, errors.New("Compose isolated network subnet is duplicated")
		}
		subnetSet[subnet] = struct{}{}
		networkScopes[name] = scope
		result.NetworkNames = append(result.NetworkNames, name)
	}
	for name, volume := range document.Volumes {
		if !composeNamePattern.MatchString(name) || (volume.Driver != "" && volume.Driver != "local") {
			return composePolicyResult{}, errors.New("Compose named volumes must use the local driver without options")
		}
		result.NamedVolumes = append(result.NamedVolumes, name)
	}
	for name, secret := range document.Secrets {
		if !composeNamePattern.MatchString(name) || !composeRuntimeSecretPattern.MatchString(secret.File) || filepath.Base(secret.File) != name {
			return composePolicyResult{}, errors.New("Compose secrets must use fixed migration-root files")
		}
		result.SecretFiles[name] = secret.File
	}
	staticIPv4Set := map[string]struct{}{}
	for name, service := range document.Services {
		if !composeNamePattern.MatchString(name) || !composeImagePattern.MatchString(service.Image) {
			return composePolicyResult{}, errors.New("Compose services require safe names and digest-pinned images")
		}
		if service.User == "" || service.User == "0" || service.User == "root" || strings.HasPrefix(service.User, "0:") {
			return composePolicyResult{}, errors.New("Compose services must declare a non-root container user")
		}
		if !service.ReadOnly || !service.Init || service.PidsLimit < 16 || service.PidsLimit > 4096 {
			return composePolicyResult{}, errors.New("Compose services require read-only roots, init, and bounded pids")
		}
		if _, err := parseCPU(service.CPUs); err != nil {
			return composePolicyResult{}, err
		}
		if _, err := parseMemoryMiB(service.MemoryLimit); err != nil {
			return composePolicyResult{}, err
		}
		if len(service.CapDrop) != 1 || service.CapDrop[0] != "ALL" || len(service.SecurityOpt) != 1 || service.SecurityOpt[0] != "no-new-privileges:true" {
			return composePolicyResult{}, errors.New("Compose services must drop all capabilities and enable no-new-privileges")
		}
		if service.Restart != "" && service.Restart != "no" && service.Restart != "on-failure" {
			return composePolicyResult{}, errors.New("Compose isolated services use only no or on-failure restart policy")
		}
		if service.StopGracePeriod != "" && !composeDurationPattern.MatchString(service.StopGracePeriod) {
			return composePolicyResult{}, errors.New("Compose stop grace period must be a bounded whole-second duration")
		}
		serviceSecrets := map[string]struct{}{}
		for _, secret := range service.Secrets {
			if _, declared := document.Secrets[secret]; !declared {
				return composePolicyResult{}, errors.New("Compose service references an undeclared secret")
			}
			if _, duplicate := serviceSecrets[secret]; duplicate {
				return composePolicyResult{}, errors.New("Compose service secret is duplicated")
			}
			serviceSecrets[secret] = struct{}{}
			usedSecrets[secret] = struct{}{}
		}
		if err := validateEnvironment(service.Environment, serviceSecrets); err != nil {
			return composePolicyResult{}, err
		}
		for dependency, policy := range service.DependsOn {
			if !composeNamePattern.MatchString(dependency) || (policy.Condition != "" && policy.Condition != "service_started" && policy.Condition != "service_healthy") || policy.Restart {
				return composePolicyResult{}, errors.New("Compose dependency policy is unsupported")
			}
			if _, exists := document.Services[dependency]; !exists {
				return composePolicyResult{}, errors.New("Compose dependency references an unknown service")
			}
		}
		if len(service.Networks) == 0 {
			return composePolicyResult{}, errors.New("Compose services must attach to declared fixed-address isolated networks")
		}
		for network, attachment := range service.Networks {
			scope, exists := networkScopes[network]
			if !exists {
				return composePolicyResult{}, errors.New("Compose service references an unknown network")
			}
			address, err := validateComposeStaticIPv4(attachment.IPv4Address, scope)
			if err != nil {
				return composePolicyResult{}, err
			}
			if _, duplicate := staticIPv4Set[address]; duplicate {
				return composePolicyResult{}, errors.New("Compose service static IPv4 address is duplicated")
			}
			staticIPv4Set[address] = struct{}{}
			usedNetworks[network] = struct{}{}
		}
		for _, volume := range service.Volumes {
			kind, err := validateBindMount(volume)
			if err != nil {
				return composePolicyResult{}, err
			}
			if strings.HasPrefix(kind, "named:") {
				name := strings.TrimPrefix(kind, "named:")
				if _, exists := document.Volumes[name]; !exists {
					return composePolicyResult{}, errors.New("Compose service references an undeclared named volume")
				}
				usedVolumes[name] = struct{}{}
			} else {
				result.BindMountRoots = append(result.BindMountRoots, strings.TrimPrefix(kind, "bind:"))
			}
		}
		for _, path := range service.Tmpfs {
			mountPath := strings.SplitN(path, ":", 2)[0]
			if err := validateContainerPath(mountPath); err != nil {
				return composePolicyResult{}, errors.New("Compose tmpfs path is unsafe")
			}
		}
		if len(service.Ports) > 0 {
			return composePolicyResult{}, errors.New("Compose isolated services cannot declare ignored host port mappings; validate their fixed private IPv4 address")
		}
		if service.Logging != nil {
			if service.Logging.Driver != "json-file" || len(service.Logging.Options) == 0 || len(service.Logging.Options) > 4 || service.Logging.Options["max-size"] == "" || service.Logging.Options["max-file"] == "" {
				return composePolicyResult{}, errors.New("Compose logging must use bounded json-file rotation")
			}
			for key, value := range service.Logging.Options {
				if (key != "max-size" && key != "max-file") || len(value) > 16 {
					return composePolicyResult{}, errors.New("Compose logging option is unsupported")
				}
			}
		}
	}
	if len(usedNetworks) != len(document.Networks) || len(usedVolumes) != len(document.Volumes) || len(usedSecrets) != len(document.Secrets) {
		return composePolicyResult{}, errors.New("Compose declares unused networks or volumes")
	}
	sort.Ints(result.PublishedPorts)
	sort.Strings(result.NamedVolumes)
	sort.Strings(result.NetworkNames)
	sort.Strings(result.BindMountRoots)
	canonical, err := yaml.Marshal(document)
	if err != nil {
		return composePolicyResult{}, errors.New("Compose canonical rendering failed")
	}
	result.CanonicalYAML = canonical
	result.Digest, err = Digest(map[string]any{"schema_version": composePolicySchema, "compose_yaml": string(canonical)})
	return result, err
}

func parseComposePolicy(data []byte) (composePolicyResult, error) {
	if len(data) == 0 || len(data) > 256*1024 {
		return composePolicyResult{}, errors.New("Compose document exceeds the 256 KiB limit")
	}
	if bytes.Contains(data, []byte("${")) {
		return composePolicyResult{}, errors.New("Compose variable interpolation is disabled")
	}
	var syntax yaml.Node
	if err := yaml.Unmarshal(data, &syntax); err != nil {
		return composePolicyResult{}, errors.New("Compose YAML is invalid")
	}
	if err := rejectYAMLAliases(&syntax); err != nil {
		return composePolicyResult{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var document composeDocument
	if err := decoder.Decode(&document); err != nil {
		return composePolicyResult{}, errors.New("Compose document contains an unknown or invalid field")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return composePolicyResult{}, errors.New("Compose document must contain exactly one YAML document")
	}
	return validateComposeDocument(document)
}

func composeFileInput(inputs map[string]any) (string, error) {
	name, err := stringInput(inputs, "compose_file")
	if err != nil || strings.Contains(name, "/") || !fileNamePattern.MatchString(name) || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
		return "", errors.New("Compose file handle is invalid")
	}
	return name, nil
}

func composeProjectInput(inputs map[string]any) (string, error) {
	project, err := stringInput(inputs, "project_name")
	if err != nil || !composeProjectPattern.MatchString(project) {
		return "", errors.New("Compose project name is outside the migration namespace")
	}
	return project, nil
}

func (e *NativeExecutor) composeRender(inputs map[string]any) (map[string]any, error) {
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	fileName, err := composeFileInput(inputs)
	if err != nil {
		return nil, err
	}
	raw, ok := inputs["rendered_compose"]
	if !ok || raw == nil {
		return nil, errors.New("rendered Compose document is required")
	}
	jsonCompatible, err := CanonicalJSON(raw)
	if err != nil || len(jsonCompatible) > 256*1024 {
		return nil, errors.New("rendered Compose document is invalid")
	}
	var normalized any
	if err := json.Unmarshal(jsonCompatible, &normalized); err != nil {
		return nil, errors.New("rendered Compose document is invalid")
	}
	yamlData, err := yaml.Marshal(normalized)
	if err != nil {
		return nil, errors.New("rendered Compose document is invalid")
	}
	policy, err := parseComposePolicy(yamlData)
	if err != nil {
		return nil, err
	}
	target, err := e.resolver.Resolve(handle, fileName, true)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(target); err == nil {
		return nil, errors.New("Compose file collision")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".compose-")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o640); err != nil {
		temporary.Close()
		return nil, err
	}
	if _, err := temporary.Write(policy.CanonicalYAML); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return nil, err
	}
	return map[string]any{
		"compose_digest": policy.Digest, "service_count": len(policy.Document.Services),
		"published_port_count": len(policy.PublishedPorts), "network_count": len(policy.NetworkNames),
		"named_volume_count": len(policy.NamedVolumes),
	}, nil
}

func wipeAndRemoveComposeSecret(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Compose runtime secret cleanup found an unsafe file")
	}
	// The leaf is 0444 while mounted so an arbitrary non-root container UID can
	// read it. The containing runtime directories remain 0700. The agent owns
	// the file and the broker is root, so either side can restore owner-write
	// permission only for the bounded zero-and-unlink operation.
	if err := os.Chmod(path, 0o600); err != nil {
		return errors.New("Compose runtime secret cleanup could not secure the file for wiping")
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	zero := make([]byte, info.Size())
	_, writeErr := file.WriteAt(zero, 0)
	zeroBytes(zero)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("Compose runtime secret cleanup failed")
	}
	return os.Remove(path)
}

func (e *NativeExecutor) stageComposeRuntimeSecrets(ctx context.Context, task TaskEnvelope, inputs map[string]any) (func() error, error) {
	bindingID, err := stringInput(inputs, "runtime_secret_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(bindingID) {
		return nil, errors.New("Compose runtime secret binding identifier is invalid")
	}
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	fileName, err := composeFileInput(inputs)
	if err != nil {
		return nil, err
	}
	composePath, err := e.resolver.Resolve(handle, fileName, false)
	if err != nil {
		return nil, err
	}
	composeData, err := os.ReadFile(composePath)
	if err != nil {
		return nil, errors.New("rendered Compose document is unavailable")
	}
	policy, err := parseComposePolicy(composeData)
	if err != nil {
		return nil, err
	}
	if len(policy.SecretFiles) == 0 {
		return nil, errors.New("Compose runtime declares no secret mounts")
	}
	project, err := composeProjectInput(inputs)
	if err != nil {
		return nil, err
	}
	raw, err := e.resolveBinding(ctx, task, bindingID)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(raw)
	binding, err := parseComposeRuntimeSecretsBinding(raw)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if len(binding.Secrets) != len(policy.SecretFiles) {
		return nil, errors.New("Compose runtime secret names do not match the approved policy")
	}
	for name := range policy.SecretFiles {
		if _, present := binding.Secrets[name]; !present {
			return nil, errors.New("Compose runtime secret names do not match the approved policy")
		}
	}
	if err := os.MkdirAll(composeRuntimeSecretsRoot, 0o700); err != nil {
		return nil, errors.New("Compose runtime secret memory root is unavailable")
	}
	rootInfo, err := os.Lstat(composeRuntimeSecretsRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Compose runtime secret memory root is unsafe")
	}
	directory := filepath.Join(composeRuntimeSecretsRoot, project)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, errors.New("Compose runtime secret staging directory is not new")
	}
	paths := make([]string, 0, len(policy.SecretFiles))
	cleanup := func() error {
		var cleanupErr error
		for _, path := range paths {
			if err := wipeAndRemoveComposeSecret(path); err != nil && cleanupErr == nil {
				cleanupErr = err
			}
		}
		if err := os.Remove(directory); err != nil && !os.IsNotExist(err) && cleanupErr == nil {
			cleanupErr = err
		}
		return cleanupErr
	}
	names := make([]string, 0, len(policy.SecretFiles))
	for name := range policy.SecretFiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := policy.SecretFiles[name]
		if path != filepath.Join(directory, name) || filepath.Dir(path) != directory {
			_ = cleanup()
			return nil, errors.New("Compose runtime secret path escaped its staging directory")
		}
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			_ = cleanup()
			return nil, errors.New("Compose runtime secret staging failed")
		}
		paths = append(paths, path)
		value := []byte(binding.Secrets[name])
		_, writeErr := file.Write(value)
		zeroBytes(value)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			_ = cleanup()
			return nil, errors.New("Compose runtime secret staging failed")
		}
		if chmodErr := os.Chmod(path, 0o444); chmodErr != nil {
			_ = cleanup()
			return nil, errors.New("Compose runtime secret staging failed")
		}
	}
	return cleanup, nil
}

func (e *NativeExecutor) composeStartWithRuntimeSecrets(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	cleanup, err := e.stageComposeRuntimeSecrets(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	response, executeErr := e.broker.Execute(ctx, BrokerRequest{SchemaVersion: brokerSchemaVersion, RequestID: task.Nonce, Task: task})
	if executeErr != nil {
		// A lost broker response is ambiguous: Compose may already have created a
		// container whose secret bind mount depends on this inode. Recovery uses
		// the typed stop primitive, which also wipes the runtime secret directory.
		return nil, executeErr
	}
	if !response.OK {
		preserveRuntimeSecrets, _ := response.Outputs["preserve_runtime_secrets"].(bool)
		if !preserveRuntimeSecrets {
			if cleanupErr := cleanup(); cleanupErr != nil {
				return nil, errors.New("typed privilege broker rejected the Compose start and runtime secret cleanup failed")
			}
		}
		if response.Error != nil {
			return nil, errors.New(response.Error.SafeMessage)
		}
		return nil, errors.New("typed privilege broker rejected the Compose start")
	}
	if response.Outputs == nil {
		response.Outputs = map[string]any{}
	}
	response.Outputs["runtime_secrets_in_memory"] = true
	return response.Outputs, nil
}

func ensurePortsAvailable(ports []int) error {
	listeners := make([]net.Listener, 0, len(ports))
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, port := range ports {
		listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return errors.New("Compose published port collides with an active listener")
		}
		listeners = append(listeners, listener)
	}
	return nil
}
