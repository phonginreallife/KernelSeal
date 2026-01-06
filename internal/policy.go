// Package internal provides core X00 functionality
package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"x00/internal/secrets"
	"x00/internal/types"
)

// PolicyManager manages X00 security policies
type PolicyManager struct {
	config         *X00Config
	configPath     string
	secretInjector *secrets.Injector
	mu             sync.RWMutex

	// Callbacks for policy updates
	onPolicyUpdate func(types.PolicyConfig)
}

// X00Config represents the complete X00 configuration
type X00Config struct {
	Version    string           `yaml:"version" json:"version"`
	Policy     PolicySpec       `yaml:"policy" json:"policy"`
	Secrets    []SecretBinding  `yaml:"secrets" json:"secrets"`
	Monitoring MonitoringConfig `yaml:"monitoring" json:"monitoring"`
}

// PolicySpec defines the LSM policy settings
type PolicySpec struct {
	Mode          string `yaml:"mode" json:"mode"` // disabled, audit, enforce
	BlockEnviron  bool   `yaml:"blockEnviron" json:"blockEnviron"`
	BlockMem      bool   `yaml:"blockMem" json:"blockMem"`
	BlockMaps     bool   `yaml:"blockMaps" json:"blockMaps"`
	BlockPtrace   bool   `yaml:"blockPtrace" json:"blockPtrace"`
	AllowSelfRead bool   `yaml:"allowSelfRead" json:"allowSelfRead"`
	AuditAll      bool   `yaml:"auditAll" json:"auditAll"`

	// Kernel-side filtering options
	// When enabled, only processes matching configured binaries will be monitored
	// This significantly reduces overhead for systems with many processes
	KernelBinaryFilter bool `yaml:"kernelBinaryFilter" json:"kernelBinaryFilter"`
}

// SecretBinding binds secrets to specific processes
type SecretBinding struct {
	Name       string          `yaml:"name" json:"name"`             // Binding name
	Selector   ProcessSelector `yaml:"selector" json:"selector"`     // How to select processes
	SecretRefs []SecretRef     `yaml:"secretRefs" json:"secretRefs"` // References to secrets
}

// ProcessSelector defines how to select target processes
type ProcessSelector struct {
	Binary     string            `yaml:"binary,omitempty" json:"binary,omitempty"`         // Match by binary name
	Container  string            `yaml:"container,omitempty" json:"container,omitempty"`   // Match by container name
	Labels     map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`         // Match by pod labels
	Namespace  string            `yaml:"namespace,omitempty" json:"namespace,omitempty"`   // Match by namespace
	CgroupPath string            `yaml:"cgroupPath,omitempty" json:"cgroupPath,omitempty"` // Match by cgroup path
}

// SecretRef references a secret source
type SecretRef struct {
	Name   string       `yaml:"name" json:"name"`     // Environment variable name
	Source SecretSource `yaml:"source" json:"source"` // Secret source
}

// SecretSource defines where to get the secret value
type SecretSource struct {
	// Kubernetes secret reference
	SecretKeyRef *SecretKeyRef `yaml:"secretKeyRef,omitempty" json:"secretKeyRef,omitempty"`
	// File path reference
	FileRef string `yaml:"fileRef,omitempty" json:"fileRef,omitempty"`
	// Environment variable reference
	EnvRef string `yaml:"envRef,omitempty" json:"envRef,omitempty"`
	// Vault reference (future)
	VaultRef *VaultRef `yaml:"vaultRef,omitempty" json:"vaultRef,omitempty"`
}

// SecretKeyRef references a Kubernetes secret
type SecretKeyRef struct {
	Name      string `yaml:"name" json:"name"`
	Key       string `yaml:"key" json:"key"`
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

// VaultRef references a HashiCorp Vault secret
type VaultRef struct {
	Path string `yaml:"path" json:"path"`
	Key  string `yaml:"key" json:"key"`
}

// MonitoringConfig defines monitoring settings
type MonitoringConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	MetricsPort int    `yaml:"metricsPort" json:"metricsPort"`
	LogLevel    string `yaml:"logLevel" json:"logLevel"`
	AuditLog    string `yaml:"auditLog" json:"auditLog"` // Path to audit log file
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager(secretInjector *secrets.Injector) *PolicyManager {
	return &PolicyManager{
		config:         DefaultConfig(),
		secretInjector: secretInjector,
	}
}

// DefaultConfig returns the default X00 configuration
func DefaultConfig() *X00Config {
	return &X00Config{
		Version: "v1",
		Policy: PolicySpec{
			Mode:               "enforce",
			BlockEnviron:       true,
			BlockMem:           true,
			BlockMaps:          false,
			BlockPtrace:        true,
			AllowSelfRead:      true,
			AuditAll:           false,
			KernelBinaryFilter: true, // Enable kernel-side filtering by default
		},
		Secrets: []SecretBinding{},
		Monitoring: MonitoringConfig{
			Enabled:     true,
			MetricsPort: 9090,
			LogLevel:    "info",
			AuditLog:    "/var/log/x00/audit.log",
		},
	}
}

// SetPolicyUpdateCallback sets the callback for policy updates
func (pm *PolicyManager) SetPolicyUpdateCallback(cb func(types.PolicyConfig)) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.onPolicyUpdate = cb
}

// LoadConfig loads configuration from a file or directory
func (pm *PolicyManager) LoadConfig(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat config path: %w", err)
	}

	var config *X00Config
	if info.IsDir() {
		config, err = pm.loadConfigFromDir(path)
	} else {
		config, err = pm.loadConfigFromFile(path)
	}

	if err != nil {
		return err
	}

	// Update config under lock
	pm.mu.Lock()
	pm.configPath = path
	pm.config = config
	pm.mu.Unlock()

	log.Printf("[CONFIG] Loaded X00 configuration from %s", path)

	// Apply policy (these methods handle their own locking)
	pm.applyPolicy()

	// Load secrets
	pm.loadSecrets()

	return nil
}

func (pm *PolicyManager) loadConfigFromFile(path string) (*X00Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	config := DefaultConfig()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", ext)
	}

	return config, nil
}

func (pm *PolicyManager) loadConfigFromDir(dir string) (*X00Config, error) {
	// Look for config files in the directory (ConfigMap mount style)
	config := DefaultConfig()

	// Check for policy.yaml
	policyPath := filepath.Join(dir, "policy.yaml")
	if data, err := os.ReadFile(policyPath); err == nil {
		if err := yaml.Unmarshal(data, &config.Policy); err != nil {
			log.Printf("[WARN] Failed to parse policy.yaml: %v", err)
		}
	}

	// Check for secrets.yaml
	secretsPath := filepath.Join(dir, "secrets.yaml")
	if data, err := os.ReadFile(secretsPath); err == nil {
		var secretBindings []SecretBinding
		if err := yaml.Unmarshal(data, &secretBindings); err != nil {
			log.Printf("[WARN] Failed to parse secrets.yaml: %v", err)
		} else {
			config.Secrets = secretBindings
		}
	}

	// Check for monitoring.yaml
	monitoringPath := filepath.Join(dir, "monitoring.yaml")
	if data, err := os.ReadFile(monitoringPath); err == nil {
		if err := yaml.Unmarshal(data, &config.Monitoring); err != nil {
			log.Printf("[WARN] Failed to parse monitoring.yaml: %v", err)
		}
	}

	return config, nil
}

func (pm *PolicyManager) applyPolicy() {
	policy := pm.GetBPFPolicy()

	pm.mu.RLock()
	cb := pm.onPolicyUpdate
	mode := pm.config.Policy.Mode
	pm.mu.RUnlock()

	if cb != nil {
		cb(policy)
	}

	log.Printf("[CONFIG] Policy applied: mode=%s", mode)
}

func (pm *PolicyManager) loadSecrets() {
	if pm.secretInjector == nil {
		return
	}

	for _, binding := range pm.config.Secrets {
		secretsList := make([]secrets.Secret, 0, len(binding.SecretRefs))

		for _, ref := range binding.SecretRefs {
			value, err := pm.resolveSecretValue(ref.Source)
			if err != nil {
				log.Printf("[WARN] Failed to resolve secret %s: %v", ref.Name, err)
				continue
			}

			secretsList = append(secretsList, secrets.Secret{
				Name:  ref.Name,
				Value: value,
			})
		}

		// Register secrets based on selector
		if binding.Selector.Binary != "" {
			pm.secretInjector.RegisterSecrets(binding.Selector.Binary, secretsList)
		}

		// TODO: Handle other selector types (container, labels, namespace, cgroupPath)
	}
}

func (pm *PolicyManager) resolveSecretValue(source SecretSource) (string, error) {
	// Environment variable reference
	if source.EnvRef != "" {
		value := os.Getenv(source.EnvRef)
		if value == "" {
			return "", fmt.Errorf("environment variable %s not set", source.EnvRef)
		}
		return value, nil
	}

	// File reference
	if source.FileRef != "" {
		data, err := os.ReadFile(source.FileRef)
		if err != nil {
			return "", fmt.Errorf("failed to read file %s: %w", source.FileRef, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// Kubernetes secret reference (requires k8s client)
	if source.SecretKeyRef != nil {
		// For now, check if the secret is mounted as a file
		// This is the typical pattern when using K8s secrets as volume mounts
		mountPath := fmt.Sprintf("/var/run/secrets/x00/%s/%s",
			source.SecretKeyRef.Name, source.SecretKeyRef.Key)
		if data, err := os.ReadFile(mountPath); err == nil {
			return strings.TrimSpace(string(data)), nil
		}

		// Alternative: read from standard k8s secret mount
		altPath := fmt.Sprintf("/var/run/secrets/kubernetes.io/serviceaccount/%s",
			source.SecretKeyRef.Key)
		if data, err := os.ReadFile(altPath); err == nil {
			return strings.TrimSpace(string(data)), nil
		}

		return "", fmt.Errorf("kubernetes secret %s/%s not found",
			source.SecretKeyRef.Name, source.SecretKeyRef.Key)
	}

	// Vault reference (future implementation)
	if source.VaultRef != nil {
		return "", fmt.Errorf("vault integration not yet implemented")
	}

	return "", fmt.Errorf("no valid secret source specified")
}

// GetBPFPolicy converts the policy spec to BPF policy config
func (pm *PolicyManager) GetBPFPolicy() types.PolicyConfig {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	policy := types.PolicyConfig{
		AllowSelfRead: boolToUint8(pm.config.Policy.AllowSelfRead),
		BlockEnviron:  boolToUint8(pm.config.Policy.BlockEnviron),
		BlockMem:      boolToUint8(pm.config.Policy.BlockMem),
		BlockMaps:     boolToUint8(pm.config.Policy.BlockMaps),
		BlockPtrace:   boolToUint8(pm.config.Policy.BlockPtrace),
		AuditAll:      boolToUint8(pm.config.Policy.AuditAll),
	}

	switch strings.ToLower(pm.config.Policy.Mode) {
	case "disabled":
		policy.EnforceMode = types.ModeDisabled
	case "audit":
		policy.EnforceMode = types.ModeAudit
	case "enforce":
		policy.EnforceMode = types.ModeEnforce
	default:
		policy.EnforceMode = types.ModeEnforce
	}

	return policy
}

// GetConfig returns the current configuration
func (pm *PolicyManager) GetConfig() *X00Config {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.config
}

// ShouldInjectSecrets returns secrets for a given process
func (pm *PolicyManager) ShouldInjectSecrets(binaryName string, cgroupID uint64) []secrets.Secret {
	if pm.secretInjector == nil {
		return nil
	}
	return pm.secretInjector.GetSecretsForProcess(binaryName, cgroupID)
}

// GetTargetBinaries returns a list of all binary names configured for secret injection
// This is used to configure kernel-side binary filtering
func (pm *PolicyManager) GetTargetBinaries() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	binaries := make([]string, 0)
	seen := make(map[string]bool)

	for _, binding := range pm.config.Secrets {
		if binding.Selector.Binary != "" && !seen[binding.Selector.Binary] {
			binaries = append(binaries, binding.Selector.Binary)
			seen[binding.Selector.Binary] = true
		}
	}

	return binaries
}

// IsKernelBinaryFilterEnabled returns whether kernel-side binary filtering is enabled
func (pm *PolicyManager) IsKernelBinaryFilterEnabled() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.config.Policy.KernelBinaryFilter
}

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// ApplyFileProtectionPolicy is a legacy function for backwards compatibility
func ApplyFileProtectionPolicy() {
	log.Println("[INFO] [X00] File protection policy initialized (see BPF manager for LSM hooks)")
}
