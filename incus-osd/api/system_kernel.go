package api

// SystemKernelConfig holds the kernel-level configuration data.
type SystemKernelConfig struct {
	PCIPassthroughIDs []string          `json:"pci_passthrough_ids,omitempty" yaml:"pci_passthrough_ids,omitempty"`
	BlacklistModules  []string          `json:"blacklist_modules,omitempty"   yaml:"blacklist_modules,omitempty"`
	SysctlConfig      map[string]string `json:"sysctl_config,omitempty"       yaml:"sysctl_config,omitempty"`
}

// SystemKernelState represents state for the system's kernel-level configuration.
type SystemKernelState struct{}

// SystemKernel defines a struct to hold information about the system's kernel-level configuration.
type SystemKernel struct {
	Config SystemKernelConfig `json:"config" yaml:"config"`
	State  SystemKernelState  `incusos:"-"   json:"state"  yaml:"state"`
}
