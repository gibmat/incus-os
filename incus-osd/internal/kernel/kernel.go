package kernel

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/lxc/incus-os/incus-osd/api"
	"github.com/lxc/incus-os/incus-osd/internal/systemd"
)

// ApplyKernelConfiguration updates various parts of the kernel configuration. A reboot
// may be required to fully apply the changes.
func ApplyKernelConfiguration(ctx context.Context, config api.SystemKernelConfig) error {
	// Update the list pf PCI(e) pass-throughs.
	err := updatePCIPassthroughs(config.PCIPassthroughIDs)
	if err != nil {
		return err
	}

	// Update the list of blacklisted kernel modules.
	err = updateBlacklistModules(config.BlacklistModules)
	if err != nil {
		return err
	}

	// Update local sysctl configuration.
	err = updateSysctlConfig(ctx, config.SysctlConfig)
	if err != nil {
		return err
	}

	return nil
}

func updatePCIPassthroughs(pciIDs []string) error {
	// Remove the existing configuration file, if it exists.
	_, err := os.Stat("/etc/modprobe.d/99-local-device-passthrough.conf")
	if err == nil {
		err = os.Remove("/etc/modprobe.d/99-local-device-passthrough.conf")
		if err != nil {
			return err
		}
	}

	// If no passthroughs are specified, there's nothing else to do.
	if len(pciIDs) == 0 {
		return nil
	}

	// Verify that the device IDs look plausible.
	re := regexp.MustCompile(`^[0-9A-Fa-f]+:[0-9A-Fa-f]+$`)
	for _, id := range pciIDs {
		if !re.MatchString(id) {
			return errors.New("PCI ID '" + id + "' is invalid")
		}
	}

	// Ensure the modprobe.d directory exists.
	err = os.MkdirAll("/etc/modprobe.d/", 0o755)
	if err != nil {
		return err
	}

	// Create the new configuration file.
	fd, err := os.Create("/etc/modprobe.d/99-local-device-passthrough.conf")
	if err != nil {
		return err
	}

	// Write the file contents.
	_, err = fd.WriteString("options vfio-pci ids=" + strings.Join(pciIDs, ",") + "\n")

	return err
}

func updateBlacklistModules(modules []string) error {
	// Remove the existing configuration file, if it exists.
	_, err := os.Stat("/etc/modprobe.d/99-blacklist-modules.conf")
	if err == nil {
		err = os.Remove("/etc/modprobe.d/99-blacklist-modules.conf")
		if err != nil {
			return err
		}
	}

	// If no blacklisted modules are specified, there's nothing else to do.
	if len(modules) == 0 {
		return nil
	}

	// Ensure the modprobe.d directory exists.
	err = os.MkdirAll("/etc/modprobe.d/", 0o755)
	if err != nil {
		return err
	}

	// Create the new configuration file.
	fd, err := os.Create("/etc/modprobe.d/99-blacklist-modules.conf")
	if err != nil {
		return err
	}

	// Write the file contents.
	for _, module := range modules {
		if module == "" {
			continue
		}

		_, err := fd.WriteString("blacklist " + module + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func updateSysctlConfig(ctx context.Context, sysctl map[string]string) error {
	// Remove the existing configuration file, if it exists.
	_, err := os.Stat("/etc/sysctl.d/99-local-sysctl.conf")
	if err == nil {
		err = os.Remove("/etc/sysctl.d/99-local-sysctl.conf")
		if err != nil {
			return err
		}
	}

	// If no sysctls are specified, there's nothing else to do.
	if len(sysctl) == 0 {
		// Restart the systemd-sysctl to pickup changes.
		return systemd.RestartUnit(ctx, "systemd-sysctl.service")
	}

	// Ensure the sysctl.d directory exists.
	err = os.MkdirAll("/etc/sysctl.d/", 0o755)
	if err != nil {
		return err
	}

	// Create the new configuration file.
	fd, err := os.Create("/etc/sysctl.d/99-local-sysctl.conf")
	if err != nil {
		return err
	}

	// Write the file contents.
	for key, value := range sysctl {
		if key == "" {
			continue
		}

		_, err := fd.WriteString(key + "=" + value + "\n")
		if err != nil {
			return err
		}
	}

	// Restart the systemd-sysctl to pickup changes.
	return systemd.RestartUnit(ctx, "systemd-sysctl.service")
}
