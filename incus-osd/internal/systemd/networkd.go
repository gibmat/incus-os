package systemd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lxc/incus/v6/shared/subprocess"

	"github.com/lxc/incus-os/incus-osd/api"
	"github.com/lxc/incus-os/incus-osd/internal/proxy"
	"github.com/lxc/incus-os/incus-osd/internal/state"
)

// networkdConfigFile represents a given filename and its contents.
type networkdConfigFile struct {
	Name     string
	Contents string
}

// ApplyNetworkConfiguration instructs systemd-networkd to apply the supplied network configuration.
func ApplyNetworkConfiguration(ctx context.Context, s *state.State, networkCfg *api.SystemNetworkConfig, timeout time.Duration, allowPartialConfig bool, refresh func(context.Context, *state.State) error) error {
	// Very first, dynamically lookup any MAC address that is referred to by an interface name.
	// This could be the case when reading in seed data, or if a user provides an interface
	// name via an API update.
	err := resolveMACs(ctx, networkCfg)
	if err != nil {
		return err
	}

	// Validate the new network configuration before proceeding.
	err = ValidateNetworkConfiguration(networkCfg, true)
	if err != nil {
		return err
	}

	// Delete any interfaces, bonds, or vlans that currently exist but don't in
	// the new configuration, or have a different configuration.
	err = cleanupStaleDevices(ctx, s.System.Network.Config, networkCfg)
	if err != nil {
		return err
	}

	// Determine if any new physical devices (starting with "_p") will be added. Later
	// after generating the new network configuration files we will need to wait until
	// the new devices are properly renamed by udev.
	expectedNewPhysicalDevices := getExpectedNewPhysicalDevices(ctx, networkCfg)

	// Update the state before (re)generating networking configuration.
	s.System.Network.Config = networkCfg

	// Apply the configured hostname, or reset back to default if not set.
	err = SetHostname(ctx, s.Hostname())
	if err != nil {
		return err
	}

	// Configure and startup the local proxy daemon.
	err = proxy.StartLocalProxy(ctx, networkCfg.Proxy)
	if err != nil {
		return err
	}

	err = generateNetworkConfiguration(ctx, networkCfg)
	if err != nil {
		return err
	}

	err = generateHosts(ctx, s)
	if err != nil {
		return err
	}

	err = waitForUdevInterfaceRename(ctx, expectedNewPhysicalDevices, 5*time.Second)
	if err != nil {
		return err
	}

	// Restart networking after new config files have been generated.
	err = RestartUnit(ctx, "systemd-networkd")
	if err != nil {
		return err
	}

	// Wait for the network to apply.
	err = waitForNetworkOnline(ctx, networkCfg, timeout)
	if err != nil {
		return err
	}

	// Wait for DNS to be functional.
	err = waitForDNS(ctx, timeout)
	if err != nil {
		if !allowPartialConfig {
			return err
		}

		slog.WarnContext(ctx, "DNS check failed, system may have trouble resolving hostnames")
	}

	// (Re)start NTP time synchronization. Since we might be overriding the default fallback NTP servers,
	// the service is disabled by default and only started once we have performed the network (re)configuration.
	err = RestartUnit(ctx, "systemd-timesyncd")
	if err != nil {
		return err
	}

	// Wait up to 30 seconds for NTP synchronization, but don't fail if it doesn't happen.
	err = waitForSystemdTimesyncd(ctx, 30*time.Second)
	if err != nil {
		slog.WarnContext(ctx, "systemd-timesyncd failed to perform NTP synchronization, system time may be incorrect")
	}

	// Refresh the state struct.
	err = UpdateNetworkState(ctx, &s.System.Network)
	if err != nil {
		return err
	}

	// Refresh registration.
	if refresh != nil {
		err := refresh(ctx, s)
		if err != nil {
			slog.WarnContext(ctx, "Failed to refresh provider registration", "err", err)
		}
	}

	return nil
}

// ValidateNetworkConfiguration performs some basic validation checks on the supplied network configuration.
func ValidateNetworkConfiguration(networkCfg *api.SystemNetworkConfig, requireValidMAC bool) error {
	if networkCfg == nil {
		return errors.New("no network configuration provided")
	}

	// Check that all interface/bond/vlan names are unique.
	names := []string{}
	for _, iface := range networkCfg.Interfaces {
		if slices.Contains(names, iface.Name) {
			return errors.New("duplicate interface/bond/vlan name: " + iface.Name)
		}

		names = append(names, iface.Name)
	}

	for _, bond := range networkCfg.Bonds {
		if slices.Contains(names, bond.Name) {
			return errors.New("duplicate interface/bond/vlan name: " + bond.Name)
		}

		names = append(names, bond.Name)
	}

	for _, vlan := range networkCfg.VLANs {
		if slices.Contains(names, vlan.Name) {
			return errors.New("duplicate interface/bond/vlan name: " + vlan.Name)
		}

		names = append(names, vlan.Name)
	}

	err := validateInterfaces(networkCfg.Interfaces, requireValidMAC)
	if err != nil {
		return err
	}

	err = validateBonds(networkCfg.Bonds, requireValidMAC)
	if err != nil {
		return err
	}

	err = validateVLANs(networkCfg)
	if err != nil {
		return err
	}

	return nil
}

// UpdateNetworkState updates the network state within the SystemNetwork struct.
func UpdateNetworkState(ctx context.Context, n *api.SystemNetwork) error {
	var err error

	if n.Config == nil {
		return errors.New("no network configuration defined")
	}

	// Clear any existing state.
	n.State = api.SystemNetworkState{
		Interfaces: make(map[string]api.SystemNetworkInterfaceState),
	}

	// Keep track of all the roles being applied.
	rolesFound := []string{}

	// State update for interfaces.
	for _, i := range n.Config.Interfaces {
		iState, err := getInterfaceState(ctx, "interface", i.Name, i.Hwaddr, "", nil)
		if err != nil {
			return err
		}

		iState.Roles = i.Roles
		rolesFound = append(rolesFound, i.Roles...)
		n.State.Interfaces[i.Name] = iState
	}

	// State update for bonds.
	for _, b := range n.Config.Bonds {
		members := make(map[string]api.SystemNetworkInterfaceState)

		for _, m := range b.Members {
			mName := "_p" + strings.ToLower(strings.ReplaceAll(m, ":", ""))

			members[mName], err = getInterfaceState(ctx, "bond_member", mName, m, "", nil)
			if err != nil {
				return err
			}
		}

		bState, err := getInterfaceState(ctx, "bond", b.Name, b.Hwaddr, "", members)
		if err != nil {
			return err
		}

		bState.Roles = b.Roles
		rolesFound = append(rolesFound, b.Roles...)
		n.State.Interfaces[b.Name] = bState
	}

	// State update for vlans.
	for _, v := range n.Config.VLANs {
		hwaddr := ""

		parent, ok := n.State.Interfaces[v.Parent]
		if ok {
			hwaddr = parent.Hwaddr
		}

		vState, err := getInterfaceState(ctx, "vlan", v.Name, hwaddr, v.Parent, nil)
		if err != nil {
			return err
		}

		vState.Roles = v.Roles
		rolesFound = append(rolesFound, v.Roles...)
		n.State.Interfaces[v.Name] = vState
	}

	// Ensure required roles exist.
	if !slices.Contains(rolesFound, api.SystemNetworkInterfaceRoleManagement) || !slices.Contains(rolesFound, api.SystemNetworkInterfaceRoleCluster) {
		for iName, i := range n.State.Interfaces {
			iState := i

			if !slices.Contains(rolesFound, api.SystemNetworkInterfaceRoleManagement) && iState.State == "routable" {
				if iState.Roles == nil {
					iState.Roles = []string{}
				}

				iState.Roles = append(iState.Roles, api.SystemNetworkInterfaceRoleManagement)
			}

			if !slices.Contains(rolesFound, api.SystemNetworkInterfaceRoleCluster) && slices.Contains(iState.Roles, api.SystemNetworkInterfaceRoleManagement) {
				iState.Roles = append(iState.Roles, api.SystemNetworkInterfaceRoleCluster)
			}

			n.State.Interfaces[iName] = iState
		}
	}

	return nil
}

// getInterfaceState runs various commands to gather network state for a specific interface.
func getInterfaceState(ctx context.Context, ifaceType string, iface string, hwaddr string, parent string, members map[string]api.SystemNetworkInterfaceState) (api.SystemNetworkInterfaceState, error) {
	// Get IPs for the interface.
	ips, err := GetIPAddresses(ctx, iface)
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	// Get routes for the interface.
	routes := []api.SystemNetworkRoute{}
	routeRegex := regexp.MustCompile(`(.+) via (.+) proto`)

	output, err := subprocess.RunCommandContext(ctx, "ip", "route", "show", "dev", resolveBridge(iface))
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	for _, r := range routeRegex.FindAllStringSubmatch(output, -1) {
		routes = append(routes, api.SystemNetworkRoute{
			To:  r[1],
			Via: r[2],
		})
	}

	// Get various details from networkctl. It would be better to use the json output
	// option, but that doesn't include everything we're interested in.
	output, err = subprocess.RunCommandContext(ctx, "networkctl", "status", "-s", resolveBridge(iface))
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	interfaceStateRegex := regexp.MustCompile(`State: (.+?) `)

	interfaceState := ""
	if len(interfaceStateRegex.FindStringSubmatch(output)) == 2 {
		interfaceState = interfaceStateRegex.FindStringSubmatch(output)[1]
	}

	localMACRegex := regexp.MustCompile(`  Hardware Address: (.+)`)

	localMAC := ""
	if len(localMACRegex.FindStringSubmatch(output)) == 2 {
		localMAC = strings.Fields(localMACRegex.FindStringSubmatch(output)[1])[0]
	}

	remoteMACRegex := regexp.MustCompile(`Permanent Hardware Address: (.+)`)

	remoteMAC := ""
	if len(remoteMACRegex.FindStringSubmatch(output)) == 2 {
		remoteMAC = strings.Fields(remoteMACRegex.FindStringSubmatch(output)[1])[0]
	}

	mtuRegex := regexp.MustCompile(`MTU: (.+?) `)

	mtu, err := strconv.Atoi(mtuRegex.FindStringSubmatch(output)[1])
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	rxBytesRegex := regexp.MustCompile(`Rx Bytes: (.+)`)

	rxBytes, err := strconv.Atoi(rxBytesRegex.FindStringSubmatch(output)[1])
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	txBytesRegex := regexp.MustCompile(`Tx Bytes: (.+)`)

	txBytes, err := strconv.Atoi(txBytesRegex.FindStringSubmatch(output)[1])
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	rxErrorsRegex := regexp.MustCompile(`Rx Errors: (.+)`)

	rxErrors, err := strconv.Atoi(rxErrorsRegex.FindStringSubmatch(output)[1])
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	txErrorsRegex := regexp.MustCompile(`Tx Errors: (.+)`)

	txErrors, err := strconv.Atoi(txErrorsRegex.FindStringSubmatch(output)[1])
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	// Get the actual underlying device's speed; querying the veth device always
	// returns 10Gbps. Interfaces, bond members, and vlans directly on an interface
	// look at the actual device, while bonds and vlans on a bond look at the bond
	// device.
	var underlyingDevice string

	switch ifaceType {
	case "interface", "bond_member":
		underlyingDevice = "_p" + strings.ToLower(strings.ReplaceAll(hwaddr, ":", ""))
	case "bond":
		underlyingDevice = iface
	case "vlan":
		if hwaddr == "" {
			underlyingDevice = parent
		} else {
			underlyingDevice = "_p" + strings.ToLower(strings.ReplaceAll(hwaddr, ":", ""))
		}
	default:
		return api.SystemNetworkInterfaceState{}, errors.New("unknown interface type '" + ifaceType + "' for interface " + iface)
	}

	// #nosec G304
	contents, err := os.ReadFile("/sys/class/net/" + underlyingDevice + "/speed")
	if err != nil {
		return api.SystemNetworkInterfaceState{}, err
	}

	speed := strings.TrimSuffix(string(contents), "\n")

	// Fetch any LLDP info.
	lldp := []api.SystemNetworkLLDPState{}

	if ifaceType == "interface" || ifaceType == "bond_member" {
		lldpIface := iface
		if ifaceType == "interface" {
			lldpIface = "_p" + strings.ToLower(strings.ReplaceAll(localMAC, ":", ""))
		}

		lldp, err = getLLDPInfo(ctx, lldpIface)
		if err != nil {
			return api.SystemNetworkInterfaceState{}, err
		}
	}

	// Get LACP info for a bond member.
	var lacp *api.SystemNetworkLACPState
	if ifaceType == "bond_member" {
		lacp = &api.SystemNetworkLACPState{
			LocalMAC:  localMAC,
			RemoteMAC: remoteMAC,
		}
	}

	return api.SystemNetworkInterfaceState{
		Type:      ifaceType,
		Addresses: ips,
		Hwaddr:    hwaddr,
		Routes:    routes,
		MTU:       mtu,
		Speed:     speed,
		State:     interfaceState,
		Stats: api.SystemNetworkInterfaceStats{
			RXBytes:  rxBytes,
			TXBytes:  txBytes,
			RXErrors: rxErrors,
			TXErrors: txErrors,
		},
		LLDP:    lldp,
		LACP:    lacp,
		Members: members,
	}, nil
}

// When dealing with a bridge, we can't just get its IP address or route. So,
// determine the "main" member corresponding to the physical NIC and return that
// device name instead. If the device isn't a bridge, return the original name
// unmodified.
func resolveBridge(iface string) string {
	_, err := os.ReadDir("/sys/class/net/" + iface + "/brif")
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return iface
	}

	return "_v" + iface
}

// GetIPAddresses returns any non-link-local address for an interface.
func GetIPAddresses(ctx context.Context, iface string) ([]string, error) {
	ipAddressRegex := regexp.MustCompile(`inet6? (.+)/\d+ `)

	output, err := subprocess.RunCommandContext(ctx, "ip", "address", "show", resolveBridge(iface))
	if err != nil {
		return nil, err
	}

	ret := []string{}
	matches := ipAddressRegex.FindAllStringSubmatch(output, -1)

	for _, addr := range matches {
		// Don't count link-local addresses.
		if strings.HasPrefix(addr[1], "169.254.") || strings.HasPrefix(addr[1], "fe80:") {
			continue
		}

		ret = append(ret, addr[1])
	}

	return ret, nil
}

// getLLDPInfo returns current LLDP information for the interface's underlying physical device.
func getLLDPInfo(ctx context.Context, iface string) ([]api.SystemNetworkLLDPState, error) {
	output, err := subprocess.RunCommandContext(ctx, "networkctl", "lldp", "--json=short", resolveBridge(iface))
	if err != nil {
		return nil, err
	}

	type lldpStruct struct {
		Neighbors []struct {
			InterfaceName string `json:"InterfaceName"` //nolint:tagliatelle
			Neighbors     []struct {
				SystemName      string `json:"SystemName"`      //nolint:tagliatelle
				ChassisID       string `json:"ChassisID"`       //nolint:tagliatelle
				PortID          string `json:"PortID"`          //nolint:tagliatelle
				PortDescription string `json:"PortDescription"` //nolint:tagliatelle
			} `json:"Neighbors"` //nolint:tagliatelle
		} `json:"Neighbors"` //nolint:tagliatelle
	}

	lldp := lldpStruct{}

	err = json.Unmarshal([]byte(output), &lldp)
	if err != nil {
		return nil, err
	}

	if len(lldp.Neighbors) == 0 {
		return nil, nil
	}

	ret := []api.SystemNetworkLLDPState{}
	for _, n := range lldp.Neighbors[0].Neighbors {
		ret = append(ret, api.SystemNetworkLLDPState{
			Name:      n.SystemName,
			ChassisID: n.ChassisID,
			PortID:    n.PortID,
			Port:      n.PortDescription,
		})
	}

	return ret, nil
}

func generateHosts(_ context.Context, s *state.State) error {
	// Generate the /etc/hosts file.
	return os.WriteFile("/etc/hosts", []byte(fmt.Sprintf(`127.0.0.1	localhost
127.0.1.1	%s

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
`, s.Hostname())), 0o644)
}

// generateNetworkConfiguration clears any existing configuration from /run/systemd/network/ and generates
// new config files from the supplied NetworkConfig struct.
func generateNetworkConfiguration(_ context.Context, networkCfg *api.SystemNetworkConfig) error {
	// Remove any existing configuration.
	err := os.RemoveAll(SystemdNetworkConfigPath)
	if err != nil {
		return err
	}

	err = os.Mkdir(SystemdNetworkConfigPath, 0o755)
	if err != nil {
		return err
	}

	// Generate .link files.
	for _, cfg := range generateLinkFileContents(*networkCfg) {
		err := os.WriteFile(filepath.Join(SystemdNetworkConfigPath, cfg.Name), []byte(cfg.Contents), 0o644)
		if err != nil {
			return err
		}
	}

	// Generate .netdev files.
	for _, cfg := range generateNetdevFileContents(*networkCfg) {
		err := os.WriteFile(filepath.Join(SystemdNetworkConfigPath, cfg.Name), []byte(cfg.Contents), 0o644)
		if err != nil {
			return err
		}
	}

	// Generate .network files.
	for _, cfg := range generateNetworkFileContents(*networkCfg) {
		err := os.WriteFile(filepath.Join(SystemdNetworkConfigPath, cfg.Name), []byte(cfg.Contents), 0o644)
		if err != nil {
			return err
		}
	}

	// Generate systemd-timesyncd configuration if any timeservers are defined.
	ntpCfg := ""
	if networkCfg.NTP != nil {
		ntpCfg = generateTimesyncContents(*networkCfg.NTP)

		if ntpCfg != "" {
			err := os.WriteFile(SystemdTimesyncConfigFile, []byte(ntpCfg), 0o644)
			if err != nil {
				return err
			}
		}
	}

	// If there's no NTP configuration, remove the old config file that might exist.
	if networkCfg.NTP == nil || ntpCfg == "" {
		_ = os.Remove(SystemdTimesyncConfigFile)
	}

	return nil
}

// waitForUdevInterfaceRename waits up to a provided timeout for udev to pickup and process
// the renaming of interfaces. At system startup there's a small race between udev being fully
// started and our reconfiguring of the network, so we poll in a loop until we see the kernel
// has been notified of the rename.
func waitForUdevInterfaceRename(ctx context.Context, expectedInterfaces []string, timeout time.Duration) error {
	endTime := time.Now().Add(timeout)

	for {
		if time.Now().After(endTime) {
			return errors.New("timed out waiting for udev to rename interface(s)")
		}

		// Trigger udev rule update to pickup device names.
		_, err := subprocess.RunCommandContext(ctx, "udevadm", "trigger", "--action=add")
		if err != nil {
			return err
		}

		// Wait for udev to be done processing the events.
		_, err = subprocess.RunCommandContext(ctx, "udevadm", "settle")
		if err != nil {
			return err
		}

		allDevicesRenamed := true

		// Check if the kernel has noticed the renaming of each of the expected
		// interfaces to the "_p<MAC address>" format.
		for _, iface := range expectedInterfaces {
			_, err = subprocess.RunCommandContext(ctx, "journalctl", "--since", "10 seconds ago", "-t", "kernel", "-g", iface+": renamed from ")
			if err != nil {
				allDevicesRenamed = false

				break
			}
		}

		if allDevicesRenamed {
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// waitForNetworkOnline waits up to a provided timeout for configured network interfaces,
// bonds, and vlans to configure their IP address(es) and come online.
func waitForNetworkOnline(ctx context.Context, networkCfg *api.SystemNetworkConfig, timeout time.Duration) error {
	isOnline := func(name string) (bool, bool) {
		output, err := subprocess.RunCommandContext(ctx, "networkctl", "status", resolveBridge(name))
		if err != nil {
			return false, true
		}

		return strings.Contains(output, "Online state: online"), strings.Contains(output, "Required For Online: yes")
	}

	hasAtLeastOneConfiguredIP := func(iface string) bool {
		ips, _ := GetIPAddresses(ctx, iface)

		return len(ips) > 0
	}

	endTime := time.Now().Add(timeout)

	devicesToCheck := []string{}

	for _, i := range networkCfg.Interfaces {
		if len(i.Addresses) == 0 {
			continue
		}

		devicesToCheck = append(devicesToCheck, i.Name)
	}

	for _, b := range networkCfg.Bonds {
		if len(b.Addresses) == 0 {
			continue
		}

		devicesToCheck = append(devicesToCheck, b.Name)
	}

	for _, v := range networkCfg.VLANs {
		if len(v.Addresses) == 0 {
			continue
		}

		devicesToCheck = append(devicesToCheck, v.Name)
	}

	for {
		if time.Now().After(endTime) {
			return errors.New("timed out waiting for network to come online")
		}

		allDevicesOnline := true

		for _, name := range devicesToCheck {
			online, requiredOnline := isOnline(name)
			if !requiredOnline {
				continue
			}

			if !online || !hasAtLeastOneConfiguredIP(name) {
				allDevicesOnline = false

				break
			}
		}

		if allDevicesOnline {
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// waitForDNS waits up to a provided timeout for the system to be able to resolve DNS records.
func waitForDNS(ctx context.Context, timeout time.Duration) error {
	endTime := time.Now().Add(timeout)
	resolver := net.Resolver{}

	for {
		if time.Now().After(endTime) {
			return errors.New("timed out waiting for DNS to respond")
		}

		ips, err := resolver.LookupIPAddr(ctx, "linuxcontainers.org")
		if err == nil && len(ips) > 0 {
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// waitForSystemdTimesyncd waits up to a provided timeout for systemd-timesyncd to
// perform an initial NTP synchronization.
func waitForSystemdTimesyncd(ctx context.Context, timeout time.Duration) error {
	endTime := time.Now().Add(timeout)

	for {
		if time.Now().After(endTime) {
			return errors.New("timed out waiting for NTP synchronization")
		}

		// Check if systemd-timesyncd has performed its initial synchronization.
		_, err := subprocess.RunCommandContext(ctx, "journalctl", "--since", "10 seconds ago", "-u", "systemd-timesyncd", "-g", "Initial clock synchronization")
		if err == nil {
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// generateLinkFileContents generates the contents of systemd.link files. Returns an array of ConfigFile structs.
// https://www.freedesktop.org/software/systemd/man/latest/systemd.link.html
func generateLinkFileContents(networkCfg api.SystemNetworkConfig) []networkdConfigFile {
	ret := []networkdConfigFile{}

	for _, i := range networkCfg.Interfaces {
		strippedHwaddr := strings.ToLower(strings.ReplaceAll(i.Hwaddr, ":", ""))
		ret = append(ret, networkdConfigFile{
			Name: fmt.Sprintf("00-_p%s.link", strippedHwaddr),
			Contents: fmt.Sprintf(`[Match]
PermanentMACAddress=%s

[Link]
MACAddressPolicy=random
NamePolicy=
Name=_p%s
`, i.Hwaddr, strippedHwaddr),
		})
	}

	for _, b := range networkCfg.Bonds {
		for _, member := range b.Members {
			strippedHwaddr := strings.ToLower(strings.ReplaceAll(member, ":", ""))
			ret = append(ret, networkdConfigFile{
				Name: fmt.Sprintf("01-_p%s.link", strippedHwaddr),
				Contents: fmt.Sprintf(`[Match]
PermanentMACAddress=%s

[Link]
NamePolicy=
Name=_p%s
`, member, strippedHwaddr),
			})
		}
	}

	return ret
}

// generateNetdevFileContents generates the contents of systemd.netdev files. Returns an array of networkdConfigFile structs.
// https://www.freedesktop.org/software/systemd/man/latest/systemd.netdev.html
func generateNetdevFileContents(networkCfg api.SystemNetworkConfig) []networkdConfigFile {
	ret := []networkdConfigFile{}

	// Create bridge and veth devices for each interface.
	for _, i := range networkCfg.Interfaces {
		mtuString := ""
		if i.MTU != 0 {
			mtuString = fmt.Sprintf("MTUBytes=%d", i.MTU)
		}

		// Bridge.
		ret = append(ret, networkdConfigFile{
			Name: fmt.Sprintf("10-%s.netdev", i.Name),
			Contents: fmt.Sprintf(`[NetDev]
Name=%s
Kind=bridge
%s

[Bridge]
VLANFiltering=true
`, i.Name, mtuString),
		})

		// veth.
		strippedHwaddr := strings.ToLower(strings.ReplaceAll(i.Hwaddr, ":", ""))
		ret = append(ret, networkdConfigFile{
			Name: fmt.Sprintf("10-_v%s.netdev", i.Name),
			Contents: fmt.Sprintf(`[NetDev]
Name=_v%s
Kind=veth
MACAddress=%s
%s

[Peer]
Name=_i%s
`, i.Name, i.Hwaddr, mtuString, strippedHwaddr),
		})
	}

	// Create bond, bridge, and veth devices for each bond.
	for _, b := range networkCfg.Bonds {
		mtuString := ""
		if b.MTU != 0 {
			mtuString = fmt.Sprintf("MTUBytes=%d", b.MTU)
		}

		// Bond.
		ret = append(ret, networkdConfigFile{
			Name: fmt.Sprintf("11-_b%s.netdev", b.Name),
			Contents: fmt.Sprintf(`[NetDev]
Name=_b%s
Kind=bond
%s

[Bond]
Mode=%s
`, b.Name, mtuString, b.Mode),
		})

		// Bridge.
		ret = append(ret, networkdConfigFile{
			Name: fmt.Sprintf("11-%s.netdev", b.Name),
			Contents: fmt.Sprintf(`[NetDev]
Name=%s
Kind=bridge
%s

[Bridge]
VLANFiltering=true
`, b.Name, mtuString),
		})

		// veth.
		bondMacAddr := b.Hwaddr
		if bondMacAddr == "" {
			bondMacAddr = b.Members[0]
		}

		strippedHwaddr := strings.ToLower(strings.ReplaceAll(bondMacAddr, ":", ""))
		ret = append(ret, networkdConfigFile{
			Name: fmt.Sprintf("11-_v%s.netdev", b.Name),
			Contents: fmt.Sprintf(`[NetDev]
Name=_v%s
Kind=veth
MACAddress=%s
%s

[Peer]
Name=_i%s
`, b.Name, bondMacAddr, mtuString, strippedHwaddr),
		})
	}

	// Create vlans.
	for _, v := range networkCfg.VLANs {
		mtuString := ""
		if v.MTU != 0 {
			mtuString = fmt.Sprintf("MTUBytes=%d", v.MTU)
		}

		ret = append(ret, networkdConfigFile{
			Name: fmt.Sprintf("12-%s.netdev", v.Name),
			Contents: fmt.Sprintf(`[NetDev]
Name=%s
Kind=vlan
%s

[VLAN]
Id=%d
`, v.Name, mtuString, v.ID),
		})
	}

	return ret
}

// generateNetworkFileContents generates the contents of systemd.network files. Returns an array of networkdConfigFile structs.
// https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html
func generateNetworkFileContents(networkCfg api.SystemNetworkConfig) []networkdConfigFile {
	ret := []networkdConfigFile{}

	// Create networks for each interface and its bridge.
	for _, i := range networkCfg.Interfaces {
		// User side of veth device.
		cfgString := fmt.Sprintf(`[Match]
Name=_v%s

[Link]
%s

[DHCP]
ClientIdentifier=mac
RouteMetric=100
UseMTU=true

[Network]
%s`, i.Name, generateLinkSectionContents(i.Addresses, i.RequiredForOnline), generateNetworkSectionContents(i.Name, networkCfg.VLANs, networkCfg.DNS, networkCfg.NTP))

		cfgString += processAddresses(i.Addresses)

		if len(i.Routes) > 0 {
			cfgString += processRoutes(i.Routes)
		}

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("20-_v%s.network", i.Name),
			Contents: cfgString,
		})

		// Bridge side of veth device.
		strippedHwaddr := strings.ToLower(strings.ReplaceAll(i.Hwaddr, ":", ""))
		cfgString = fmt.Sprintf(`[Match]
Name=_i%s

[Network]
Bridge=%s
`, strippedHwaddr, i.Name)

		cfgString += generateVLANContents(i.Name, i.VLANTags, networkCfg.VLANs)

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("20-_i%s.network", strippedHwaddr),
			Contents: cfgString,
		})

		// Add underlying interface to bridge.
		cfgString = fmt.Sprintf(`[Match]
Name=_p%s

[Network]
LLDP=%s
EmitLLDP=%s
Bridge=%s
`, strippedHwaddr, strconv.FormatBool(i.LLDP), strconv.FormatBool(i.LLDP), i.Name)

		cfgString += generateVLANContents(i.Name, i.VLANTags, networkCfg.VLANs)

		if i.MTU != 0 {
			cfgString += fmt.Sprintf("[Link]\nMTUBytes=%d\n", i.MTU)
		}

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("20-_p%s.network", strippedHwaddr),
			Contents: cfgString,
		})

		// Bridge.
		cfgString = fmt.Sprintf(`[Match]
Name=%s

[Network]
LinkLocalAddressing=no
ConfigureWithoutCarrier=yes
`, i.Name)

		if i.MTU != 0 {
			cfgString += fmt.Sprintf("[Link]\nMTUBytes=%d\n", i.MTU)
		}

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("20-%s.network", i.Name),
			Contents: cfgString,
		})
	}

	// Create networks for each bond, its member(s), and its bridge.
	for _, b := range networkCfg.Bonds {
		// User side of veth device.
		cfgString := fmt.Sprintf(`[Match]
Name=_v%s

[Link]
%s

[DHCP]
ClientIdentifier=mac
RouteMetric=100
UseMTU=true

[Network]
%s`, b.Name, generateLinkSectionContents(b.Addresses, b.RequiredForOnline), generateNetworkSectionContents(b.Name, networkCfg.VLANs, networkCfg.DNS, networkCfg.NTP))

		cfgString += processAddresses(b.Addresses)

		if len(b.Routes) > 0 {
			cfgString += processRoutes(b.Routes)
		}

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("21-_v%s.network", b.Name),
			Contents: cfgString,
		})

		// Bridge side of veth device.
		bondMacAddr := b.Hwaddr
		if bondMacAddr == "" {
			bondMacAddr = b.Members[0]
		}

		strippedHwaddr := strings.ToLower(strings.ReplaceAll(bondMacAddr, ":", ""))

		cfgString = fmt.Sprintf(`[Match]
Name=_i%s

[Network]
Bridge=%s
`, strippedHwaddr, b.Name)

		cfgString += generateVLANContents(b.Name, b.VLANTags, networkCfg.VLANs)

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("21-_i%s.network", strippedHwaddr),
			Contents: cfgString,
		})

		// Add bond to bridge.
		cfgString = fmt.Sprintf(`[Match]
Name=_b%s

[Network]
LinkLocalAddressing=no
ConfigureWithoutCarrier=yes
Bridge=%s
`, b.Name, b.Name)

		cfgString += generateVLANContents(b.Name, b.VLANTags, networkCfg.VLANs)

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("21-_b%s.network", b.Name),
			Contents: cfgString,
		})

		// Bridge.
		cfgString = fmt.Sprintf(`[Match]
Name=%s

[Network]
LinkLocalAddressing=no
ConfigureWithoutCarrier=yes
`, b.Name)

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("21-%s.network", b.Name),
			Contents: cfgString,
		})

		// Bond members.
		for index, member := range b.Members {
			memberStrippedHwaddr := strings.ToLower(strings.ReplaceAll(member, ":", ""))

			ret = append(ret, networkdConfigFile{
				Name: fmt.Sprintf("21-_b%s-dev%d.network", b.Name, index),
				Contents: fmt.Sprintf(`[Match]
Name=_p%s

[Network]
LLDP=%s
EmitLLDP=%s
Bond=_b%s
`, memberStrippedHwaddr, strconv.FormatBool(b.LLDP), strconv.FormatBool(b.LLDP), b.Name),
			})
		}
	}

	// Create network for each VLAN.
	for _, v := range networkCfg.VLANs {
		cfgString := fmt.Sprintf(`[Match]
Name=%s

[Link]
%s

[DHCP]
ClientIdentifier=mac
RouteMetric=100
UseMTU=true

[Network]
%s`, v.Name, generateLinkSectionContents(v.Addresses, v.RequiredForOnline), generateNetworkSectionContents(v.Name, nil, networkCfg.DNS, networkCfg.NTP))

		cfgString += processAddresses(v.Addresses)

		if len(v.Routes) > 0 {
			cfgString += processRoutes(v.Routes)
		}

		ret = append(ret, networkdConfigFile{
			Name:     fmt.Sprintf("22-%s.network", v.Name),
			Contents: cfgString,
		})
	}

	return ret
}

func processAddresses(addresses []string) string {
	ret := ""
	if len(addresses) != 0 {
		ret += "LinkLocalAddressing=ipv6\n"
	} else {
		ret += "LinkLocalAddressing=no\n"
		ret += "ConfigureWithoutCarrier=yes\n"
	}

	hasDHCP4 := false
	hasDHCP6 := false
	acceptIPv6RA := false

	for _, addr := range addresses {
		switch addr {
		case "dhcp4":
			hasDHCP4 = true
		case "dhcp6":
			hasDHCP6 = true
		case "slaac":
			acceptIPv6RA = true

		default:
			ret += fmt.Sprintf("Address=%s\n", addr)
		}
	}

	if acceptIPv6RA {
		ret += "IPv6AcceptRA=true\n"
	} else {
		ret += "IPv6AcceptRA=false\n"
	}

	if hasDHCP4 && hasDHCP6 { //nolint:gocritic
		ret += "DHCP=yes\n"
	} else if hasDHCP4 {
		ret += "DHCP=ipv4\n"
	} else if hasDHCP6 {
		ret += "DHCP=ipv6\n"
	}

	return ret
}

func processRoutes(routes []api.SystemNetworkRoute) string {
	ret := ""

	for _, route := range routes {
		ret += "\n[Route]\n"

		switch route.Via {
		case "dhcp4":
			ret += "Gateway=_dhcp4\n"
		case "slaac":
			ret += "Gateway=_ipv6ra\n"
		default:
			ret += fmt.Sprintf("Gateway=%s\n", route.Via)
		}

		ret += fmt.Sprintf("Destination=%s\n", route.To)
	}

	return ret
}

func generateNetworkSectionContents(name string, vlans []api.SystemNetworkVLAN, dns *api.SystemNetworkDNS, ntp *api.SystemNetworkNTP) string {
	ret := ""

	// Add any matching VLANs to the config.
	for _, v := range vlans {
		if v.Parent == name {
			ret += fmt.Sprintf("VLAN=%s\n", v.Name)
		}
	}

	// If there are search domains or name servers, add those to the config.
	if dns != nil {
		if len(dns.SearchDomains) > 0 {
			ret += fmt.Sprintf("Domains=%s\n", strings.Join(dns.SearchDomains, " "))
		}

		for _, ns := range dns.Nameservers {
			ret += fmt.Sprintf("DNS=%s\n", ns)
		}
	}

	// If there are time servers defined, add them to the config.
	if ntp != nil {
		for _, ts := range ntp.Timeservers {
			ret += fmt.Sprintf("NTP=%s\n", ts)
		}
	}

	return ret
}

func generateTimesyncContents(ntp api.SystemNetworkNTP) string {
	if len(ntp.Timeservers) == 0 {
		return ""
	}

	return "[Time]\nFallbackNTP=" + strings.Join(ntp.Timeservers, " ") + "\n"
}

func generateVLANContents(devName string, additionalVLANTags []int, vlans []api.SystemNetworkVLAN) string {
	vlanTags := []int{}

	// Add any additional VLAN tags.
	vlanTags = append(vlanTags, additionalVLANTags...)

	// Grab any relevant tags for this device from VLAN definitions.
	for _, vlan := range vlans {
		if vlan.Parent == devName {
			vlanTags = append(vlanTags, vlan.ID)

			break
		}
	}

	// Sort and remove any duplicate tags.
	slices.Sort(vlanTags)
	vlanTags = slices.Compact(vlanTags)

	ret := ""

	if len(vlanTags) > 0 {
		for _, tag := range vlanTags {
			ret += "\n[BridgeVLAN]\n"
			ret += fmt.Sprintf("VLAN=%d\n", tag)
		}
	}

	return ret
}

func generateLinkSectionContents(addresses []string, requiredForOnline string) string {
	if len(addresses) == 0 || requiredForOnline == "no" {
		return "RequiredForOnline=no"
	}

	if requiredForOnline == "" {
		requiredForOnline = "any"
	}

	return "RequiredForOnline=yes\nRequiredFamilyForOnline=" + requiredForOnline
}

func cleanupStaleDevices(ctx context.Context, oldCfg *api.SystemNetworkConfig, newCfg *api.SystemNetworkConfig) error {
	// Check for changed/deleted interfaces.
	for oldIndex := range oldCfg.Interfaces {
		newIndex := slices.IndexFunc(newCfg.Interfaces, func(i api.SystemNetworkInterface) bool {
			return oldCfg.Interfaces[oldIndex].Name == i.Name
		})

		// If not found, remove the existing interface (either deleted, or the device is now a bond or vlan).
		if newIndex < 0 {
			deleteNetworkDevice(ctx, "_v"+oldCfg.Interfaces[oldIndex].Name, oldCfg.Interfaces[oldIndex].Name)

			continue
		}

		// Check if the interface's configuration has changed.
		oldConfig, err := json.Marshal(oldCfg.Interfaces[oldIndex])
		if err != nil {
			return err
		}

		newConfig, err := json.Marshal(newCfg.Interfaces[newIndex])
		if err != nil {
			return err
		}

		if !bytes.Equal(oldConfig, newConfig) {
			deleteNetworkDevice(ctx, "_v"+oldCfg.Interfaces[oldIndex].Name, oldCfg.Interfaces[oldIndex].Name)

			continue
		}
	}

	// Check for changed/deleted bonds.
	for oldIndex := range oldCfg.Bonds {
		newIndex := slices.IndexFunc(newCfg.Bonds, func(b api.SystemNetworkBond) bool {
			return oldCfg.Bonds[oldIndex].Name == b.Name
		})

		// If not found, remove the existing bond (either deleted, or the device is now an interface or vlan).
		if newIndex < 0 {
			deleteNetworkDevice(ctx, "_b"+oldCfg.Bonds[oldIndex].Name, "_v"+oldCfg.Bonds[oldIndex].Name, oldCfg.Bonds[oldIndex].Name)

			continue
		}

		// Check if the bond's configuration has changed.
		oldConfig, err := json.Marshal(oldCfg.Bonds[oldIndex])
		if err != nil {
			return err
		}

		newConfig, err := json.Marshal(newCfg.Bonds[newIndex])
		if err != nil {
			return err
		}

		if !bytes.Equal(oldConfig, newConfig) {
			deleteNetworkDevice(ctx, "_b"+oldCfg.Bonds[oldIndex].Name, "_v"+oldCfg.Bonds[oldIndex].Name, oldCfg.Bonds[oldIndex].Name)

			continue
		}
	}

	// Check for changed/deleted vlans.
	for oldIndex := range oldCfg.VLANs {
		newIndex := slices.IndexFunc(newCfg.VLANs, func(v api.SystemNetworkVLAN) bool {
			return oldCfg.VLANs[oldIndex].Name == v.Name
		})

		// If not found, remove the existing vlan (either deleted, or the device is now an interface or bond).
		if newIndex < 0 {
			deleteNetworkDevice(ctx, oldCfg.VLANs[oldIndex].Name)

			continue
		}

		// Check if the vlan's configuration has changed.
		oldConfig, err := json.Marshal(oldCfg.VLANs[oldIndex])
		if err != nil {
			return err
		}

		newConfig, err := json.Marshal(newCfg.VLANs[newIndex])
		if err != nil {
			return err
		}

		if !bytes.Equal(oldConfig, newConfig) {
			deleteNetworkDevice(ctx, oldCfg.VLANs[oldIndex].Name)

			continue
		}
	}

	return nil
}

func deleteNetworkDevice(ctx context.Context, devices ...string) {
	for _, dev := range devices {
		// Ignore errors; when deconstructing a complex network setup we may have already
		// removed one end of a shared device, and we don't want to error out if we fail to
		// remove the other end.
		_, _ = subprocess.RunCommandContext(ctx, "networkctl", "delete", dev)
	}
}

// resolveMACs attempts to resolve any non-MAC looking value to a MAC address by treating the
// value of an interface name and attempting to query its MAC.
func resolveMACs(ctx context.Context, config *api.SystemNetworkConfig) error {
	hwaddrhRegex := regexp.MustCompile(`^[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}$`)

	for i := range len(config.Interfaces) {
		if !hwaddrhRegex.MatchString(config.Interfaces[i].Hwaddr) {
			hwaddr, err := getMacForInterface(ctx, config.Interfaces[i].Hwaddr)
			if err != nil {
				return fmt.Errorf("interface %d failed getting MAC for '%s': %s", i, config.Interfaces[i].Hwaddr, err.Error())
			}

			config.Interfaces[i].Hwaddr = hwaddr
		}
	}

	for i := range len(config.Bonds) {
		if config.Bonds[i].Hwaddr != "" && !hwaddrhRegex.MatchString(config.Bonds[i].Hwaddr) {
			hwaddr, err := getMacForInterface(ctx, config.Bonds[i].Hwaddr)
			if err != nil {
				return fmt.Errorf("bond %d failed getting MAC for '%s': %s", i, config.Bonds[i].Hwaddr, err.Error())
			}

			config.Bonds[i].Hwaddr = hwaddr
		}

		for j := range len(config.Bonds[i].Members) {
			if !hwaddrhRegex.MatchString(config.Bonds[i].Members[j]) {
				hwaddr, err := getMacForInterface(ctx, config.Bonds[i].Members[j])
				if err != nil {
					return fmt.Errorf("bond %d member %d failed getting MAC for '%s': %s", i, j, config.Bonds[i].Members[j], err.Error())
				}

				config.Bonds[i].Members[j] = hwaddr
			}
		}
	}

	return nil
}

// getMacForInterface attempts to query a give network interface and return its MAC address.
func getMacForInterface(ctx context.Context, iface string) (string, error) {
	macAddressRegex := regexp.MustCompile(`link/ether (.+) brd`)

	output, err := subprocess.RunCommandContext(ctx, "ip", "link", "show", iface)
	if err != nil {
		return "", err
	}

	match := macAddressRegex.FindAllStringSubmatch(output, -1)
	if len(match) != 1 {
		return "", errors.New("no MAC address found")
	}

	return match[0][1], nil
}

func getExpectedNewPhysicalDevices(ctx context.Context, config *api.SystemNetworkConfig) []string {
	devices := []string{}
	ret := []string{}

	// Get a list of all the expected "_p" physical devices referenced by the interfaces or bond
	// members in the given network configuration.
	for i := range config.Interfaces {
		devices = append(devices, "_p"+strings.ToLower(strings.ReplaceAll(config.Interfaces[i].Hwaddr, ":", "")))
	}

	for i := range config.Bonds {
		for j := range config.Bonds[i].Members {
			devices = append(devices, "_p"+strings.ToLower(strings.ReplaceAll(config.Bonds[i].Members[j], ":", "")))
		}
	}

	// Check if the given device is already known to networkd; if not, add it to the list
	// of devices we need to wait for.
	for _, dev := range devices {
		_, err := subprocess.RunCommandContext(ctx, "networkctl", "status", dev)
		if err != nil {
			ret = append(ret, dev)
		}
	}

	return ret
}
