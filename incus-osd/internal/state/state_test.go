package state_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lxc/incus-os/incus-osd/internal/state"
)

var goldJSON = `{"secure_boot":{"version":"","fully_applied":false},"applications":{"incus":{"initialized":true,"version":"202506241635"}},"os":{"name":"IncusOS","running_release":"202506241635","next_release":"202506241635"},"services":{"iscsi":{"state":{"initiator_name":""},"config":{"enabled":false,"targets":null}},"lvm":{"state":{},"config":{"enabled":false,"system_id":0}},"nvme":{"state":{"host_id":"","host_nqn":""},"config":{"enabled":false,"targets":null}},"ovn":{"state":{},"config":{"enabled":false,"ic_chassis":false,"database":"","tls_client_certificate":"","tls_client_key":"","tls_ca_certificate":"","tunnel_address":"","tunnel_protocol":""}},"usbip":{"state":{},"config":{"targets":null}}},"system":{"encryption":{"config":{"recovery_keys":["ebbbibiu-ltgjfuhk-gvutdrvu-hijhvfje-gvlrgrfv-ndekdtdh-ghteuklj-ldedfifb"]},"state":{"recovery_keys_retrieved":true}},"network":{"config":{"interfaces":[{"name":"enp5s0","addresses":["dhcp4","slaac"],"hwaddr":"10:66:6a:7c:8c:b0","lldp":false}]},"state":{"interfaces":{"enp5s0":{"type":"interface","addresses":["10.234.136.156"],"routes":[{"to":"default","via":"10.234.136.1"}],"mtu":1500,"speed":"10Gbps","state":"routable","stats":{"rx_bytes":944,"tx_bytes":751,"rx_errors":0,"tx_errors":0}}}}},"provider":{"config":{"name":"local","config":null},"state":{"registered":false}}}}`

var goldEncoding = `#Version: 0
Applications[incus].Initialized: true
Applications[incus].Version: 202506241635
OS.Name: IncusOS
OS.RunningRelease: 202506241635
OS.NextRelease: 202506241635
System.Encryption.Config.RecoveryKeys[0]: ebbbibiu-ltgjfuhk-gvutdrvu-hijhvfje-gvlrgrfv-ndekdtdh-ghteuklj-ldedfifb
System.Encryption.State.RecoveryKeysRetrieved: true
System.Network.Config.Interfaces[0].Name: enp5s0
System.Network.Config.Interfaces[0].Addresses[0]: dhcp4
System.Network.Config.Interfaces[0].Addresses[1]: slaac
System.Network.Config.Interfaces[0].Hwaddr: 10:66:6a:7c:8c:b0
System.Provider.Config.Name: local
`

// Test basic json decoding/encoding of state.
func TestJsonEncoding(t *testing.T) {
	t.Parallel()

	var s state.State

	err := json.Unmarshal([]byte(goldJSON), &s)
	require.NoError(t, err)

	content, err := json.Marshal(s)
	require.NoError(t, err)

	require.JSONEq(t, goldJSON, string(content))
}

// Test basic custom decoding/encoding of state.
func TestCustomEncoding(t *testing.T) {
	t.Parallel()

	s, err := state.Decode([]byte(goldEncoding))
	require.NoError(t, err)

	content, err := state.Encode(s)
	require.NoError(t, err)

	require.Equal(t, goldEncoding, string(content))
}

func TestEncodingSwitch(t *testing.T) {
	t.Parallel()

	var js state.State

	err := json.Unmarshal([]byte(goldJSON), &js)
	require.NoError(t, err)

	content, err := state.Encode(&js)
	require.NoError(t, err)

	cs1, err := state.Decode(content)
	require.NoError(t, err)

	cs2, err := state.Decode([]byte(goldEncoding))
	require.NoError(t, err)

	require.Equal(t, cs1, cs2)
}
