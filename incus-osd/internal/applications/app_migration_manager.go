package applications

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/FuturFusion/migration-manager/shared/api"

	apiseed "github.com/lxc/incus-os/incus-osd/api/seed"
	"github.com/lxc/incus-os/incus-osd/internal/seed"
	"github.com/lxc/incus-os/incus-osd/internal/systemd"
)

type migrationManager struct {
	common
}

// Start starts the systemd unit.
func (*migrationManager) Start(ctx context.Context, _ string) error {
	// Start the unit.
	return systemd.EnableUnit(ctx, true, "migration-manager.service")
}

// Stop stops the systemd unit.
func (*migrationManager) Stop(ctx context.Context, _ string) error {
	// Stop the unit.
	return systemd.StopUnit(ctx, "migration-manager.service")
}

// Restart restarts the main systemd unit.
func (*migrationManager) Restart(ctx context.Context, _ string) error {
	return systemd.RestartUnit(ctx, "migration-manager.service")
}

// Update triggers restart after an application update.
func (*migrationManager) Update(ctx context.Context, _ string) error {
	// Reload the systemd daemon to pickup any service definition changes.
	err := systemd.ReloadDaemon(ctx)
	if err != nil {
		return err
	}

	// Restart the unit.
	return systemd.RestartUnit(ctx, "migration-manager.service")
}

// Initialize runs first time initialization.
func (mm *migrationManager) Initialize(ctx context.Context) error {
	// Get the preseed from the seed partition.
	mmSeed, err := seed.GetMigrationManager(ctx, seed.GetSeedPath())
	if err != nil && !seed.IsMissing(err) {
		return err
	}

	// Configure an empty seed if none was provided.
	if mmSeed == nil {
		mmSeed = new(apiseed.MigrationManager)
	}

	if mmSeed.Preseed == nil {
		mmSeed.Preseed = new(apiseed.MigrationManagerPreseed)
	}

	// Wait for Migration Manager to begin accepting connections.
	count := 0

	for {
		_, err := doMMRequest(ctx, "http://localhost/1.0", http.MethodGet, nil)
		if err == nil {
			break
		}

		count++

		if count > 10 {
			return errors.New("failed to connect to Migration Manager via local socket")
		}

		time.Sleep(500 * time.Millisecond)
	}

	// Apply SystemCertificate, if any.
	if mmSeed.Preseed.SystemCertificate != nil {
		contentJSON, err := json.Marshal(mmSeed.Preseed.SystemCertificate)
		if err != nil {
			return err
		}

		_, err = doMMRequest(ctx, "http://localhost/1.0/system/certificate", http.MethodPost, contentJSON)
		if err != nil {
			return err
		}
	}

	// Apply SystemNetwork, if any.
	if mmSeed.Preseed.SystemNetwork == nil {
		mmSeed.Preseed.SystemNetwork = new(api.SystemNetwork)
	}

	{
		// If no IP address is provided, default to listening on all addresses on port 8443.
		if mmSeed.Preseed.SystemNetwork.Address == "" {
			mmSeed.Preseed.SystemNetwork.Address = "[::]:8443"

			// Get the management address.
			mgmtAddr := mm.state.ManagementAddress()
			if mgmtAddr != nil {
				mmSeed.Preseed.SystemNetwork.WorkerEndpoint = "https://" + net.JoinHostPort(mgmtAddr.String(), "8443")
			}
		}

		contentJSON, err := json.Marshal(mmSeed.Preseed.SystemNetwork)
		if err != nil {
			return err
		}

		_, err = doMMRequest(ctx, "http://localhost/1.0/system/network", http.MethodPut, contentJSON)
		if err != nil {
			return err
		}
	}

	// Apply SystemSecurity, if any.
	if mmSeed.Preseed.SystemSecurity == nil && len(mmSeed.TrustedClientCertificates) > 0 {
		mmSeed.Preseed.SystemSecurity = new(api.SystemSecurity)
	}

	if mmSeed.Preseed.SystemSecurity != nil {
		// Compute fingerprints for any user-provided client certificates and add to the
		// list of trusted TLS client certificates.
		for i, certString := range mmSeed.TrustedClientCertificates {
			fp, err := getCertificateFingerprint(certString)
			if err != nil {
				return fmt.Errorf("%w (seed index %d)", err, i)
			}

			if !slices.Contains(mmSeed.Preseed.SystemSecurity.TrustedTLSClientCertFingerprints, fp) {
				mmSeed.Preseed.SystemSecurity.TrustedTLSClientCertFingerprints = append(mmSeed.Preseed.SystemSecurity.TrustedTLSClientCertFingerprints, fp)
			}
		}

		contentJSON, err := json.Marshal(mmSeed.Preseed.SystemSecurity)
		if err != nil {
			return err
		}

		_, err = doMMRequest(ctx, "http://localhost/1.0/system/security", http.MethodPut, contentJSON)
		if err != nil {
			return err
		}
	}

	return nil
}

// IsRunning reports if the application is currently running.
func (*migrationManager) IsRunning(ctx context.Context) bool {
	return systemd.IsActive(ctx, "migration-manager.service")
}

// GetCertificate returns the keypair for the server certificate.
func (*migrationManager) GetCertificate() (*tls.Certificate, error) {
	// Load the certificate.
	tlsCert, err := os.ReadFile("/var/lib/migration-manager/server.crt")
	if err != nil {
		return nil, err
	}

	tlsKey, err := os.ReadFile("/var/lib/migration-manager/server.key")
	if err != nil {
		return nil, err
	}

	// Put together a keypair.
	cert, err := tls.X509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// AddTrustedCertificate adds a new trusted certificate to the application.
func (*migrationManager) AddTrustedCertificate(ctx context.Context, _ string, cert string) error {
	// Compute the certificate's fingerprint.
	fp, err := getCertificateFingerprint(cert)
	if err != nil {
		return err
	}

	// Get the current security configuration.
	body, err := doMMRequest(ctx, "http://localhost/1.0/system/security", http.MethodGet, nil)
	if err != nil {
		return err
	}

	sec := &api.SystemSecurity{}

	err = json.Unmarshal(body, sec)
	if err != nil {
		return err
	}

	// Check if the certificate is already trusted.
	if slices.Contains(sec.TrustedTLSClientCertFingerprints, fp) {
		return errors.New("client certificate is already trusted")
	}

	// Add the certificate's fingerprint to list of trusted clients.
	sec.TrustedTLSClientCertFingerprints = append(sec.TrustedTLSClientCertFingerprints, fp)

	contentJSON, err := json.Marshal(sec)
	if err != nil {
		return err
	}

	_, err = doMMRequest(ctx, "http://localhost/1.0/system/security", http.MethodPut, contentJSON)

	return err
}

// Migration Manager specific helper to interact with the REST API.
func doMMRequest(ctx context.Context, url string, method string, body []byte) ([]byte, error) {
	return doRequest(ctx, "/run/migration-manager/unix.socket", url, method, body)
}

// IsPrimary reports if the application is a primary application.
func (*migrationManager) IsPrimary() bool {
	return true
}

// FactoryReset performs a full factory reset of the application.
func (mm *migrationManager) FactoryReset(ctx context.Context) error {
	// Stop the application.
	err := mm.Stop(ctx, "")
	if err != nil {
		return err
	}

	// Wipe local configuration.
	err = mm.WipeLocalData()
	if err != nil {
		return err
	}

	// Start the application.
	err = mm.Start(ctx, "")
	if err != nil {
		return err
	}

	// Perform first start initialization.
	return mm.Initialize(ctx)
}

// WipeLocalData removes local data created by the application.
func (*migrationManager) WipeLocalData() error {
	err := os.RemoveAll("/var/lib/migration-manager/")
	if err != nil {
		return err
	}

	return os.Remove("/var/log/migration-manager.log")
}

// GetBackup returns a tar archive backup of the application's configuration and/or state.
func (*migrationManager) GetBackup(archive io.Writer, complete bool) error {
	if complete {
		return createTarArchive("/var/lib/migration-manager/", nil, archive)
	}

	return createTarArchive("/var/lib/migration-manager/", []string{"artifacts"}, archive)
}

// RestoreBackup restores a tar archive backup of the application's configuration and/or state.
func (*migrationManager) RestoreBackup(ctx context.Context, archive io.Reader) error {
	return extractTarArchive(ctx, "/var/lib/migration-manager/", []string{"migration-manager.service"}, archive)
}
