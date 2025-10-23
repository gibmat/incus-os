package applications

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/lxc/incus/v6/shared/api"
	"github.com/lxc/incus/v6/shared/revert"

	"github.com/lxc/incus-os/incus-osd/internal/state"
)

type common struct {
	state *state.State
}

// AddTrustedCertificate adds a new trusted certificate to the application.
func (*common) AddTrustedCertificate(_ context.Context, _ string, _ string) error {
	return errors.New("not supported")
}

// GetCertificate gets the server certificate for the application.
func (*common) GetCertificate() (*tls.Certificate, error) {
	return nil, errors.New("not supported")
}

// Initialize runs first time initialization.
func (*common) Initialize(_ context.Context) error {
	return nil
}

// Restart restarts runs restart action.
func (*common) Restart(_ context.Context, _ string) error {
	return nil
}

// Start runs startup action.
func (*common) Start(_ context.Context, _ string) error {
	return nil
}

// Stop runs shutdown action.
func (*common) Stop(_ context.Context, _ string) error {
	return nil
}

// Update triggers a partial application restart after an update.
func (*common) Update(_ context.Context, _ string) error {
	return nil
}

// IsPrimary reports if the application is a primary application.
func (*common) IsPrimary() bool {
	return false
}

// IsRunning reports if the application is currently running.
func (*common) IsRunning(_ context.Context) bool {
	return true
}

// WipeLocalData removes local data created by the application.
func (*common) WipeLocalData() error {
	return errors.New("not supported")
}

// FactoryReset performs a full factory reset of the application.
func (*common) FactoryReset(_ context.Context) error {
	return errors.New("not supported")
}

// GetBackup returns a tar archive backup of the application's configuration and/or state.
func (*common) GetBackup(_ io.Writer, _ bool) error {
	return errors.New("not supported")
}

// RestoreBackup restores a tar archive backup of the application's configuration and/or state.
func (*common) RestoreBackup(_ io.Reader) error {
	return errors.New("not supported")
}

// Common helper to construct an HTTP client using the provided local Unix socket.
func unixHTTPClient(socketPath string) (*http.Client, error) {
	// Setup a Unix socket dialer
	unixDial := func(_ context.Context, _ string, _ string) (net.Conn, error) {
		raddr, err := net.ResolveUnixAddr("unix", socketPath)
		if err != nil {
			return nil, err
		}

		return net.DialUnix("unix", nil, raddr)
	}

	// Define the http transport
	transport := &http.Transport{
		DialContext:           unixDial,
		DisableKeepAlives:     true,
		ExpectContinueTimeout: time.Second * 30,
		ResponseHeaderTimeout: time.Second * 3600,
		TLSHandshakeTimeout:   time.Second * 5,
	}

	// Define the http client
	client := &http.Client{}

	client.Transport = transport

	// Setup redirect policy
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Replicate the headers
		req.Header = via[len(via)-1].Header

		return nil
	}

	return client, nil
}

// Common helper for performing REST API calls.
func doRequest(ctx context.Context, socket string, url string, method string, body []byte) ([]byte, error) {
	client, err := unixHTTPClient(socket)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	r := &api.ResponseRaw{}

	err = json.NewDecoder(resp.Body).Decode(r)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK || r.StatusCode != http.StatusOK {
		return nil, errors.New(r.Error)
	}

	ret, err := json.Marshal(r.Metadata)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// Comment helper to compute the SHA256 fingerprint of a PEM-encoded certificate.
func getCertificateFingerprint(certificate string) (string, error) {
	certBlock, _ := pem.Decode([]byte(certificate))
	if certBlock == nil {
		return "", errors.New("cannot parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("invalid certificate: %w", err)
	}

	rawFp := sha256.Sum256(cert.Raw)

	return hex.EncodeToString(rawFp[:]), nil
}

func createTarArchive(archiveRoot string, excludePaths []string, archive io.Writer) error {
	zw := gzip.NewWriter(archive)
	tw := tar.NewWriter(zw)

	err := filepath.Walk(archiveRoot, func(path string, info fs.FileInfo, _ error) error {
		archiveFilename := strings.TrimPrefix(path, archiveRoot)

		// Skip the root directory and any relative path starting with a path to be excluded.
		if archiveFilename == "" || slices.ContainsFunc(excludePaths, func(s string) bool {
			return strings.HasPrefix(archiveFilename, s)
		}) {
			return nil
		}

		mode := int64(info.Mode().Perm())
		modTime := info.ModTime()

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("unable to stat file " + archiveFilename)
		}

		uid := int(stat.Uid)
		gid := int(stat.Gid)

		switch {
		case info.Mode().IsDir():
			// Create the header for the directory.
			header := &tar.Header{
				Name:     archiveFilename,
				Typeflag: tar.TypeDir,
				Mode:     mode,
				ModTime:  modTime,
				Uid:      uid,
				Gid:      gid,
			}

			// Write the header.
			err := tw.WriteHeader(header)
			if err != nil {
				return err
			}
		case info.Mode()&os.ModeSymlink == os.ModeSymlink:
			// Get the symlink destination.
			dest, err := os.Readlink(path)
			if err != nil {
				return err
			}

			// Create the header for the symlink.
			header := &tar.Header{
				Name:     archiveFilename,
				Typeflag: tar.TypeSymlink,
				Linkname: dest,
				Mode:     mode,
				ModTime:  modTime,
				Uid:      uid,
				Gid:      gid,
			}

			// Write the header.
			err = tw.WriteHeader(header)
			if err != nil {
				return err
			}
		case info.Mode().IsRegular():
			// Open the file.
			// #nosec G304
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			// Create the header for the file.
			header := &tar.Header{
				Name:     archiveFilename,
				Typeflag: tar.TypeReg,
				Mode:     mode,
				ModTime:  modTime,
				Uid:      uid,
				Gid:      gid,
				Size:     info.Size(),
			}

			// Write the header and file contents.
			err = tw.WriteHeader(header)
			if err != nil {
				return err
			}

			_, err = io.Copy(tw, file)
			if err != nil {
				return err
			}
		default:
			return errors.New("unsupported file: " + archiveFilename)
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = tw.Close()
	if err != nil {
		return err
	}

	return zw.Close()
}

func extractTarArchive(archiveRoot string, archive io.Reader) error {
	reverter := revert.New()
	defer reverter.Fail()

	// Backup the current directory.
	backupArchiveRoot := strings.TrimSuffix(archiveRoot, "/") + ".bak"

	err := os.Rename(archiveRoot, backupArchiveRoot)
	if err != nil {
		return err
	}

	// If we encounter an error, restore things to the prior state.
	reverter.Add(func() {
		// Restore the backup directory.
		_ = os.RemoveAll(archiveRoot)
		_ = os.Rename(backupArchiveRoot, archiveRoot)
	})

	// Create the new root directory.
	stat, err := os.Stat(backupArchiveRoot)
	if err != nil {
		return err
	}

	err = os.Mkdir(archiveRoot, stat.Mode())
	if err != nil {
		return err
	}

	// Iterate through each file in the tar archive.
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return err
		}

		// Don't let someone feed us a path traversal escape attack.
		// #nosec G305
		filename := filepath.Join(archiveRoot, header.Name)
		if !strings.HasPrefix(filename, archiveRoot) {
			return fmt.Errorf("cannot restore file outside of application root '%s' (bad file '%s')", archiveRoot, filename)
		}

		mode := fs.FileMode(header.Mode) //nolint:gosec

		switch header.Typeflag {
		case tar.TypeDir:
			err := os.Mkdir(filename, mode)
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			err := os.Symlink(header.Linkname, filename)
			if err != nil {
				return err
			}
		case tar.TypeReg:
			// Write file to disk.
			// #nosec G304
			file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, mode)
			if err != nil {
				return err
			}
			defer file.Close() //nolint:revive

			// Read from the archive in chunks to avoid excessive memory consumption.
			var size int64

			for {
				n, err := io.CopyN(file, tr, 4*1024*1024)
				size += n

				if err != nil {
					if errors.Is(err, io.EOF) {
						break
					}

					return err
				}
			}
		default:
			return errors.New("unsupported file: " + header.Name)
		}

		// Set proper ownership.
		err = os.Lchown(filename, header.Uid, header.Gid)
		if err != nil {
			return err
		}
	}

	// Remove the old backup.
	err = os.RemoveAll(backupArchiveRoot)
	if err != nil {
		return err
	}

	reverter.Success()

	return nil
}
