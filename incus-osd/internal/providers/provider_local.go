package providers

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/lxc/incus-os/incus-osd/internal/state"
)

// The Local provider.
type local struct {
	state *state.State

	path string

	releaseAssets  []string
	releaseVersion string
}

func (*local) ClearCache(_ context.Context) error {
	// No cache for the local provider.
	return nil
}

func (*local) RefreshRegister(_ context.Context) error {
	// No registration with the local provider.
	return ErrRegistrationUnsupported
}

func (*local) Register(_ context.Context, _ bool) error {
	// No registration with the local provider.
	return ErrRegistrationUnsupported
}

func (*local) Deregister(_ context.Context) error {
	// Since we can't register, deregister is a no-op.
	return nil
}

func (*local) Type() string {
	return "local"
}

func (p *local) GetSecureBootCertUpdate(ctx context.Context) (SecureBootCertUpdate, error) {
	// Get latest release.
	err := p.checkRelease(ctx)
	if err != nil {
		return nil, err
	}

	// Verify the list of returned assets for the Secure Boot update contains at least
	// one file for the release version, otherwise we shouldn't report an update.
	foundUpdateFile := false

	for _, asset := range p.releaseAssets {
		if strings.HasPrefix(filepath.Base(asset), "SecureBootKeys_") && strings.Contains(filepath.Base(asset), p.releaseVersion) {
			foundUpdateFile = true

			break
		}
	}

	if !foundUpdateFile {
		return nil, ErrNoUpdateAvailable
	}

	// Prepare the OS update struct.
	update := localSecureBootCertUpdate{
		provider: p,
		assets:   p.releaseAssets,
		version:  p.releaseVersion,
	}

	return &update, nil
}

func (p *local) GetOSUpdate(ctx context.Context) (OSUpdate, error) {
	// Get latest release.
	err := p.checkRelease(ctx)
	if err != nil {
		return nil, err
	}

	// Verify the list of returned assets for the OS update contains at least
	// one file for the release version, otherwise we shouldn't report an OS update.
	foundUpdateFile := false

	for _, asset := range p.releaseAssets {
		if strings.HasPrefix(filepath.Base(asset), "IncusOS_") && strings.Contains(filepath.Base(asset), p.releaseVersion) {
			foundUpdateFile = true

			break
		}
	}

	if !foundUpdateFile {
		return nil, ErrNoUpdateAvailable
	}

	// Prepare the OS update struct.
	update := localOSUpdate{
		provider: p,
		assets:   p.releaseAssets,
		version:  p.releaseVersion,
	}

	return &update, nil
}

func (p *local) GetApplication(ctx context.Context, name string) (Application, error) {
	// Get latest release.
	err := p.checkRelease(ctx)
	if err != nil {
		return nil, err
	}

	// Verify the list of returned assets contains a "<name>.raw" file, otherwise
	// we shouldn't return an application update.
	foundUpdateFile := false

	for _, asset := range p.releaseAssets {
		if filepath.Base(asset) == name+".raw" {
			foundUpdateFile = true

			break
		}
	}

	if !foundUpdateFile {
		return nil, ErrNoUpdateAvailable
	}

	// Prepare the application struct.
	app := localApplication{
		provider: p,
		name:     name,
		assets:   p.releaseAssets,
		version:  p.releaseVersion,
	}

	return &app, nil
}

func (p *local) load(_ context.Context) error {
	// Use a hardcoded path for now.
	p.path = "/root/updates/"

	return nil
}

func (p *local) checkRelease(_ context.Context) error {
	// Deal with missing path.
	_, err := os.Lstat(p.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNoUpdateAvailable
		}

		return err
	}

	// Parse the version string.
	body, err := os.ReadFile(filepath.Join(p.path, "RELEASE"))
	if err != nil {
		return err
	}

	p.releaseVersion = strings.TrimSpace(string(body))

	// Build asset list.
	assets := []string{}

	entries, err := os.ReadDir(p.path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		assets = append(assets, filepath.Join(p.path, entry.Name()))
	}

	p.releaseAssets = assets

	return nil
}

func (p *local) copyAsset(_ context.Context, name string, targetPath string, progressFunc func(float64)) error {
	// Open the source.
	// #nosec G304
	src, err := os.Open(filepath.Join(p.path, name))
	if err != nil {
		return err
	}

	defer src.Close()

	// Get the file size.
	s, err := src.Stat()
	if err != nil {
		return err
	}

	srcSize := float64(s.Size())

	// Open the destination.
	// #nosec G304
	dst, err := os.Create(filepath.Join(targetPath, name))
	if err != nil {
		return err
	}

	defer dst.Close()

	// Copy the content.
	count := int64(0)

	for {
		_, err := io.CopyN(dst, src, 4*1024*1024)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return err
		}

		// Update progress every 24MiB.
		if progressFunc != nil && count%6 == 0 {
			progressFunc(float64(count*4*1024*1024) / srcSize)
		}

		count++
	}

	return nil
}

// An application from the Local provider.
type localApplication struct {
	provider *local

	assets  []string
	name    string
	version string
}

func (a *localApplication) Name() string {
	return a.name
}

func (a *localApplication) Version() string {
	return a.version
}

func (a *localApplication) IsNewerThan(otherVersion string) bool {
	return datetimeComparison(a.version, otherVersion)
}

func (a *localApplication) Download(ctx context.Context, targetPath string, progressFunc func(float64)) error {
	// Create the target path.
	err := os.MkdirAll(targetPath, 0o700)
	if err != nil {
		return err
	}

	for _, asset := range a.assets {
		appName := strings.TrimSuffix(filepath.Base(asset), ".raw")

		// Only select the desired applications.
		if appName != a.name {
			continue
		}

		// Copy the application.
		err = a.provider.copyAsset(ctx, filepath.Base(asset), targetPath, progressFunc)
		if err != nil {
			return err
		}
	}

	return nil
}

// An update from the Local provider.
type localOSUpdate struct {
	provider *local

	assets  []string
	version string
}

func (o *localOSUpdate) Version() string {
	return o.version
}

func (o *localOSUpdate) IsNewerThan(otherVersion string) bool {
	return datetimeComparison(o.version, otherVersion)
}

func (o *localOSUpdate) DownloadUpdate(ctx context.Context, targetPath string, progressFunc func(float64)) error {
	// Clear the path.
	err := os.RemoveAll(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Create the target path.
	err = os.MkdirAll(targetPath, 0o700)
	if err != nil {
		return err
	}

	for _, asset := range o.assets {
		// Only select OS files for the expected version.
		if !strings.HasPrefix(filepath.Base(asset), "IncusOS_"+o.version) {
			continue
		}

		// Parse the file names.
		fields := strings.SplitN(filepath.Base(asset), ".", 2)
		if len(fields) != 2 {
			continue
		}

		// Skip the full image.
		if fields[1] == "raw" {
			continue
		}

		// Download the actual update.
		err = o.provider.copyAsset(ctx, filepath.Base(asset), targetPath, progressFunc)
		if err != nil {
			return err
		}
	}

	return nil
}

func (*localOSUpdate) DownloadImage(_ context.Context, _ string, _ string, _ func(float64)) (string, error) {
	// No reason to support fetching a full install image from the local (development) provider.
	return "", errors.New("downloading full image not supported by local provider")
}

// Secure Boot key updates from the Local provider.
type localSecureBootCertUpdate struct {
	provider *local

	assets  []string
	version string
}

func (o *localSecureBootCertUpdate) Version() string {
	return o.version
}

func (o *localSecureBootCertUpdate) GetFilename() string {
	return "SecureBootKeys_" + o.version + ".tar"
}

func (o *localSecureBootCertUpdate) IsNewerThan(otherVersion string) bool {
	return datetimeComparison(o.version, otherVersion)
}

func (o *localSecureBootCertUpdate) Download(ctx context.Context, targetPath string) error {
	for _, asset := range o.assets {
		// Only select Secure Boot keys for the expected version.
		if filepath.Base(asset) != o.GetFilename() {
			continue
		}

		// Download the actual update.
		err := o.provider.copyAsset(ctx, filepath.Base(asset), targetPath, nil)
		if err != nil {
			return err
		}
	}

	return nil
}
