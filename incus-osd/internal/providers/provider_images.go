package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lxc/incus/v6/shared/osarch"
	"github.com/lxc/incus/v6/shared/subprocess"

	apiupdate "github.com/lxc/incus-os/incus-osd/api/images"
	"github.com/lxc/incus-os/incus-osd/internal/state"
)

// The images provider.
type images struct {
	state *state.State

	serverURL string
	updateCA  string

	lastCheck    time.Time
	latestUpdate *apiupdate.UpdateFull
}

func (p *images) ClearCache(_ context.Context) error {
	// Reset the last check time.
	p.lastCheck = time.Time{}

	return nil
}

func (*images) RefreshRegister(_ context.Context) error {
	// No registration with the images provider.
	return ErrRegistrationUnsupported
}

func (*images) Register(_ context.Context, _ bool) error {
	// No registration with the images provider.
	return ErrRegistrationUnsupported
}

func (*images) Deregister(_ context.Context) error {
	// Since we can't register, deregister is a no-op.
	return nil
}

func (*images) Type() string {
	return "images"
}

func (p *images) GetSecureBootCertUpdate(ctx context.Context) (SecureBootCertUpdate, error) {
	// Get latest release.
	latestUpdate, err := p.checkRelease(ctx)
	if err != nil {
		return nil, err
	}

	// Check if a SecureBoot update is included.
	found := false

	for _, file := range latestUpdate.Files {
		if file.Type == apiupdate.UpdateFileTypeUpdateSecureboot {
			found = true

			break
		}
	}

	if !found {
		return nil, ErrNoUpdateAvailable
	}

	update := imagesSecureBootCertUpdate{
		provider:     p,
		latestUpdate: latestUpdate,
	}

	return &update, nil
}

func (p *images) GetOSUpdate(ctx context.Context) (OSUpdate, error) {
	// Get latest release.
	latestUpdate, err := p.checkRelease(ctx)
	if err != nil {
		return nil, err
	}

	// Check that an OS update is included.
	found := false

	for _, file := range latestUpdate.Files {
		if file.Component == apiupdate.UpdateFileComponentOS {
			found = true

			break
		}
	}

	if !found {
		return nil, ErrNoUpdateAvailable
	}

	// Prepare the OS update struct.
	update := imagesOSUpdate{
		provider:     p,
		latestUpdate: latestUpdate,
	}

	return &update, nil
}

func (p *images) GetApplication(ctx context.Context, name string) (Application, error) {
	// Get latest release.
	latestUpdate, err := p.checkRelease(ctx)
	if err != nil {
		return nil, err
	}

	// Check that an application update is included.
	found := false

	for _, file := range latestUpdate.Files {
		if string(file.Component) == name {
			found = true

			break
		}
	}

	if !found {
		return nil, ErrNoUpdateAvailable
	}

	// Prepare the application struct.
	app := imagesApplication{
		provider:     p,
		name:         name,
		latestUpdate: latestUpdate,
	}

	return &app, nil
}

func (p *images) load(_ context.Context) error {
	// Set up the configuration.
	p.serverURL = p.state.System.Provider.Config.Config["server_url"]
	p.updateCA = p.state.System.Provider.Config.Config["update_ca"]

	// Basic validation.
	if p.serverURL == "" {
		p.serverURL = "https://images.linuxcontainers.org/os"
		p.updateCA = LXCUpdateCA
	}

	return nil
}

func (p *images) checkRelease(ctx context.Context) (*apiupdate.UpdateFull, error) {
	// Only talk to image server once an hour.
	if p.latestUpdate != nil && !p.lastCheck.IsZero() && p.lastCheck.Add(time.Hour).After(time.Now()) {
		return p.latestUpdate, nil
	}

	// Get local architecture.
	archName, err := osarch.ArchitectureGetLocal()
	if err != nil {
		return nil, err
	}

	// Get the latest signed index.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.serverURL+"/index.sjson", nil)
	if err != nil {
		return nil, err
	}

	resp, err := p.tryRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("server failed to return expected file")
	}

	// Write the CA certificate.
	rootCA, err := os.CreateTemp("", "")
	if err != nil {
		return nil, err
	}

	_, err = fmt.Fprintf(rootCA, "%s", p.updateCA)
	if err != nil {
		return nil, err
	}

	defer func() { _ = os.Remove(rootCA.Name()) }()

	// Validate signed index.
	verified := bytes.NewBuffer(nil)

	err = subprocess.RunCommandWithFds(ctx, resp.Body, verified, "openssl", "smime", "-verify", "-text", "-CAfile", rootCA.Name())
	if err != nil {
		return nil, err
	}

	// Parse the update list.
	index := &apiupdate.Index{}

	err = json.NewDecoder(bytes.NewReader(verified.Bytes())).Decode(index)
	if err != nil {
		return nil, err
	}

	// Get the latest update for the expected channel.
	var latestUpdate *apiupdate.UpdateFull

	for _, update := range index.Updates {
		// Skip any update targeting the wrong channel(s).
		if update.Version != p.state.OS.RunningRelease && p.state.System.Update.Config.Channel != "" && !slices.Contains(update.Channels, p.state.System.Update.Config.Channel) {
			continue
		}

		// Skip any update with no files.
		if len(update.Files) == 0 {
			continue
		}

		// Strip files for other architectures.
		newFiles := []apiupdate.UpdateFile{}

		for _, file := range update.Files {
			if file.Architecture != "" && string(file.Architecture) != archName {
				continue
			}

			newFiles = append(newFiles, file)
		}

		update.Files = newFiles

		// Skip images with no suitable files.
		if len(update.Files) == 0 {
			continue
		}

		latestUpdate = &update

		break
	}

	if latestUpdate == nil {
		return nil, ErrNoUpdateAvailable
	}

	// Record the release.
	p.lastCheck = time.Now()
	p.latestUpdate = latestUpdate

	return latestUpdate, nil
}

func (*images) tryRequest(req *http.Request) (*http.Response, error) {
	var err error

	for range 5 {
		var resp *http.Response

		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			return resp, nil
		}

		time.Sleep(time.Second)
	}

	return nil, err
}

// An application from the images provider.
type imagesApplication struct {
	provider *images

	name         string
	latestUpdate *apiupdate.UpdateFull
}

func (a *imagesApplication) Name() string {
	return a.name
}

func (a *imagesApplication) Version() string {
	return a.latestUpdate.Version
}

func (a *imagesApplication) IsNewerThan(otherVersion string) bool {
	return datetimeComparison(a.latestUpdate.Version, otherVersion)
}

func (a *imagesApplication) Download(ctx context.Context, targetPath string, progressFunc func(float64)) error {
	// Create the target path.
	err := os.MkdirAll(targetPath, 0o700)
	if err != nil {
		return err
	}

	for _, file := range a.latestUpdate.Files {
		// Only select the desired applications.
		if string(file.Component) != a.name {
			continue
		}

		fileURL := a.provider.serverURL + "/" + a.latestUpdate.Version + "/" + file.Filename
		targetName := strings.TrimSuffix(filepath.Base(file.Filename), ".gz")

		// Download the application.
		err = downloadAsset(ctx, http.DefaultClient, fileURL, file.Sha256, filepath.Join(targetPath, targetName), progressFunc)
		if err != nil {
			return err
		}
	}

	return nil
}

// An update from the images provider.
type imagesOSUpdate struct {
	provider *images

	latestUpdate *apiupdate.UpdateFull
}

func (o *imagesOSUpdate) Version() string {
	return o.latestUpdate.Version
}

func (o *imagesOSUpdate) IsNewerThan(otherVersion string) bool {
	return datetimeComparison(o.latestUpdate.Version, otherVersion)
}

func (o *imagesOSUpdate) DownloadUpdate(ctx context.Context, targetPath string, progressFunc func(float64)) error {
	// Clear the target path.
	err := os.RemoveAll(targetPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Create the target path.
	err = os.MkdirAll(targetPath, 0o700)
	if err != nil {
		return err
	}

	for _, file := range o.latestUpdate.Files {
		// Only select OS updates.
		if file.Component != apiupdate.UpdateFileComponentOS || !slices.Contains([]apiupdate.UpdateFileType{apiupdate.UpdateFileTypeUpdateEFI, apiupdate.UpdateFileTypeUpdateUsr, apiupdate.UpdateFileTypeUpdateUsrVerity, apiupdate.UpdateFileTypeUpdateUsrVeritySignature}, file.Type) {
			continue
		}

		fileURL := o.provider.serverURL + "/" + o.latestUpdate.Version + "/" + file.Filename
		targetName := strings.TrimSuffix(filepath.Base(file.Filename), ".gz")

		// Download the application.
		err = downloadAsset(ctx, http.DefaultClient, fileURL, file.Sha256, filepath.Join(targetPath, targetName), progressFunc)
		if err != nil {
			return err
		}
	}

	return nil
}

func (o *imagesOSUpdate) DownloadImage(ctx context.Context, imageType string, targetPath string, progressFunc func(float64)) (string, error) {
	// Create the target path.
	err := os.MkdirAll(targetPath, 0o700)
	if err != nil {
		return "", err
	}

	for _, file := range o.latestUpdate.Files {
		// Only select OS updates.
		if file.Component != apiupdate.UpdateFileComponentOS || string(file.Type) != "image-"+imageType {
			continue
		}

		fileURL := o.provider.serverURL + "/" + o.latestUpdate.Version + "/" + file.Filename
		targetName := strings.TrimSuffix(filepath.Base(file.Filename), ".gz")

		// Download the application.
		err = downloadAsset(ctx, http.DefaultClient, fileURL, file.Sha256, filepath.Join(targetPath, targetName), progressFunc)

		return targetName, err
	}

	return "", fmt.Errorf("failed to download image type '%s' for release %s", imageType, o.latestUpdate.Version)
}

// Secure Boot key updates from the images provider.
type imagesSecureBootCertUpdate struct {
	provider *images

	latestUpdate *apiupdate.UpdateFull
}

func (o *imagesSecureBootCertUpdate) Version() string {
	return o.latestUpdate.Version
}

func (o *imagesSecureBootCertUpdate) GetFilename() string {
	return "SecureBootKeys_" + o.latestUpdate.Version + ".tar"
}

func (o *imagesSecureBootCertUpdate) IsNewerThan(otherVersion string) bool {
	// Prior to distributing SecureBoot updates via the normal update channel,
	// we had a hard-coded release URL. The latest version there was 202601010000,
	// which we need to temporarily allow to downgrade until we pass Jan 1, 2026.
	if otherVersion == "202601010000" {
		return datetimeComparison(o.latestUpdate.Version, "202510272025")
	}

	return datetimeComparison(o.latestUpdate.Version, otherVersion)
}

func (o *imagesSecureBootCertUpdate) Download(ctx context.Context, targetPath string) error {
	// Create the target path.
	err := os.MkdirAll(targetPath, 0o700)
	if err != nil {
		return err
	}

	for _, file := range o.latestUpdate.Files {
		// Only select the SecureBoot update.
		if file.Type != apiupdate.UpdateFileTypeUpdateSecureboot {
			continue
		}

		fileURL := o.provider.serverURL + "/" + o.latestUpdate.Version + "/" + file.Filename

		// Download the application.
		err = downloadAsset(ctx, http.DefaultClient, fileURL, file.Sha256, filepath.Join(targetPath, o.GetFilename()), nil)
		if err != nil {
			return err
		}
	}

	return nil
}
