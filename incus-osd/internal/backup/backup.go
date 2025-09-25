package backup

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/lxc/incus/v6/shared/revert"

	"github.com/lxc/incus-os/incus-osd/internal/state"
)

// GetOSBackup returns a tar archive of all the files under /var/lib/incus-os/.
func GetOSBackup() ([]byte, error) {
	// Simplifying assumption: /var/lib/incus-osd/ only contains files that are
	// relatively small. We don't handle traversing directories or need to worry
	// about memory exhaustion when creating the tar archive.
	var ret bytes.Buffer

	tw := tar.NewWriter(&ret)

	files, err := os.ReadDir("/var/lib/incus-os/")
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			return nil, errors.New("backup cannot contain directories")
		}

		contents, err := os.ReadFile(filepath.Join("/var/lib/incus-os/", file.Name()))
		if err != nil {
			return nil, err
		}

		header := &tar.Header{
			Name: file.Name(),
			Mode: 0o600,
			Size: int64(len(contents)),
		}

		err = tw.WriteHeader(header)
		if err != nil {
			return nil, err
		}

		_, err = tw.Write(contents)
		if err != nil {
			return nil, err
		}
	}

	err = tw.Close()
	if err != nil {
		return nil, err
	}

	return ret.Bytes(), nil
}

func ApplyOSBackup(s *state.State, buf io.Reader, doTotalRestore bool) error {
	reverter := revert.New()
	defer reverter.Fail()

	// Backup the current /var/lib/incus-os/.
	err := os.Rename("/var/lib/incus-os/", "/var/lib/incus-os.bak/")
	if err != nil {
		return err
	}

	// If we encounter an error, restore things to the state prior to starting.
	reverter.Add(func() {
		// Restore the backup directory.
		_ = os.RemoveAll("/var/lib/incus-os/")
		_ = os.Rename("/var/lib/incus-os.bak/", "/var/lib/incus-os/")

		// Ensure we load the old state back.
		oldState, _ := state.LoadOrCreate("/var/lib/incus-os/state.txt")
		s = oldState
	})

	// Create a new /var/lib/incus-os/.
	err = os.Mkdir("/var/lib/incus-os/", 0o700)
	if err != nil {
		return err
	}

	// Iterate through each file in the tar archive.
	tr := tar.NewReader(buf)
	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return err
		}

		if header.Typeflag != tar.TypeReg {
			return errors.New("backup cannot contain anything other than regular files")
		}

		// Don't let someone feed us a path traversal escape attack.
		filename := filepath.Base(header.Name)

		var contents []byte

		_, err = tr.Read(contents)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}

		// Only restore the local pool key when performing a total system restore.
		if filename == "zpool.local.key" && !doTotalRestore {
			continue
		}

		// Restoring the actual state requires additional work.
		if filename == "state.txt" {
			newState := &state.State{}

			err := state.Decode(contents, nil, newState)
			if err != nil {
				return err
			}

			// TODO: Selectively filter out fields
			// TODO: Make sure list of configured applications is consistent with the new state
			// TODO: Sync recovery passphrases in new state. (assumes TPM unlocking is currently good)

			newState.SetPath(filepath.Join("/var/lib/incus-os/", filename))

			s = newState

			err = s.Save()
			if err != nil {
				return err
			}

			continue
		}

		// Write any other file to disk.
		err = os.WriteFile(filepath.Join("/var/lib/incus-os/", filename), contents, 0o600)
		if err != nil {
			return err
		}
	}

	// Remove the old /var/lib/incus-os/ backup.
	err = os.RemoveAll("/var/lib/incus-os.bak/")
	if err != nil {
		return err
	}

	reverter.Success()

	return nil
}
