package providers

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
)

func downloadAsset(ctx context.Context, client *http.Client, assetURL string, expectedSHA256 string, target string, progressFunc func(float64)) error {
	// Prepare the request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return err
	}

	// Get a reader for the release asset.
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Get the release asset size.
	srcSize := float64(resp.ContentLength)

	// Setup a sha256 hasher.
	h := sha256.New()

	// Setup the main reader.
	tr := io.TeeReader(resp.Body, h)

	// Setup a gzip reader to decompress during streaming.
	body, err := gzip.NewReader(tr)
	if err != nil {
		return err
	}

	defer body.Close()

	// Create the target path.
	// #nosec G304
	fd, err := os.Create(target)
	if err != nil {
		return err
	}

	defer fd.Close()

	// Read from the decompressor in chunks to avoid excessive memory consumption.
	count := int64(0)

	for {
		_, err = io.CopyN(fd, body, 4*1024*1024)
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

	// Check the hash.
	if expectedSHA256 != "" && expectedSHA256 != hex.EncodeToString(h.Sum(nil)) {
		return errors.New("sha256 mismatch for file " + target)
	}

	return nil
}
