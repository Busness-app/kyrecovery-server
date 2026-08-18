package capsule

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ReadManifestFromFile reads only the manifest from a .kycap file on disk in O(1) memory.
func ReadManifestFromFile(capsulePath string) (*Manifest, error) {
	f, err := os.Open(capsulePath)
	if err != nil {
		return nil, fmt.Errorf("failed opening capsule file %s: %w", capsulePath, err)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading archive header: %w", err)
		}
		if hdr.Name == "manifest.json" {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				return nil, err
			}
			return &m, nil
		}
	}
	return nil, errors.New("manifest.json not found in capsule archive")
}
