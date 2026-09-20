package remote

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Exonical/stigctl/internal/baseline"
)

func CreatePayload(contentRoot string, resolved baseline.Resolved, profiles []string) (string, func(), error) {
	file, err := os.CreateTemp("", "stigctl-remote-*.tar.gz")
	if err != nil {
		return "", func() {}, fmt.Errorf("create remote payload: %w", err)
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }

	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	closeWithError := func() error {
		if err := tw.Close(); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		return file.Close()
	}

	product, release, _ := strings.Cut(resolved.Ref, ":")
	if err := addTree(tw, resolved.Path, filepath.Join("content", "stig", product, release)); err != nil {
		_ = closeWithError()
		cleanup()
		return "", func() {}, err
	}
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if _, ok := seen[profile]; ok {
			continue
		}
		seen[profile] = struct{}{}
		source := filepath.Join(contentRoot, "profiles", profile+".yaml")
		name := filepath.Join("content", "profiles", profile+".yaml")
		if err := addFile(tw, source, name); err != nil {
			_ = closeWithError()
			cleanup()
			return "", func() {}, err
		}
	}
	if err := closeWithError(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("close remote payload: %w", err)
	}
	return path, cleanup, nil
}

func addTree(tw *tar.Writer, root, prefix string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("remote payload does not allow symlink %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		return addFile(tw, path, filepath.Join(prefix, rel))
	})
}

func addFile(tw *tar.Writer, source, name string) error {
	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat payload file %s: %w", source, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("payload file %s is not a regular file", source)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(name)
	header.Mode = 0o600
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(tw, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
