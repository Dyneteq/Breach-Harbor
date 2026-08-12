// Package selfupdate checks GitHub Releases for a newer breachharbor
// build and installs it over the running binary. It mirrors the same
// asset layout install.sh downloads (see .github/workflows/release.yml):
// breachharbor_<tag>_<goos>_<goarch>.tar.gz plus a combined
// checksums.txt, both attached to the GitHub Release for that tag.
package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultRepo is the GitHub owner/repo releases are published under.
const DefaultRepo = "Dyneteq/Breach-Harbor"

// Updater checks for and installs newer breachharbor releases.
type Updater struct {
	// Repo is the GitHub owner/repo to check, e.g. "Dyneteq/Breach-Harbor".
	Repo string
	// Client is the HTTP client used for all requests. Defaults to a
	// 60s-timeout client — release tarballs are a few MB.
	Client *http.Client
	// GOOS/GOARCH select which release asset to fetch. Default to the
	// running binary's own runtime.GOOS/runtime.GOARCH.
	GOOS, GOARCH string
	// APIBaseURL and DownloadBaseURL are overridable for tests; they
	// default to the real GitHub API and github.com release-download
	// hosts.
	APIBaseURL      string
	DownloadBaseURL string
}

// New returns an Updater targeting the real breachharbor repo on the
// running binary's own OS/arch.
func New() *Updater {
	return &Updater{
		Repo:            DefaultRepo,
		Client:          &http.Client{Timeout: 60 * time.Second},
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		APIBaseURL:      "https://api.github.com",
		DownloadBaseURL: "https://github.com",
	}
}

// Release identifies one published GitHub Release by tag.
type Release struct {
	Tag string
}

type releasePayload struct {
	TagName string `json:"tag_name"`
}

// Resolve looks up a release by tag ("latest" resolves to the newest
// published release).
func (u *Updater) Resolve(ctx context.Context, tag string) (Release, error) {
	if tag == "" {
		tag = "latest"
	}
	url := fmt.Sprintf("%s/repos/%s/releases/latest", u.APIBaseURL, u.Repo)
	if tag != "latest" {
		url = fmt.Sprintf("%s/repos/%s/releases/tags/%s", u.APIBaseURL, u.Repo, tag)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, err
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return Release{}, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Release{}, fmt.Errorf("no release %q found for %s", tag, u.Repo)
	}
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}

	var p releasePayload
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return Release{}, fmt.Errorf("decode release metadata from %s: %w", url, err)
	}
	if p.TagName == "" {
		return Release{}, fmt.Errorf("no tag_name in release metadata from %s", url)
	}
	return Release{Tag: p.TagName}, nil
}

// AssetName is the base name (no extension) of the release tarball
// for this Updater's OS/arch — must match release.yml's ASSET naming.
func (u *Updater) AssetName(tag string) string {
	return fmt.Sprintf("breachharbor_%s_%s_%s", tag, u.GOOS, u.GOARCH)
}

func (u *Updater) download(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := u.Client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch %s: unexpected status %s", url, resp.Status)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}
	return nil
}

// Fetch downloads and checksum-verifies the release tarball for rel,
// then extracts the breachharbor binary into a temp directory. The
// caller must invoke the returned cleanup once done with binPath (and
// after every Install call that reads it).
func (u *Updater) Fetch(ctx context.Context, rel Release) (binPath string, cleanup func(), err error) {
	asset := u.AssetName(rel.Tag)
	base := fmt.Sprintf("%s/%s/releases/download/%s", u.DownloadBaseURL, u.Repo, rel.Tag)

	tmpDir, err := os.MkdirTemp("", "breachharbor-update-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(tmpDir) }

	tarName := asset + ".tar.gz"
	tarPath := filepath.Join(tmpDir, tarName)
	if err := u.download(ctx, base+"/"+tarName, tarPath); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("download %s: %w (no build published for %s/%s in %s?)", tarName, err, u.GOOS, u.GOARCH, rel.Tag)
	}

	sumsPath := filepath.Join(tmpDir, "checksums.txt")
	if err := u.download(ctx, base+"/checksums.txt", sumsPath); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("download checksums.txt: %w", err)
	}

	if err := verifyChecksum(tarPath, sumsPath, tarName); err != nil {
		cleanup()
		return "", nil, err
	}

	binPath, err = extractBinary(tarPath, tmpDir, asset)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return binPath, cleanup, nil
}

// verifyChecksum confirms filePath's sha256 matches the entry for
// wantName inside a "checksums.txt" (sha256sum-format: "<hex>  <name>"
// per line, as produced by `sha256sum` in release.yml).
func verifyChecksum(filePath, checksumsPath, wantName string) error {
	data, err := os.ReadFile(checksumsPath)
	if err != nil {
		return err
	}
	var expected string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[1] == wantName || strings.TrimPrefix(fields[1], "*") == wantName {
			expected = fields[0]
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("no checksum entry for %s in checksums.txt", wantName)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", wantName, expected, actual)
	}
	return nil
}

// extractBinary pulls the "breachharbor" binary out of a release
// tarball (layout: <asset>/breachharbor, matching release.yml) into
// destDir, returning its path.
func extractBinary(tarPath, destDir, asset string) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("open %s as gzip: %w", tarPath, err)
	}
	defer gz.Close()

	wantName := filepath.Join(asset, "breachharbor")
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("%s: no %s entry found", tarPath, wantName)
		}
		if err != nil {
			return "", fmt.Errorf("read %s: %w", tarPath, err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Clean(hdr.Name) != wantName {
			continue
		}
		outPath := filepath.Join(destDir, "breachharbor")
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return "", err
		}
		// #nosec G110 -- release tarballs are our own build output,
		// bounded by GitHub's asset size limits, not attacker input.
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return "", fmt.Errorf("extract %s: %w", wantName, err)
		}
		if err := out.Close(); err != nil {
			return "", err
		}
		return outPath, nil
	}
}

// Install atomically replaces targetPath with the contents of
// srcPath: write alongside targetPath (same directory, so the final
// rename is same-filesystem and therefore atomic), then rename over
// it. Leaves targetPath untouched on any failure.
func Install(srcPath, targetPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".breachharbor-update-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("install over %s: %w", targetPath, err)
	}
	return nil
}
