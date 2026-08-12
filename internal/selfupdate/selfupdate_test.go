package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildFakeAsset produces a tar.gz containing "<asset>/breachharbor"
// with the given content, plus a matching checksums.txt line — the
// same shape release.yml publishes.
func buildFakeAsset(t *testing.T, asset, content string) (tarBytes []byte, checksumLine string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte(content)
	if err := tw.WriteHeader(&tar.Header{
		Name: asset + "/breachharbor",
		Mode: 0o755,
		Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(buf.Bytes())
	line := fmt.Sprintf("%s  %s.tar.gz\n", hex.EncodeToString(sum[:]), asset)
	return buf.Bytes(), line
}

// newFakeGitHub serves a minimal stand-in for the GitHub API +
// release-download hosts install.sh and this package both talk to.
func newFakeGitHub(t *testing.T, tag, goos, goarch, binContent string) (apiURL, downloadURL string, closeFn func()) {
	t.Helper()
	asset := fmt.Sprintf("breachharbor_%s_%s_%s", tag, goos, goarch)
	tarBytes, checksumLine := buildFakeAsset(t, asset, binContent)

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/fake/repo/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name": %q}`, tag)
	})
	mux.HandleFunc("/repos/fake/repo/releases/tags/", func(w http.ResponseWriter, r *http.Request) {
		reqTag := strings.TrimPrefix(r.URL.Path, "/repos/fake/repo/releases/tags/")
		if reqTag != tag {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"tag_name": %q}`, tag)
	})
	mux.HandleFunc(fmt.Sprintf("/fake/repo/releases/download/%s/%s.tar.gz", tag, asset), func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarBytes)
	})
	mux.HandleFunc(fmt.Sprintf("/fake/repo/releases/download/%s/checksums.txt", tag), func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, checksumLine)
	})

	srv := httptest.NewServer(mux)
	return srv.URL, srv.URL, srv.Close
}

func testUpdater(t *testing.T, tag, goos, goarch, binContent string) *Updater {
	t.Helper()
	apiURL, downloadURL, closeFn := newFakeGitHub(t, tag, goos, goarch, binContent)
	t.Cleanup(closeFn)
	return &Updater{
		Repo:            "fake/repo",
		Client:          http.DefaultClient,
		GOOS:            goos,
		GOARCH:          goarch,
		APIBaseURL:      apiURL,
		DownloadBaseURL: downloadURL,
	}
}

func TestResolve_Latest(t *testing.T) {
	u := testUpdater(t, "v1.2.3", "linux", "amd64", "binary-content")
	rel, err := u.Resolve(context.Background(), "latest")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rel.Tag != "v1.2.3" {
		t.Errorf("Tag = %q, want v1.2.3", rel.Tag)
	}
}

func TestResolve_SpecificTag(t *testing.T) {
	u := testUpdater(t, "v1.2.3", "linux", "amd64", "binary-content")
	rel, err := u.Resolve(context.Background(), "v1.2.3")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rel.Tag != "v1.2.3" {
		t.Errorf("Tag = %q, want v1.2.3", rel.Tag)
	}
}

func TestResolve_UnknownTag(t *testing.T) {
	u := testUpdater(t, "v1.2.3", "linux", "amd64", "binary-content")
	if _, err := u.Resolve(context.Background(), "v9.9.9"); err == nil {
		t.Fatal("expected an error for an unknown tag, got nil")
	}
}

func TestFetch_DownloadsVerifiesAndExtracts(t *testing.T) {
	u := testUpdater(t, "v1.2.3", "linux", "amd64", "totally-a-binary")
	binPath, cleanup, err := u.Fetch(context.Background(), Release{Tag: "v1.2.3"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer cleanup()

	content, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", binPath, err)
	}
	if string(content) != "totally-a-binary" {
		t.Errorf("extracted content = %q, want %q", content, "totally-a-binary")
	}

	info, err := os.Stat(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("extracted binary is not executable: mode = %v", info.Mode())
	}
}

func TestFetch_NoAssetForPlatform(t *testing.T) {
	// Server only has a linux/amd64 asset; ask for darwin/arm64.
	u := testUpdater(t, "v1.2.3", "linux", "amd64", "totally-a-binary")
	u.GOOS, u.GOARCH = "darwin", "arm64"

	_, _, err := u.Fetch(context.Background(), Release{Tag: "v1.2.3"})
	if err == nil {
		t.Fatal("expected an error when no asset exists for this platform, got nil")
	}
}

func TestFetch_ChecksumMismatchRejected(t *testing.T) {
	u := testUpdater(t, "v1.2.3", "linux", "amd64", "totally-a-binary")

	// Tamper with the served tarball's content by pointing at a server
	// that mismatches the checksum: simplest way is to corrupt one of
	// the two independently-derived pieces. Rebuild a checksums.txt
	// with a wrong hash for the same tag, sharing the tarball handler.
	mux := http.NewServeMux()
	asset := "breachharbor_v1.2.3_linux_amd64"
	tarBytes, _ := buildFakeAsset(t, asset, "totally-a-binary")
	mux.HandleFunc("/repos/fake/repo/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v1.2.3"}`)
	})
	mux.HandleFunc("/fake/repo/releases/download/v1.2.3/"+asset+".tar.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarBytes)
	})
	mux.HandleFunc("/fake/repo/releases/download/v1.2.3/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s.tar.gz\n", strings.Repeat("0", 64), asset)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u.APIBaseURL = srv.URL
	u.DownloadBaseURL = srv.URL

	_, _, err := u.Fetch(context.Background(), Release{Tag: "v1.2.3"})
	if err == nil {
		t.Fatal("expected a checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected a checksum mismatch error, got: %v", err)
	}
}

func TestInstall_ReplacesTargetAtomically(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "breachharbor")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "breachharbor")
	if err := os.WriteFile(src, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Install(src, target); err != nil {
		t.Fatalf("Install: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new" {
		t.Errorf("target content = %q, want %q", content, "new")
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("installed binary is not executable: mode = %v", info.Mode())
	}
}

func TestInstall_LeavesNoTempFileBehindOnSuccess(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "breachharbor")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "breachharbor")
	if err := os.WriteFile(src, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Install(src, target); err != nil {
		t.Fatalf("Install: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly 1 entry in %s after Install, got %d: %v", dir, len(entries), entries)
	}
}
