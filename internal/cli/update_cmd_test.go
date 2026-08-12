package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dyneteq/Breach-Harbor/internal/selfupdate"
	"github.com/Dyneteq/Breach-Harbor/internal/version"
)

// fakeUpdateServer serves a minimal stand-in for the GitHub API +
// release-download hosts, publishing exactly one release ("tag")
// whose asset content is binContent — enough to drive update_cmd.go's
// full check/download/verify/install path without real network.
func fakeUpdateServer(t *testing.T, tag, binContent string) *httptest.Server {
	t.Helper()
	goos, goarch := "linux", "amd64" // arbitrary but must match the Updater under test
	asset := fmt.Sprintf("breachharbor_%s_%s_%s", tag, goos, goarch)

	var tarBuf bytes.Buffer
	gz := gzip.NewWriter(&tarBuf)
	tw := tar.NewWriter(gz)
	body := []byte(binContent)
	if err := tw.WriteHeader(&tar.Header{Name: asset + "/breachharbor", Mode: 0o755, Size: int64(len(body))}); err != nil {
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
	sum := sha256.Sum256(tarBuf.Bytes())
	checksumLine := fmt.Sprintf("%s  %s.tar.gz\n", hex.EncodeToString(sum[:]), asset)

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
	mux.HandleFunc("/fake/repo/releases/download/"+tag+"/"+asset+".tar.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarBuf.Bytes())
	})
	mux.HandleFunc("/fake/repo/releases/download/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, checksumLine)
	})
	return httptest.NewServer(mux)
}

// withFakeUpdater points newUpdater at srv for the duration of the
// test, restoring the real constructor afterward.
func withFakeUpdater(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := newUpdater
	newUpdater = func() *selfupdate.Updater {
		return &selfupdate.Updater{
			Repo:            "fake/repo",
			Client:          http.DefaultClient,
			GOOS:            "linux",
			GOARCH:          "amd64",
			APIBaseURL:      srv.URL,
			DownloadBaseURL: srv.URL,
		}
	}
	t.Cleanup(func() { newUpdater = orig })
}

func TestMain_Update_AlreadyUpToDate(t *testing.T) {
	srv := fakeUpdateServer(t, version.Version, "irrelevant")
	defer srv.Close()
	withFakeUpdater(t, srv)

	stdout, _, code := run("update")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Already up to date") {
		t.Errorf("expected an up-to-date message, got %q", stdout)
	}
}

func TestMain_Update_CheckOnly_DoesNotInstall(t *testing.T) {
	srv := fakeUpdateServer(t, "v99.0.0", "irrelevant")
	defer srv.Close()
	withFakeUpdater(t, srv)

	stdout, _, code := run("update", "--check")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "v99.0.0") {
		t.Errorf("expected the newer tag to be mentioned, got %q", stdout)
	}
	if !strings.Contains(stdout, "available") {
		t.Errorf("expected an availability message, got %q", stdout)
	}
}

func TestMain_Update_InstallsOverRunningBinary(t *testing.T) {
	dir := t.TempDir()
	fakeExe := filepath.Join(dir, "breachharbor")
	if err := os.WriteFile(fakeExe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	origExecutable := executableOverride
	executableOverride = func() (string, error) { return fakeExe, nil }
	t.Cleanup(func() { executableOverride = origExecutable })

	srv := fakeUpdateServer(t, "v99.0.0", "new-binary-content")
	defer srv.Close()
	withFakeUpdater(t, srv)

	stdout, _, code := run("update")
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "Updated to v99.0.0") {
		t.Errorf("expected an updated confirmation, got %q", stdout)
	}

	content, err := os.ReadFile(fakeExe)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new-binary-content" {
		t.Errorf("target content = %q, want %q", content, "new-binary-content")
	}
}

func TestMain_Update_JSON(t *testing.T) {
	srv := fakeUpdateServer(t, version.Version, "irrelevant")
	defer srv.Close()
	withFakeUpdater(t, srv)

	stdout, _, code := run("update", "--json")
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if !strings.Contains(stdout, `"up_to_date": true`) {
		t.Errorf("expected JSON reporting up_to_date, got %q", stdout)
	}
}

func TestMain_Update_UnknownVersion(t *testing.T) {
	srv := fakeUpdateServer(t, "v1.0.0", "irrelevant")
	defer srv.Close()
	withFakeUpdater(t, srv)

	_, stderr, code := run("update", "--version", "v9.9.9")
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "breachharbor:") {
		t.Errorf("expected an actionable error prefix, got %q", stderr)
	}
}
