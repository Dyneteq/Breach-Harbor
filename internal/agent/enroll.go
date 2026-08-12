package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Enrollment is what `agent enroll <url> --token` persists to
// <data-dir>/enrollment.json: the server URL, the collector bearer
// token, and the server's blocklist-signing public key pinned at
// enroll time (bare TOFU — PLAN.md's M3 sketch adds pinning/rotation
// hardening on top of this).
type Enrollment struct {
	ServerURL     string    `json:"server_url"`
	Token         string    `json:"token"`
	CollectorName string    `json:"collector_name"`
	PublicKey     []byte    `json:"public_key"`
	EnrolledAt    time.Time `json:"enrolled_at"`
}

func enrollmentPath(dataDir string) string { return filepath.Join(dataDir, "enrollment.json") }

// LoadEnrollment reads the persisted enrollment, if any. found=false
// with a nil error means standalone — nothing has been enrolled yet,
// which is the default, fully-supported state (PLAN.md: "Optional"
// next to `agent enroll` in the command tree).
func LoadEnrollment(dataDir string) (Enrollment, bool, error) {
	data, err := os.ReadFile(enrollmentPath(dataDir))
	if err != nil {
		if os.IsNotExist(err) {
			return Enrollment{}, false, nil
		}
		return Enrollment{}, false, fmt.Errorf("read enrollment: %w", err)
	}
	var e Enrollment
	if err := json.Unmarshal(data, &e); err != nil {
		return Enrollment{}, false, fmt.Errorf("corrupt enrollment file %s: %w", enrollmentPath(dataDir), err)
	}
	return e, true, nil
}

// SaveEnrollment writes atomically at 0600 — the file contains a live
// bearer token.
func SaveEnrollment(dataDir string, e Enrollment) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data directory %s: %w", dataDir, err)
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp := enrollmentPath(dataDir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, enrollmentPath(dataDir))
}

// RemoveEnrollment reverts an agent to standalone. Removing a
// never-enrolled agent's (nonexistent) file is a safe no-op.
func RemoveEnrollment(dataDir string) error {
	err := os.Remove(enrollmentPath(dataDir))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// enrollAPIResponse mirrors internal/server/enroll.go's response
// shape. Duplicated rather than imported — internal/server pulls in
// gorm/gin, far more than internal/agent should depend on for one
// struct's shape.
type enrollAPIResponse struct {
	CollectorName string `json:"collector_name"`
	CollectorIP   string `json:"collector_ip"`
	PublicKey     []byte `json:"public_key"`
}

// Enroll calls POST <serverURL>/v1/enroll with token and, on success,
// returns an Enrollment ready to persist. It never writes to disk
// itself — internal/cli/agent_enroll.go decides when to save it.
func Enroll(ctx context.Context, client *http.Client, serverURL, token string) (Enrollment, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	url := strings.TrimRight(serverURL, "/") + "/v1/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return Enrollment{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return Enrollment{}, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Enrollment{}, fmt.Errorf("enroll: server returned %s", resp.Status)
	}

	var er enrollAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return Enrollment{}, fmt.Errorf("enroll: decode response: %w", err)
	}
	if len(er.PublicKey) == 0 {
		return Enrollment{}, fmt.Errorf("enroll: server did not return a signing public key")
	}

	return Enrollment{
		ServerURL:     serverURL,
		Token:         token,
		CollectorName: er.CollectorName,
		PublicKey:     er.PublicKey,
		EnrolledAt:    time.Now(),
	}, nil
}
