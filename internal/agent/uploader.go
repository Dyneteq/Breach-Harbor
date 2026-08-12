package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Dyneteq/Breach-Harbor/internal/blocklist"
	"github.com/Dyneteq/Breach-Harbor/internal/store"
)

// uploadBatchSize bounds how many queued observations go into one
// POST /v1/observations request.
const uploadBatchSize = 100

// Uploader is what an enrolled agent uses to drain its local
// observation queue to the server and to fetch/verify/merge the
// server's published blocklist — PLAN.md M2 item 7: "persisted
// enrollment, batched fire-and-forget uploads with backoff, blocklist
// fetch/verify/merge (union with local-synth entries, never replace)."
type Uploader struct {
	Store      store.AgentStore
	Enrollment Enrollment
	Client     *http.Client
	Logf       func(format string, args ...any)
}

func NewUploader(st store.AgentStore, enrollment Enrollment) *Uploader {
	return &Uploader{
		Store:      st,
		Enrollment: enrollment,
		Client:     &http.Client{Timeout: 30 * time.Second},
		Logf:       func(string, ...any) {},
	}
}

type observationPayload struct {
	IP           string                 `json:"ip"`
	IncidentType string                 `json:"incident_type"`
	HappenedAt   time.Time              `json:"happened_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type observationsPayload struct {
	Observations []observationPayload `json:"observations"`
}

// UploadPending drains up to uploadBatchSize queued observations and
// POSTs them in one batch. Nothing is Acked (removed from the queue)
// unless the upload succeeds — a failed attempt is retried wholesale
// on the next call ("fire-and-forget" from the caller's perspective,
// never silently lossy from the queue's).
func (u *Uploader) UploadPending(ctx context.Context) (int, error) {
	obs, err := u.Store.Dequeue(uploadBatchSize)
	if err != nil {
		return 0, fmt.Errorf("dequeue observations: %w", err)
	}
	if len(obs) == 0 {
		return 0, nil
	}

	body := observationsPayload{Observations: make([]observationPayload, 0, len(obs))}
	ids := make([]string, 0, len(obs))
	for _, o := range obs {
		body.Observations = append(body.Observations, observationPayload{
			IP:           o.IP.String(),
			IncidentType: o.Kind,
			HappenedAt:   o.Time,
			Metadata:     metadataToAny(o.Metadata),
		})
		ids = append(ids, o.ID)
	}

	data, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}

	url := strings.TrimRight(u.Enrollment.ServerURL, "/") + "/v1/observations"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+u.Enrollment.Token)

	resp, err := u.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("upload %d observation(s): %w", len(obs), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("upload %d observation(s): server returned %s", len(obs), resp.Status)
	}

	if err := u.Store.Ack(ids); err != nil {
		return 0, fmt.Errorf("ack uploaded observations: %w", err)
	}
	return len(obs), nil
}

func metadataToAny(m map[string]string) map[string]interface{} {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// RefreshBlocklist fetches and verifies the server's current
// blocklist, merges it with localEntries (union by prefix, never
// overwrite), and persists the fetched copy so a later restart still
// has it if the server becomes unreachable — "cache first, ask later"
// applied to the agent side of enrollment. On any fetch/verify
// failure it falls back to the last cached copy (if any), merged with
// localEntries, and returns the failure as a non-fatal error for the
// caller to log.
// Heartbeat tells the server this agent is alive and reachable right
// now — unlike UploadPending, it fires on every tick regardless of
// whether there's anything queued, which is the whole point: a quiet
// agent that has detected nothing still needs to show up as present,
// not indistinguishable from a dead one. No body, no queue
// interaction; just a bearer-token POST.
func (u *Uploader) Heartbeat(ctx context.Context) error {
	url := strings.TrimRight(u.Enrollment.ServerURL, "/") + "/v1/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+u.Enrollment.Token)

	resp, err := u.Client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("heartbeat: server returned %s", resp.Status)
	}
	return nil
}

// firewallStatusPayload is what POST /v1/firewall-status carries: a
// point-in-time snapshot of this agent's firewall.Backend, so the
// dashboard can show what's actually being enforced right now, not
// just whether the agent claims to be in enforce mode.
type firewallStatusPayload struct {
	Backend    string   `json:"backend"`
	Enforcing  bool     `json:"enforcing"`
	BlockedIPs []string `json:"blocked_ips"`
	// Config is the backend's raw Status() dump — the host's whole
	// ruleset, not just BlockedIPs — for display only.
	Config string `json:"config"`
}

// SendFirewallStatus reports this agent's firewall.Backend's current
// state to the server: which backend, whether it's actually enforcing,
// which addresses it has blocked right now (its own rules, not the
// server's published blocklist), and the backend's raw ruleset dump.
// Like Heartbeat, this is fire-and-forget — no queue, no retry; the
// next tick sends a fresh snapshot regardless of whether this one
// landed.
func (u *Uploader) SendFirewallStatus(ctx context.Context, backend string, enforcing bool, blockedIPs []string, config string) error {
	body := firewallStatusPayload{Backend: backend, Enforcing: enforcing, BlockedIPs: blockedIPs, Config: config}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	url := strings.TrimRight(u.Enrollment.ServerURL, "/") + "/v1/firewall-status"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+u.Enrollment.Token)

	resp, err := u.Client.Do(req)
	if err != nil {
		return fmt.Errorf("firewall status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("firewall status: server returned %s", resp.Status)
	}
	return nil
}

func (u *Uploader) RefreshBlocklist(ctx context.Context, localEntries []blocklist.Entry) ([]blocklist.Entry, error) {
	fetched, err := blocklist.FetchAndVerify(ctx, u.Client, u.Enrollment.ServerURL, u.Enrollment.Token, u.Enrollment.PublicKey)
	if err != nil {
		cached, found, cerr := u.Store.LoadBlocklist()
		if cerr == nil && found {
			return blocklist.Merge(localEntries, cached.Blocklist.Entries), fmt.Errorf("fetch blocklist (serving last cached copy from %s): %w", cached.Blocklist.GeneratedAt.Format(time.RFC3339), err)
		}
		return localEntries, fmt.Errorf("fetch blocklist (no cached copy available yet): %w", err)
	}

	// The signature itself isn't re-derivable from FetchAndVerify's
	// already-verified return value — that's fine, since this on-disk
	// copy only needs to survive as *content* across a restart; it was
	// verified once, on the way in, and is trusted from then on the
	// same way the rest of this file's local state is.
	if err := u.Store.SaveBlocklist(blocklist.SignedBlocklist{Blocklist: *fetched, PublicKey: u.Enrollment.PublicKey}); err != nil {
		u.Logf("save fetched blocklist: %v", err)
	}

	return blocklist.Merge(localEntries, fetched.Entries), nil
}
