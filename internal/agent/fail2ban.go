package agent

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
)

// Fail2banChecker reports whether fail2ban has already banned an IP in
// one of its own jails. Queried live via fail2ban-client rather than
// relying solely on internal/logsource/fail2ban.go's log tailer, so a
// block decision reached from any event source — not just a re-emitted
// "Ban" log line — still sees fail2ban's current state before adding a
// rule of our own.
type Fail2banChecker interface {
	Banned(ctx context.Context, ip netip.Addr) bool
}

// fail2banClient implements Fail2banChecker via the fail2ban-client
// CLI, the only interface fail2ban itself exposes for querying live
// ban state.
type fail2banClient struct{}

// NewFail2banClient returns a Fail2banChecker backed by the real
// fail2ban-client binary. Every query is best-effort: fail2ban-client
// missing, fail2ban not running, or no permission to reach its socket
// all report "not banned" rather than erroring, so a host without
// fail2ban behaves exactly as it did before this check existed — it
// never blocks or fails a real block decision.
func NewFail2banClient() Fail2banChecker { return fail2banClient{} }

// Banned runs `fail2ban-client banned <ip>`, which prints the list of
// jails currently banning ip — "[]" if none do. Any output other than
// an empty list is treated as banned; any command failure is treated
// as not banned (see NewFail2banClient).
func (fail2banClient) Banned(ctx context.Context, ip netip.Addr) bool {
	out, err := exec.CommandContext(ctx, "fail2ban-client", "banned", ip.String()).Output()
	if err != nil {
		return false
	}
	trimmed := strings.TrimSpace(string(out))
	return trimmed != "" && trimmed != "[]"
}
