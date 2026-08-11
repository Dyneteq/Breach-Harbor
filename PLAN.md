# Breach Harbor — unified CLI restructuring plan

This is the full restructuring plan (all milestones), kept in the repo so any session — not just
the one that wrote it — can pick up work with full context. It supersedes `M1_PLAN.md` (deleted;
its M1 refinements are folded into the M1 section below).

## Progress

- ✅ **M0 — it builds.** Done, merged onto branch `restructure/m0-it-builds` (pushed to origin;
  confirm whether it's merged to `master` yet — open a PR if not). Commits: `65da53a` (M0 itself),
  `2222cd5` (post-M0 cleanup: consolidated `cmd/bh` into a single source built under two output
  names, removed stray Python/`.vscode` cruft, trimmed README). One deviation from the original
  design below worth knowing: the "two independent `main.go` files" plan for the `bh` alias
  (§ Target file/package layout) was simplified during cleanup — there is only
  `cmd/breachharbor/main.go`; the Makefile builds `bin/bh` from that same source via
  `go build -o bin/bh ./cmd/breachharbor`. **Do not recreate `cmd/bh/`.**
- ✅ **M1 — the agent stands alone.** Implemented on branch `restructure/m1-agent-stands-alone`
  (off `restructure/m0-it-builds`), commits from `588eb5d` (`internal/logsource`) through
  `dc562c9` (doctor rows) — see that branch's log for the full incremental history (one commit per
  package/feature area, per the working conventions below). All ten M1 checklist items are done:
  `internal/logsource` (fail2ban/journal/authlog/nginx + fixtures), `internal/agent/offender.go`
  (fixed-weight sliding-window scoring), `internal/agent/agent.go` (the run loop),
  `internal/agent/config.go`, `internal/feed` (spamhaus/firehol/tor/abuseipdb + TTL cache),
  `internal/store/filestore.go` (+ lock-free `ReadOffenders`/`ReadQueueDepth` for status/top/sources
  to read a *live* agent's state without contending its exclusive lock — a gap only found while
  wiring the CLI), `internal/agent/systemd.go`, and real `agent run/status/top/enforce/sources/
  install/uninstall` in `internal/cli`. `go build ./... && go vet ./... && go test ./... -race &&
  gofmt -l .` all clean; cross-compiles verified for linux/amd64, linux/arm64, darwin/arm64; manually
  smoke-tested against a real scratch `--data-dir` on this darwin dev box (dry-run banner, zero
  sources/no firewall correctly detected, real feed fetches over the network, `status`/`top`/
  `sources` reading the live agent's state concurrently with no lock contention).
  **Known gaps, called out rather than silently skipped:**
  - The `agent run`/`agent status`/`agent top` console wording is close to but not a pixel-perfect
    match of the example transcripts in this doc's "Full CLI command tree" section — the
    *substance* (dry-run countdown, per-source probe rows, WOULD BLOCK/BLOCKED lines, live top
    table) is all there; exact spacing/phrasing was not chased line-for-line.
  - The systemd unit (`internal/agent/systemd.go`) is **unverified on a real Linux/systemd host** —
    no such machine was available in the environment that built it. `AmbientCapabilities=
    CAP_NET_ADMIN CAP_NET_RAW` sufficing for nft/ipset without full root is a real open question;
    the `--root` fallback exists precisely because of that. Verify on a real box before relying on
    the non-root path.
  - No real-VM demo was performed (simulate SSH brute force → confirm blocking end-to-end) — the
    logic paths are covered by unit tests (`internal/agent/agent_test.go`'s dry-run/enforcing/
    feed-match/block-failure cases) and one darwin smoke test, but PLAN.md's own M1 demo script
    (a fresh Linux VM with sshd/nginx/fail2ban) was not run.
  - `agent run`'s `--config` flag is accepted but explicitly rejected ("not implemented") — no file
    config loader was built, flags only, as scoped.
- ✅ **M2 — the server is useful.** Implemented on branch
  `restructure/m2-server-is-useful` (off `restructure/m1-agent-stands-alone`),
  commits `1e0a91f` through `7fbf933` — see that branch's log for the full
  incremental history. All ten M2 checklist items are done: `internal/server`
  (the HTTP bootstrap that never existed — `server.go`/`http.go`/`ingest.go`/
  `enroll.go`/`publisher.go`/`systemd.go`), `middleware/auth.go` (header-then-
  cookie, split into `AuthMiddleware`/`WebAuthMiddleware`), `models.Collector
  .TokenHash` + batched ingest (`CreateInBatches`), `services/dashboard.go`'s
  N+1 fix (one grouped query), `services/location.go` real ASN/hosting/Tor
  enrichment (`internal/feed/asn.go`'s curated table + a second GeoLite2-ASN
  reader + a swappable Tor index), `internal/blocklist` (ed25519 sign/verify/
  publish + agent-side fetch/verify/merge), `internal/agent/enroll.go` +
  `uploader.go`, `server run/install/status` CLI, `agent enroll` CLI, and
  `handlers/web.go`'s `HandleDeleteCollector` stub + the token-in-plaintext
  bug (now shown once at creation, only a hash persists). `go build ./...`,
  `go vet ./...`, `go test ./... -race`, and `gofmt -l .` all clean on M2's
  own code; cross-compiles verified for linux/amd64, linux/arm64,
  darwin/arm64; a real `breachharbor server run` was smoke-tested standalone
  on this darwin box and inside the actual `docker build`-produced image
  (health check, login/register/dashboard/collectors/incidents/ip-addresses
  pages, collector create-with-token-banner and delete, all verified over
  real HTTP against a real SQLite DB) — this caught and fixed a real crash
  (`SetFuncMap` needed before `LoadHTMLGlob`, see gaps below) that unit
  tests alone hadn't exercised. `internal/server/e2e_test.go`'s
  `TestEndToEnd_EnrollObserveIngestPublishFetchVerifyMerge` automates
  PLAN.md's own M2 demo script end to end, including the "kill the server
  mid-session" cache-fallback assertion.
  **Known gaps, called out rather than silently skipped:**
  - `agent enroll` only takes effect on the *next* `agent run` — a
    currently-running agent process only reads its enrollment file at
    startup (unlike `agent enforce --on/--off`, which a live process
    reconciles from disk every 3s). Documented in the CLI's own output;
    could be wired onto the same `stateTicker` in a follow-up if it turns
    out to matter in practice.
  - No dedicated `httptest` coverage was added for the pre-existing JSON
    REST handlers (`handlers/auth.go`'s `Login`/`Register`/`GetCurrentUser`,
    `handlers/collector.go`'s `GetCollectors`/`GetCollectorByName`/
    `GetIncidents*`, `handlers/dashboard.go`'s `GetIPAddresses*`) — that
    code predates this milestone and wasn't modified, so the risk is lower,
    but it's still unexercised by any automated test through `internal/server`'s
    router specifically (only indirectly, via the manual dashboard smoke
    test above, for the HTML-rendering equivalents).
  - `services/location.go`'s ASN/City enrichment was only exercised against
    the no-MaxMind-database fallback path (no `.mmdb` files were available
    in the environment that built this) — the actual `geoip2.Reader.ASN()`/
    `.City()` lookup paths, and the real field values MaxMind's databases
    return, are unverified against real data. Verify with real
    `GeoLite2-City.mmdb`/`GeoLite2-ASN.mmdb` files before relying on
    ISP/ASN/datacenter enrichment being accurate.
  - The blocklist's "cross-collector consensus" half
    (`internal/server/publisher.go`'s `confirmedFromIncidents`: ≥3
    incidents for one IP across any collector in 24h) is a judgment call
    with no explicit spec in this plan to match against — tune the
    threshold/window against real traffic before relying on it, same
    caveat as the agent's own offender-scoring weights.
  - `server install`'s systemd unit (`internal/server/systemd.go`) has the
    same **unverified-on-a-real-systemd-host** caveat M1's agent unit
    still carries — no such machine was available here either.
  - No real two-machine demo (a real agent box + a real server box) was
    run — the full loop is covered by `TestEndToEnd_...` (in-process,
    `httptest`) plus the manual single-box smoke tests above, but not
    across an actual network between two separate hosts.
  - `internal/logsource`'s `testdata/*.log` fixture gap (from a
    `.gitignore` rule that silently excluded them) was found and fixed
    directly on `restructure/m1-agent-stands-alone` (commit `b17ede2`,
    concurrently with this M2 work, in another session) — that fix hadn't
    been merged into `restructure/m2-server-is-useful` as of M2's last
    commit here, so `go test ./...` on this branch alone still shows 6
    unrelated `internal/logsource` failures until the branches are merged.
    Not an M2 regression; nothing in M2 touches `internal/logsource`.
  - Open question #1 (`Collector` → `Agent` rename) was decided: **kept as
    `Collector`** — renaming touched enough of the existing, working
    services/handlers/templates layer that it wasn't worth the churn for
    this milestone.

- Sketch only: M3 (trust hardening), M4 (sharing).

Before starting M3, confirm the branch is still green:
`go build ./... && go vet ./... && go test ./... && gofmt -l .` — and merge
`restructure/m1-agent-stands-alone`'s `b17ede2` (or its equivalent) in
first, to pick up the `internal/logsource` test-fixture fix noted above.

## Context

This repo (`Dyneteq/Breach-Harbor`) did not build at the start of this project: `cmd/server/main.go`
was documented in the README but had never existed in git history, and the entire HTTP bootstrap
(router registration, `gorm.Open()`, template loading) was missing. On top of that, 8,675 of 8,714
tracked files were a stray Python virtualenv accidentally committed during the migration from an
old Django+React stack (fixed in M0), the repo mixed a marketing site with the Go app, the
Dockerfile couldn't work (CGO-disabled build against a CGO-only sqlite driver), and several
security/correctness bugs existed in the data layer (plaintext collector tokens, a `Metadata`
field that couldn't round-trip through the DB, dead `Location` enrichment fields).

The goal of this restructuring is to turn this into **one Go module, one static binary, two
modes** (`breachharbor agent` / `breachharbor server`) — a threat-blocking agent people can
install in five minutes and actually understand. Every design choice below is judged against
that: dry-run by default, zero required config, fully reversible enforcement, cache-first so the
agent never depends on a live server, no AI/ML, pluggable firewall/log-source/feed backends. This
plan covers M0–M2 in full implementation detail; M3/M4 are sketched. The marketing site
(`index.html`, `styles.css`, `CNAME`, `.github/workflows/github-pages.yml`) stays exactly where it
is at repo root — the repo owner is refactoring that separately and it is out of scope here.

Decisions below reflect explicit sign-off already collected: stdlib `flag` only (no cobra),
greenfield migration (no live data), fix the stale `Breach-Harbor-Core-API` references and rename
the go.mod module (done in M0), wire up the existing dashboard in M2, keep multi-user JWT auth,
add `github.com/glebarez/sqlite` as the pure-Go GORM dialector (done in M0), and include a
GeoLite2-ASN download for real ISP/ASN enrichment (M2).

## Findings (verified directly, pre-M0 state)

- **No entry point existed anywhere.** Zero `package main` in the repo. `internal/` compiled as a
  library only; nothing wired `gin.Default()`, `gorm.Open()`, or template loading together. *(Fixed
  in M0.)*
- **`.venv/` (87MB, 8675/8714 tracked files)** was committed in the single commit that migrated
  the repo from Django/React to the current Go app (`e86b568`), and was not in `.gitignore`.
  *(Fixed in M0.)*
- **`go.mod`**: module `breach-harbor-core`, go 1.23/toolchain 1.24.4, deps `gin`,
  `golang-jwt/jwt/v5`, `godotenv`, `oschwald/geoip2-golang`, `golang.org/x/crypto` (bcrypt),
  `gorm.io/driver/sqlite` (wraps CGO `mattn/go-sqlite3`), `gorm.io/gorm`. No CLI framework.
  *(Module renamed and driver swapped in M0.)*
- **`internal/models/models.go`**: `Incident.Metadata map[string]interface{}` tagged only
  `gorm:"type:text"` — no serializer, wouldn't round-trip. *(Fixed in M0.)* `Location` declares
  `ISP/Organization/AS/ASN/IsAnonymousProxy/IsSatelliteProvider/IsLegitimateProxy/IsDatacenter/
  IsResidential/IsTorExitNode/IsHostingProvider` but `location.go` only ever populates
  `CountryName/CountryCode/City/Lat/Lon/Timezone/IsInEuropeanUnion/IsAnonymousProxy/
  IsSatelliteProvider` — the rest are permanently zero/false, and `IsLegitimateProxy` is never set
  at all. *(M2 work — see Data model changes.)* `Collector.Token` is a strong `crypto/rand` 64-hex
  token but stored **in plaintext**, matched by `WHERE token = ?`, and serialized back out in JSON
  (`json:"token"`, no exclusion). *(M2 work.)*
- **`internal/middleware/auth.go`**: `AuthMiddleware`/`CollectorAuthMiddleware` only read
  `Authorization: Bearer` headers; the HTMX login flow (`handlers/web.go`) sets an `auth_token`
  cookie the middleware never reads — these two auth paths are inconsistent as written. *(M2
  work.)*
- **`internal/services/dashboard.go`**: hourly incident counts run 24 separate queries in a loop
  (N+1). *(M2 work.)*
- **No tests anywhere** pre-M0. *(M0 added tests for firewall/cli/config/models; each milestone
  adds its own.)*
- **Dockerfile**: `golang:1.21-alpine` (mismatched vs go 1.23/1.24.4), built `CGO_ENABLED=0`
  against a CGO-only driver, referenced a `/health` endpoint that didn't exist. *(Fixed in M0.)*
- **CI**: the only workflow (`.github/workflows/github-pages.yml`) builds/deploys the marketing
  site via Jekyll. Nothing built, vetted, or tested the Go code. *(Fixed in M0 —
  `.github/workflows/go.yml` added.)*
- **README** told users to `go run cmd/server/main.go` (never existed), documented a full
  REST/web surface that wasn't wired up, promised an ML roadmap, and linked to a different repo
  name (`Dyneteq/Breach-Harbor-Core-API`) throughout. *(Fixed in M0.)*
- Existing code worth keeping and adapting: `internal/models`, `internal/services/
  {auth,collector,dashboard,location}.go`, `internal/handlers/*`, `internal/middleware/auth.go`
  (fix, don't discard), `internal/config`, `templates/*`, `static/*` — this is real, mostly-working
  effort, not dead code. Still true; M2 wires these up.

## Target file/package layout

Marketing site untouched at repo root.

```
/                                  # marketing site stays here, untouched: index.html, styles.css, CNAME
  README.md                        # [M0 done] real quick-start, fixed repo links, no ML roadmap
  LICENCE                          # unchanged (GPL-3.0)
  go.mod / go.sum                  # [M0 done] github.com/Dyneteq/Breach-Harbor
  Makefile                         # [M0 done] builds both binaries, test, lint
  .gitignore                       # [M0 done]

  .github/workflows/
    github-pages.yml               # unchanged
    go.yml                         # [M0 done] build/vet/test/gofmt, matrix linux amd64+arm64, darwin arm64

  cmd/
    breachharbor/main.go           # [M0 done] entrypoint — os.Exit(cli.Main(os.Args, os.Stdout, os.Stderr))
                                    # bh alias: same source, built with -o bin/bh — no separate cmd/bh/

  internal/
    cli/                           # [M0 done] subcommand dispatch (stdlib flag, hand-rolled)
      root.go, agent_cmd.go, server_cmd.go, doctor_cmd.go, version_cmd.go, output.go

    agent/                         # [M1] standalone agent
      agent.go, config.go, offender.go (rule scoring, not ML), systemd.go

    server/                        # [M2] the missing HTTP bootstrap
      server.go, http.go, ingest.go, enroll.go, publisher.go, systemd.go

    firewall/                      # [M0 done] pluggable backend
      firewall.go (Backend interface), nft.go, ipset.go, pf.go (macOS, [M1 stretch]), detect.go,
      exec.go (argv-array exec seam)

    logsource/                     # [M1] pluggable sources
      logsource.go (Source interface), journal.go, authlog.go, nginx.go, fail2ban.go

    feed/                          # [M1 partial, M2 completes] pluggable free feeds
      feed.go (Provider interface), spamhaus.go, firehol.go, tor.go, abuseipdb.go, cache.go
      asn.go                       # [M2] datacenter/hosting ASN cross-reference

    blocklist/                     # [M2] signing/verification (M1 only needs local synthesis,
      blocklist.go, sign.go (ed25519, stdlib), publish.go, fetch.go   # which can live in agent/ or store/ until M2 needs the full type)

    store/                         # [M1] agent-local state — NOT the server's GORM/sqlite
      store.go (AgentStore interface), filestore.go (JSON+NDJSON, atomic writes, lock file)

    models/       services/        # [M0 done: Metadata fix] [M2: TokenHash, dashboard N+1, enrichment]
    handlers/     middleware/      # [M2] wired into internal/server/http.go; auth.go bug fixed
    config/                        # [M0 done, base] [M1/M2 extend: flags + optional file, agent/server split]
    version/                       # [M0 done] ldflags-populated Version/Commit/Date/Signed

  templates/  static/              # kept as-is, wired up behind `server run --web` (default on) in M2
  scripts/download-geoip.sh        # [M2] extended to also fetch GeoLite2-ASN
  Dockerfile                       # [M0 done]
  docker-compose.yml               # [M0 done]
```

## Full CLI command tree

```
breachharbor <command> [subcommand] [flags]

agent
  run        --config --data-dir --enforce --sources --server --feed --abuseipdb-key
             --refresh --firewall --json      Foreground. Auto-detects sources. Dry run unless --enforce.  [M1]
  install    --enforce                        systemd unit (Linux only this pass).                        [M1]
  uninstall  --purge                          Remove the service. Implies flush.                           [M1]
  status     --json                           What's running, watched, blocked, since when.                [M1]
  top        --json --n --watch               Live top-attackers view.                                     [M1]
  enforce    --on|--off                       Switch observe-only <-> enforcing.                           [M1]
  flush      --yes                            Remove every rule this agent added. Always safe.             [M0 done]
  sources    --json                           Detected log sources and their state.                        [M1]
  enroll <url> --token                        Point this agent at a server. Optional.                      [M2]

server
  run        --config --listen --data-dir --db --publish-interval --sign-key --web --json                  [M2]
  install    --listen                         Service unit for the server.                                 [M2]
  status     --json                           Health, agent count, ingest rate, blocklist freshness.        [M2]

doctor       --json     Diagnose environment, pass/fail checklist.        [M0 done, base — M1 adds log-source rows]
version      --json     Version, commit, build date, signed-release flag. [M0 done]
```

Every data-producing command supports `--json`. Only `agent enforce --on`, the mutating half of
`agent flush`, and the install/uninstall commands require root; `status`/`top`/`doctor`/`version`/
`agent flush` (as a "what would be removed" report) work unprivileged.

### Example output — `agent run` (fresh install, zero config, dry run) — target wording for M1

```
$ breachharbor agent run
BREACH::HARBOR agent v0.5.0 (linux/amd64, commit a1b2c3d)

┌─────────────────────────────────────────────────────────────────┐
│  DRY RUN — nothing is being blocked.                             │
│  Observing for 24h so you can review what would happen.          │
│  Enable blocking any time with:  breachharbor agent enforce --on │
│  Time remaining in dry run: 23h 58m                               │
└─────────────────────────────────────────────────────────────────┘

[2026-08-11 09:41:02] sources: detected 2 of 4 possible
  ✔ systemd journal (sshd)         unit=ssh.service
  ✔ nginx access/error logs        /var/log/nginx/access.log, /var/log/nginx/error.log
  ✘ /var/log/auth.log              not found (systemd-only distro — journal already covers this)
  ✘ fail2ban                        /var/log/fail2ban.log not found — fail2ban not installed

[2026-08-11 09:41:02] firewall backend: nftables (nft v1.0.9 detected)
[2026-08-11 09:41:03] feeds: spamhaus DROP (1,203 ranges), firehol level1 (612 ranges), tor exit nodes (1,847 IPs)
[2026-08-11 09:41:03] local queue: 0 pending observations (standalone mode, no server enrolled)

[2026-08-11 09:44:17] WOULD BLOCK  203.0.113.44     ssh: 7 failed logins in 60s (threshold: 5/60s)
[2026-08-11 09:44:51] WOULD BLOCK  198.51.100.9     feed: spamhaus DROP listed range 198.51.100.0/24
[2026-08-11 09:45:03] WOULD BLOCK  192.0.2.187      nginx: 40 requests to /wp-login.php in 30s (scan threshold)
```

### Example output — `agent status` — target wording for M1

```
$ breachharbor agent status
BREACH::HARBOR agent — running (pid 41203, uptime 3h12m)
mode:            enforcing
firewall:        nftables (table inet breachharbor, set bh_blocked, 14 addresses)
sources:         2 active (systemd journal, nginx) — see `breachharbor agent sources`
feeds:           3 active, last refresh 2026-08-11 09:35:11 (12m ago), next in 3m
server:          not enrolled (standalone) — run `breachharbor agent enroll <url>` to connect one
queue:           0 pending observations
blocked now:     14 IPs (11 from feeds, 3 from local detection)
since:           2026-08-11 06:35:04 (enforcing enabled 2026-08-11 06:40:00)
```

Not-running variant:

```
BREACH::HARBOR agent — not running
No PID file at /var/run/breachharbor/agent.pid.
Start it now:      breachharbor agent run        (foreground, for testing)
Or install it:      sudo breachharbor agent install   (systemd, runs at boot)
```

### Example output — `agent top` — target wording for M1

```
BREACH::HARBOR — live attackers                          mode: DRY RUN   refresh: 2s
updated 2026-08-11 09:47:21

RANK  IP                SCORE  EVENTS  SOURCE         COUNTRY  STATUS         SINCE
1     203.0.113.44       98     41      ssh            RU       would block    09:44:17 (3m ago)
2     198.51.100.9       76      1      feed:spamhaus  BG       would block    09:44:51 (3m ago)
3     192.0.2.187        61     40      nginx          NL       would block    09:45:03 (2m ago)
4     203.0.113.201      12      3      ssh            US       watching       09:46:40 (46s ago)
5     198.51.100.220      4      1      nginx          DE       watching       09:47:02 (19s ago)

5 attackers tracked, 3 over block threshold, 0 currently blocked (dry run)
Press Ctrl+C to exit.
```

(Country column needs GeoIP lookup — `internal/services/location.go` already has MaxMind
GeoLite2-City wiring; reuse it read-only from the agent side if the `.mmdb` file is present,
otherwise leave the column blank rather than blocking on it. Full feed/ASN-based enrichment is M2
scope.)

### Example output — `doctor` (M0 baseline; M1 adds the "Log sources" rows)

```
$ breachharbor doctor
BREACH::HARBOR doctor — environment check

OS/ARCH               linux/amd64                                             ok
Build                  static, CGO disabled                                    ok
Permissions            running as uid=1000 (not root)                          note: firewall commands need root
Firewall backend        nftables detected (nft v1.0.9)                          ok
                        iptables/ipset detected as fallback                      ok
Log sources             systemd journal: readable (sshd unit present)           ok      [M1]
                        /var/log/auth.log: not found                            skip (journal covers it)  [M1]
                        nginx logs: readable                                     ok      [M1]
                        fail2ban: not found                                     skip (not installed)      [M1]
Data directory           /var/lib/breachharbor: does not exist                    fail — sudo mkdir -p /var/lib/breachharbor
Feeds (network)           spamhaus.org: reachable (203ms)                         ok      [M1]
                          firehol iblocklist mirror: reachable (180ms)            ok      [M1]
                          check.torproject.org: reachable (410ms)                 ok      [M1]

Outbound network calls this tool will make if you continue:
  GET https://www.spamhaus.org/drop/drop.txt                   every 15m (disable: --feed spamhaus=off)
  GET https://iplists.firehol.org/files/firehol_level1.netset  every 15m (disable: --feed firehol=off)
  GET https://check.torproject.org/torbulkexitlist              every 15m (disable: --feed tor=off)
  nothing else — no telemetry, no server calls unless you run: breachharbor agent enroll <url>

3 ok, 3 skip, 1 fail — fix the failed item above, then re-run doctor.
```

The M0-shipped `doctor` currently only has OS/ARCH, Build, Permissions, Firewall backend, and Data
directory rows (see `internal/cli/doctor_cmd.go`) — no Log sources or Feeds rows yet, since
`internal/logsource` and `internal/feed` didn't exist. Add them in M1/M2 respectively; move
`defaultDataDir()` out of `doctor_cmd.go` and into `internal/agent/config.go` when that package
exists, so there's one definition, not two.

## Key interfaces

```go
// internal/firewall/firewall.go — [M0 done, as built]
type Target struct{ Addr netip.Prefix }

type Backend interface {
	Name() string
	Available(ctx context.Context) error                // no root, no mutation
	Init(ctx context.Context) error                      // idempotent; only called when enforcing
	Block(ctx context.Context, targets []Target) error
	Unblock(ctx context.Context, targets []Target) error
	List(ctx context.Context) ([]Target, error)
	Flush(ctx context.Context) error                     // removes everything this backend ever added; safe anytime
}
func Detect(ctx context.Context, prefer string) (Backend, error)
```
Implementations shell out via argv-array `exec.CommandContext` only (never shell strings), behind
a `runner` seam in `internal/firewall/exec.go` for testability. nftables: dedicated `table inet
breachharbor`. ipset: dedicated sets `bh-blocked4`/`bh-blocked6` + dedicated chains
`BREACHHARBOR`/`BREACHHARBOR6` with one idempotent jump rule each. This package is done for
Linux — M1/M2 consume it, no Linux-side changes expected.

**macOS backend (pf)** — *[M1 stretch, does not gate the M1 demo]*: `internal/firewall/pf.go`
implements `Backend` via `pfctl`; no interface changes needed, `Target`/`netip.Prefix` already
carry no Linux-specific concepts. Design: anchor `breach-harbor` + one table `bh-blocked` (a pf
table holds v4 and v6 together, so unlike nft/ipset there's no need to split them) + a `block in
quick from <bh-blocked>` rule loaded into that anchor. `Available` stays non-mutating —
`LookPath("pfctl")` plus a read-only liveness check (e.g. `pfctl -s info`), mirroring `nft list
tables`/`ipset -v`. `Init` is idempotent: creates/loads the anchor+table if missing, and calls
`pfctl -e` only if pf is currently disabled. `Flush` removes only the breach-harbor anchor/table —
it must never call `pfctl -d`, since other things on macOS (Application Firewall, VPN clients) may
depend on pf staying enabled. `Block`/`Unblock` are per-address (`pfctl -t bh-blocked -T
add/delete <ip>`), closer in shape to `ipset.go` than `nft.go`'s batch style. `List` parses `pfctl
-t bh-blocked -T show` (one CIDR per line — simpler than either existing backend's output).
`detect.go`'s `"auto"` path adds `PF` as a candidate only when `runtime.GOOS == "darwin"`;
explicit `--firewall pf` forces it and errors if unavailable elsewhere. `doctor_cmd.go`'s
`firewallChecks` gains a darwin-gated pf row. Requires root, same as nft/ipset. Anchor/table
lifecycle needs verification against real macOS + root — CI's darwin/arm64 build matrix entry
compiles it but doesn't run it privileged, so the fake-`runner` unit tests in `pf_test.go` can't
substitute for a manual pass.

```go
// internal/logsource/logsource.go — [M1]
type Event struct {
	Source string
	Kind   EventKind // ssh_failed_login | http_suspicious | fail2ban_ban
	IP     netip.Addr
	Time   time.Time
	Raw    string
	Fields map[string]string
}
type ProbeResult struct{ Available bool; Detail string; Err error }
type Source interface {
	Name() string
	Probe(ctx context.Context) ProbeResult
	Watch(ctx context.Context, out chan<- Event) error   // reopens rotated files, never blocks startup
}
func ProbeAll(ctx context.Context) []ProbeResult
func Detect(ctx context.Context) []Source
```

Build order within M1 (highest value / lowest effort first): `fail2ban.go` (tail
`/var/log/fail2ban.log`, re-emit its `Ban` lines — fail2ban already did the correlation; this is
the headline "point it at your existing jails" path) → `journal.go` (`journalctl -u ssh.service -o
json --no-pager -f`, argv-array via the same `runner`-seam pattern as `internal/firewall/exec.go`
— reuse it, don't reinvent it) → `authlog.go` (tail `/var/log/auth.log` + regex, for non-systemd
setups) → `nginx.go` (combined-log-format burst detection against sensitive paths like
`/wp-login.php`, `/.env`, `/xmlrpc.php`). Every `Probe` reports `Available: false` with a human
`Detail` for "not present," never an error — errors are reserved for genuinely unexpected failures
(e.g. a permissions error on a file that does exist).

```go
// internal/feed/feed.go — [M1: spamhaus/firehol/tor/abuseipdb + cache; M2: asn.go]
type Entry struct{ Prefix netip.Prefix; Reason string; Provider string }
type Provider interface {
	Name() string
	RequiresKey() (needed, configured bool)
	Fetch(ctx context.Context) ([]Entry, error)          // bounded timeout, never fatal to caller
}
```
`internal/feed/cache.go` wraps every provider with an on-disk TTL cache at
`<data-dir>/feeds/<name>.json`; a failed `Fetch` serves the last-good cache.

```go
// internal/store/store.go — [M1] agent-local, deliberately NOT GORM/sqlite
type Offender struct {
	IP netip.Addr; Score int; Events int
	FirstSeen, LastSeen time.Time; Sources []string
	Blocked bool; BlockedAt *time.Time
}
type Observation struct {
	ID string; IP netip.Addr; Kind string; Time time.Time; Metadata map[string]string
}
type AgentStore interface {
	GetOffender(ip netip.Addr) (Offender, bool, error)
	PutOffender(o Offender) error
	ListOffenders() ([]Offender, error)
	DeleteOffender(ip netip.Addr) error
	Enqueue(obs Observation) error      // never blocks; drops oldest past MaxQueueEntries, never grows unbounded
	Dequeue(max int) ([]Observation, error)
	Ack(ids []string) error
	QueueDepth() (int, error)
	Close() error
	// SaveBlocklist/LoadBlocklist land in M2 once internal/blocklist's
	// Blocklist type exists — M1's agent only needs its own offender
	// list, no blocklist persistence yet.
}
```
Implemented in `internal/store/filestore.go` over JSON/NDJSON files with atomic write-then-rename
and a lock file (a second `agent run` against the same `--data-dir` must fail fast with a clear
message, not corrupt state) — a standalone agent must never require a database file just to start
blocking things.

```go
// internal/blocklist/blocklist.go — [M2]
type Entry struct{ Prefix netip.Prefix `json:"prefix"`; Reason string `json:"reason"` }
type Blocklist struct {
	Version int; GeneratedAt time.Time; TTL time.Duration; Entries []Entry
}
type Signer interface {   // server-side only, ed25519 via stdlib crypto/ed25519, zero new dep
	Sign(bl Blocklist) (signature []byte, err error)
	PublicKey() []byte
}
type Verifier interface {
	Verify(bl Blocklist, signature, publicKey []byte) error
}
```
Agent-side `fetch.go` only replaces the on-disk cache on successful verification; any failure
(network or signature) falls back to the last-good cached list — this is the "cache first, ask
later" decision made literal.

## Offender scoring (M1) — fixed-weight rules, not ML

No statistics, no learning, ever — detection is explainable rules plus free feeds only. Suggested
starting weights (tune against real logs during M1 testing, but document whatever you land on in
a comment table so a user can read *why* an IP was flagged):

- ssh failed login: +15, decaying over the sliding window
- nginx burst to a sensitive path: +10
- feed match (Spamhaus/FireHOL/Tor): +100 (instant block-eligible)
- fail2ban ban line: +100 (fail2ban already decided; trust it)
- Block-eligible threshold: 50 (tune against real logs)

## Data model changes

- **`Incident.Metadata`**: ✅ done in M0 — `gorm:"type:text;serializer:json" json:"metadata"`.
- **`Collector.Token` → `TokenHash`** *(M2)*: replace plaintext `Token string json:"token"` with
  `TokenHash string gorm:"uniqueIndex;not null" json:"-"`. Keep `crypto/rand` generation (already
  correct, 256-bit); show the plaintext token exactly once at creation (GitHub-PAT-style),
  store/compare only `sha256(token)`. A fast deterministic hash is correct here (high-entropy
  bearer token, not a low-entropy password needing bcrypt).
- **`Location`'s dead boolean/enrichment fields** *(M2)*: populate for real at server-side ingest
  time (never on the agent's hot path), via `internal/services/location.go`:
  - `IsTorExitNode` ← `feed/tor.go` exact-IP match.
  - `IsDatacenter`/`IsHostingProvider` ← `feed/asn.go`, cross-referencing the IP's ASN (from a
    newly-added GeoLite2-ASN download) against a curated hosting/cloud ASN list.
  - `ISP`/`Organization`/`AS`/`ASN` ← GeoLite2-ASN lookup directly (extend
    `scripts/download-geoip.sh` to fetch it alongside GeoLite2-City, same MaxMind license key).
  - `IsResidential` ← documented heuristic:
    `!IsDatacenter && !IsHostingProvider && !IsTorExitNode && !IsAnonymousProxy` (no free
    "this is residential" feed exists).
  - `IsAnonymousProxy`/`IsSatelliteProvider`/`IsInEuropeanUnion` — already correct, untouched.
  - `IsLegitimateProxy` — verify empirically during M2 whether GeoLite2-City's free edition
    actually carries this trait; wire it if so, otherwise drop the field with a comment explaining
    why.
- **Server-side store**: ✅ driver swapped in M0 (`github.com/glebarez/sqlite`, pure Go, built on
  `modernc.org/sqlite`) — keeps every existing service-layer query in `services/
  {auth,collector,dashboard,location}.go` unchanged.
- **Agent-local store is a different schema entirely** *(M1)* — see `AgentStore` above, not
  GORM/sqlite, so a standalone agent needs zero database setup.

## Milestone breakdown

### M0 — it builds — ✅ DONE

1. ✅ `git rm -r --cached .venv`; gitignore `.venv/`, Python artifacts, `bin/`.
2. ✅ Sqlite driver swap (`glebarez/sqlite`), verified via `AutoMigrate` + CRUD tests.
3. ✅ Module rename to `github.com/Dyneteq/Breach-Harbor`; imports rewritten.
4. ✅ `Incident.Metadata` tag fix.
5. ✅ `cmd/breachharbor/main.go` (single source; `bh` built from it, not a separate package),
   `internal/cli/root.go` + `doctor_cmd.go`/`version_cmd.go` + `agent flush` (all real).
6. ✅ `internal/firewall/`: interface + `nft.go` + `ipset.go` + `detect.go`, tested via the
   `runner` seam.
7. ✅ `internal/version/version.go` + Makefile `-ldflags` wiring.
8. ✅ `Dockerfile` rewritten: `golang:1.24-alpine`, `CGO_ENABLED=0`, `doctor --json` healthcheck.
   Verified with a real `docker build` (8.4MB image).
9. ✅ `.github/workflows/go.yml`: fmt/vet/test, linux amd64+arm64, darwin arm64 build matrix.
10. ✅ Tests: firewall argv assertions, CLI dispatch, config loader, models CRUD.
11. ✅ README rewritten and later simplified further.

**Demo**: `make build` → binaries; `version`/`doctor`/`agent flush` work; CI green on a clean
clone. **Verified.**

### M1 — agent stands alone — ✅ DONE

Goal: `breachharbor agent run` with zero flags is a genuinely useful standalone product — no
server required. Auto-detected log sources, a real 24h dry run, real `enforce --on`, a reversible
`flush` (already works), real `status`/`top`/`sources`, feeds pulling free public lists, local
file-backed state that survives restarts.

1. `internal/logsource/`: fail2ban → journal → authlog → nginx, in that order (see Key interfaces
   above for build-order rationale).
2. `internal/agent/offender.go`: fixed-weight, explainable scoring (see Offender scoring above).
3. `internal/agent/agent.go`: sources → offender store → firewall backend (if enforcing); persists
   `dry_run_until` on first run to `<data-dir>/agent-state.json`.
4. `internal/agent/config.go`: zero-config defaults + flags. Move `defaultDataDir()` here from
   `internal/cli/doctor_cmd.go` (currently duplicated logic waiting to happen — there should be
   one definition).
5. `internal/feed/`: spamhaus/firehol/tor/abuseipdb providers + TTL cache (`asn.go` is M2).
6. `internal/store/filestore.go`: full implementation, lock file, atomic writes (no blocklist
   persistence yet — that's M2).
7. `internal/agent/systemd.go`: unit file template + `install`/`uninstall`. Try
   `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` first so it doesn't need to run fully as root;
   fall back to root with a clear message if that proves insufficient — verify empirically on a
   real Linux box or VM, don't assume it works.
8. CLI: replace the `internal/cli/agent_cmd.go` stubs for `run` (full banner + live loop), `top`,
   `status`, `enforce`, `sources`, `install`/`uninstall` with real implementations. `flush` is
   already done, don't touch it. Reuse the existing `printJSON`/`fail()` conventions from
   `output.go`.
9. `doctor_cmd.go`: add the Log sources and Feeds-reachability rows once `internal/logsource` and
   `internal/feed` exist.
10. Tests: offender scoring (table-driven, covering decay and threshold), log parsers against real
    fixture lines (Ubuntu 22.04/24.04, Debian 12 sshd/auth.log formats, nginx combined log format,
    fail2ban ban lines — store fixtures under `internal/logsource/testdata/`), feed providers via
    `httptest` including the cache-fallback-on-failure path, filestore round-trip + bounded-queue
    drop + lock contention, CLI dispatch tests extended to the newly-real subcommands (same
    fake-stdout/stderr pattern as `internal/cli/cli_test.go`).
11. *(Stretch, optional — does not gate the M1 demo, which stays Linux-VM-based)*
    `internal/firewall/pf.go`: macOS backend via `pfctl` (see Key interfaces → macOS backend (pf)
    for the full design). Wire into `detect.go` (darwin-only auto-candidate, explicit `pf` name)
    and `doctor_cmd.go` (darwin-gated check row). Test via the existing fake-`runner` pattern in a
    new `pf_test.go`; anchor/table lifecycle still needs a manual verification pass on real macOS
    with root, since CI builds darwin/arm64 but doesn't run it privileged.

**Demo**: fresh Linux VM/container with sshd, nginx, fail2ban installed. `sudo breachharbor agent
install` (dry run active) → simulate an SSH brute force → within a minute `agent status`/`agent
top` show it as "would block" → `sudo breachharbor agent enforce --on` actually blocks it (verify
directly with `nft list table inet breachharbor` or `iptables -L BREACHHARBOR -n`) → `sudo
breachharbor agent flush --yes` removes it cleanly, zero leftover state.

**Risk**: log-format drift across distros — mitigate with fixtures and "never fail because one
source is missing/weird."

Full example CLI output text to match (reviewed and approved wording — keep the voice): see the
`agent run`/`agent status`/`agent top`/`doctor` sections above under "Full CLI command tree."

### M2 — server is useful — ✅ DONE

1. `internal/server/http.go`: the bootstrap that's never existed — `POST /v1/enroll`, `POST
   /v1/observations` (batched, replacing one-event-per-request), `GET /v1/blocklist`, plus
   dashboard routes behind `--web` (default on).
2. Fix `middleware/auth.go`: one middleware, header-then-cookie; hash-compare collector tokens.
3. Model fixes: `TokenHash`, batch ingest (`CreateInBatches`).
4. `services/dashboard.go`: replace the 24-query loop with one grouped query.
5. `services/location.go`: wire real feed/ASN enrichment (extend `download-geoip.sh` for
   GeoLite2-ASN).
6. `internal/blocklist/publish.go`: ticker at `--publish-interval` (default 15m), ed25519 key
   auto-generated to `<data-dir>/signing.key` (0600) on first run.
7. `internal/agent/enroll.go` + `uploader.go` + `blocklist/fetch.go`: persisted enrollment,
   batched fire-and-forget uploads with backoff, blocklist fetch/verify/merge (union with
   local-synth entries, never replace).
8. CLI: `server run`, `server install`, `server status`.
9. Fix `handlers/web.go`'s `HandleDeleteCollector` stub and the auth-cookie bug as part of wiring
   the dashboard in.
10. Tests: `httptest` handler tests for all endpoints, dashboard query test, publisher scheduler
    test, one in-process end-to-end test (enroll → observe → ingest → publish → fetch → verify →
    merge) using a no-op firewall backend so it's CI-safe without root/nft.

**Demo**: kill the server mid-session — the already-enrolled agent keeps enforcing its last
verified cached blocklist unaffected. This is "cache first, ask later" made literal and demoable.

**Risk**: enroll/ingest/publish has no prior art in the repo to adapt from — newest surface area.

### M3 (trust hardening) — sketch

Server-pubkey pinning/rotation instead of bare TOFU-on-enroll, rate limiting and auth on every
server endpoint, observation dedupe/idempotency at ingest, blocklist entry provenance/expiry, an
append-only audit log of every enforce/flush/block/unblock, `doctor --server <url>`. Mostly
hardening existing packages, no new ones expected.

### M4 (sharing) — sketch

Optional multi-source trust: an agent subscribing to more than one signed blocklist with
per-source attribution and union-never-overwrite conflict resolution, plus a shareable signed "my
ruleset" bundle (config/thresholds only, never incident data). Still zero ML, still opt-in, still
cache-first.

## Migration plan (greenfield, no live deployments)

- SQLite files from the old CGO driver are standard SQLite3 format; `glebarez/sqlite`/
  `modernc.org/sqlite` opens them without conversion, and nothing in the schema uses a
  CGO-specific extension. Recommend a `cp` backup before the first run against any pre-existing
  file — not a scripted migration.
- `Incident.Metadata` fix is additive at the schema level (column stays `TEXT`); nothing was ever
  successfully written under the old tag, so there's nothing to backfill.
- Module rename was a pure mechanical import-path change with zero data implication. Done.

## Explicitly out of scope for this project

- Any ML/AI-based detection or docs referencing it — the README's ML roadmap was deleted in M0,
  not deprioritized.
- ~~macOS/BSD firewall backends~~ — macOS (`pf`) is now planned as an M1 stretch item, see Key
  interfaces → macOS backend (pf) and M1 step 11; it doesn't gate the M1 demo. Non-macOS BSD
  variants (FreeBSD/OpenBSD `pf` differences) remain out of scope.
- Windows support.
- Multi-server federation beyond the M4 sketch.
- A centrally-run, project-hosted default public blocklist service.
- Billing/licensing/SaaS concepts.
- Live firewall-backend migration on an already-enforcing agent (switching nft↔ipset means flush +
  reinstall).
- Visual redesign of `templates/`/`static/` — M2 wiring only, no redesign.
- Any change to `index.html`, `styles.css`, `CNAME`, or `.github/workflows/github-pages.yml` — the
  repo owner is handling the marketing site separately.
- Distro packaging (deb/rpm/Homebrew) beyond the static binary + systemd unit.
- Log sources beyond the four named (no Windows Event Log, no cloud-provider log integrations).

## Open questions remaining (lower-stakes, decide during implementation)

1. `Collector` → `Agent` rename in the DB schema/API terminology — clean match to the merged
   architecture, or unnecessary churn for M2? Low risk either way; decide when M2 starts.
2. Keep `gin`, or move the server to stdlib `net/http` (Go 1.22+ pattern routing) to shed gin's
   large transitive dependency footprint? Recommendation: leave it (sunk dependency, already
   works), revisit only if it becomes a real pain point.
3. Systemd capability hardening (`CAP_NET_ADMIN` instead of full root) — attempt it in M1 as
   described, with a documented root fallback if it doesn't pan out empirically; not worth
   blocking M1 on.
4. Whether Breach Harbor itself ever publishes a default community blocklist post-M4 — pure
   product direction, doesn't affect implementation.

## Verification

- `make build && ./bin/breachharbor version && ./bin/breachharbor doctor` on a clean clone, per
  milestone.
- `go build ./... && go vet ./... && go test ./...` green at every milestone (CI-enforced from
  M0).
- M1: manual VM test — simulate an SSH brute force, confirm `agent status`/`top` show it, `enforce
  --on` blocks it in `nft`/`iptables` directly, `flush` leaves zero breachharbor state behind.
- M2: manual test — enroll an agent, kill the server, confirm the agent keeps enforcing its last
  cached signed blocklist; `--web` dashboard reachable and login/incident/collector pages
  functional.

## Working conventions (established during M0, keep following them)

- One milestone per feature branch (`restructure/m0-it-builds` was M0's), commit incrementally,
  stop for review before merging — don't barrel through multiple milestones unprompted.
- Only commit when explicitly asked; only push when explicitly asked.
- No `Co-Authored-By` trailers in commit messages (global user preference).
- Every milestone leaves `go build ./...`, `go vet ./...`, `go test ./...`, and `gofmt -l .` clean
  — verify before considering a milestone done, not just before committing.
- Prefer deleting code over adding it — the `cmd/bh` consolidation during M0 cleanup is the
  precedent: two files doing the same thing became one file built twice.
