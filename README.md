<div align="center">
  <h1>BREACH::HARBOR</h1>
  <p><strong>The threat blocking agent you can set up in five minutes and actually understand.</strong></p>

  <p>
    <a href="https://github.com/Dyneteq/Breach-Harbor/issues">Report Bug</a>
    ·
    <a href="https://github.com/Dyneteq/Breach-Harbor/issues">Request Feature</a>
    ·
    <a href="https://breachharbor.com">Official Website</a>
  </p>
</div>

## Overview

BREACH::HARBOR is a single static binary, `breachharbor`, with two modes:

```
breachharbor agent     # collects signals and enforces firewall rules on one machine
breachharbor server    # the brain: aggregates, enriches, decides, publishes blocklists
```

The agent auto-detects log sources (systemd journal, nginx, `/var/log/auth.log`, fail2ban),
observes in dry-run mode by default, and only blocks traffic once you explicitly turn enforcement
on. Every rule it adds lives in its own dedicated firewall table/chain/set, so `breachharbor agent
flush` can remove exactly what the agent added and nothing else, at any time. A standalone agent
with no server enrolled is a fully working product on its own.

## Project status

This repository is being restructured from an unfinished Core API into the single-binary CLI
described above. Current state:

- **M0 — it builds.** Done. Single Go module, real entry points (`cmd/breachharbor`,
  `cmd/bh`), pure-Go SQLite (no CGO), CI. `breachharbor version`, `breachharbor doctor`, and
  `breachharbor agent flush` are real today; every other subcommand reports that it isn't
  implemented yet rather than pretending to work.
- **M1 — the agent stands alone.** In progress. Log source detection, offender scoring, `agent
  run`/`status`/`top`/`enforce`, systemd install.
- **M2 — the server is useful.** Planned. Ingest, enrichment, signed blocklist publishing, the
  existing dashboard wired up.

## Quick start

Requires Go 1.24+.

```bash
git clone https://github.com/Dyneteq/Breach-Harbor.git
cd Breach-Harbor
make build
./bin/breachharbor version
./bin/breachharbor doctor
```

`doctor` diagnoses your environment (OS/arch, permissions, available firewall backend, data
directory) and tells you exactly what's missing and how to fix it — it never requires root.

```bash
./bin/breachharbor agent flush        # safe to run anytime; reports what would be removed
sudo ./bin/breachharbor agent flush --yes   # actually removes any rules this agent ever added
```

`breachharbor agent run` and `breachharbor server run` are the headline commands but land in M1
and M2 respectively — running them today prints a clear "not implemented yet" message instead of
silently doing nothing.

## Project structure

```
cmd/
  breachharbor/     # main entry point
  bh/                # short alias, identical binary
internal/
  cli/               # subcommand dispatch (stdlib flag, no framework)
  firewall/          # pluggable nftables / iptables+ipset backend
  version/           # ldflags-populated build metadata
  config/            # server-side env/file configuration
  models/            # GORM models (server-side store)
  services/          # server-side business logic
  handlers/          # HTTP handlers (wired up in M2)
  middleware/        # auth middleware
templates/           # HTMX dashboard templates (wired up in M2)
static/              # dashboard CSS/JS
scripts/             # download-geoip.sh
```

## Development

```bash
make build       # builds bin/breachharbor and bin/bh
make test        # go test ./...
make vet         # go vet ./...
make fmt-check   # gofmt -l . (fails if anything needs formatting)
```

CI (`.github/workflows/go.yml`) runs all three, plus cross-compiles for linux/amd64,
linux/arm64, and darwin/arm64 with `CGO_ENABLED=0` on every push and pull request.

## Docker

```bash
docker build -t breachharbor .
docker compose up
```

The image is a minimal Alpine base with the static binary, no CGO. Its healthcheck runs
`breachharbor doctor --json` — the same command you'd run by hand — instead of a bespoke HTTP
endpoint.

## Security

- The agent never blocks on a network round trip: firewall decisions are made from a local cache,
  refreshed on a schedule, never on the hot path.
- Nothing leaves the machine unless you opt in (`breachharbor agent enroll <url>`). `breachharbor
  doctor` prints exactly what network calls would be made and where.
- No AI/ML detection anywhere in this project — detection is explainable rules plus free public
  threat feeds (Spamhaus DROP, FireHOL, Tor exit nodes, optionally AbuseIPDB).

## Contributing

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

Please add tests for new functionality — this is a security tool that runs as root and edits
firewalls, so untested code isn't shippable.

## License

BREACH::HARBOR is released under the [GPL-3.0 license](https://github.com/Dyneteq/Breach-Harbor/blob/master/LICENCE).

## Support

- **Issues**: [GitHub Issues](https://github.com/Dyneteq/Breach-Harbor/issues)
- **Email**: security@breachharbor.com

---

<div align="center">
  <a href="https://breachharbor.com">
    <img src="https://img.shields.io/badge/BREACH::HARBOR-Website-blue" alt="Website"/>
  </a>
  <a href="https://github.com/Dyneteq/Breach-Harbor/issues">
    <img src="https://img.shields.io/github/issues/Dyneteq/Breach-Harbor" alt="Issues"/>
  </a>
  <a href="https://github.com/Dyneteq/Breach-Harbor/blob/master/LICENCE">
    <img src="https://img.shields.io/badge/License-GPL%20v3-green.svg" alt="License"/>
  </a>
  <a href="https://golang.org/">
    <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go" alt="Go Version"/>
  </a>
</div>
