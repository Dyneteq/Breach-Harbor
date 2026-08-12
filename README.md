<div align="center">
  <h1>BREACH::HARBOR</h1>
  <p><strong>The threat blocking agent you can set up in five minutes and actually understand.</strong></p>

  <p>
    <a href="https://github.com/Dyneteq/Breach-Harbor/issues">Report Bug</a>
    ·
    <a href="https://github.com/Dyneteq/Breach-Harbor/issues">Request Feature</a>
    ·
    <a href="https://breachharbor.com">Website</a>
  </p>

  <pre><code>curl -fsSL https://breachharbor.com/install.sh | sh</code></pre>
</div>

## What it is

One static binary, two modes:

```
breachharbor agent     # watches one machine and blocks attackers
breachharbor server    # aggregates signal from many agents, publishes blocklists
```

The agent auto-detects your logs (sshd, nginx, fail2ban), watches quietly for 24 hours by
default, and blocks nothing until you tell it to. Everything it blocks lives in one dedicated
firewall table, so `breachharbor agent flush` undoes all of it, instantly, any time. No server
required: the agent is a complete product on its own.

## Quick start

```bash
curl -fsSL https://breachharbor.com/install.sh | sh
breachharbor doctor
```

That downloads the right prebuilt binary for your OS/arch (linux/amd64, linux/arm64,
darwin/arm64, openbsd/amd64), verifies its checksum, and installs it to `/usr/local/bin`.
No release built for your platform yet? Build from source instead (requires Go 1.24+):

```bash
git clone https://github.com/Dyneteq/Breach-Harbor.git
cd Breach-Harbor
make build
./bin/breachharbor doctor
```

`doctor` tells you what's ready to go and what isn't; it never needs root.

```bash
breachharbor agent flush          # always safe: reports what would be removed
sudo breachharbor agent flush --yes    # actually removes it
```

## Status

Being rebuilt into the CLI above, one milestone at a time:

- ✅ **M0: it builds.** `version`, `doctor`, `agent flush` work today. Everything else says so
  honestly instead of pretending.
- 🚧 **M1: the agent stands alone.** In progress.
- ⏳ **M2: the server is useful.** Planned.

## Development

```bash
make build       # bin/breachharbor + bin/bh
make test
make vet
make fmt-check
```

CI runs all of these plus a cross-compile check for linux/amd64, linux/arm64, darwin/arm64.

## Docker

```bash
docker build -t breachharbor .
docker compose up
```

Static binary, no CGO, ~8MB image. Healthcheck is just `breachharbor doctor --json`.

## Security notes

- Nothing leaves the machine unless you run `breachharbor agent enroll <url>`; `doctor` shows
  exactly what would be sent and where.
- No AI/ML. Detection is plain rules plus free public threat feeds (Spamhaus, FireHOL, Tor exit
  nodes).

## Contributing

PRs welcome: fork, branch, and open a pull request. Add tests: this runs as root and edits
firewalls, so untested code doesn't ship.

## License

[GPL-3.0](https://github.com/Dyneteq/Breach-Harbor/blob/master/LICENCE)

## Support

[GitHub Issues](https://github.com/Dyneteq/Breach-Harbor/issues)
