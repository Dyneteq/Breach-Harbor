#!/bin/bash

# BREACH::HARBOR - local development runner
#
# Builds the binary and runs the server or agent against a scratch
# data directory under .dev/ (gitignored) instead of the real system
# default (~/.breachharbor or similar) — so iterating never touches
# state you'd have to clean up by hand, and `rm -rf .dev` always
# resets everything.
#
#   scripts/dev.sh                    # build + run the server (default)
#   scripts/dev.sh server [flags...]  # same, explicit
#   scripts/dev.sh agent [flags...]   # build + run the agent
#   scripts/dev.sh clean              # report what's in .dev/, delete nothing
#   scripts/dev.sh clean --yes        # actually wipe .dev/ (both data dirs)
#
# clean mirrors this project's own `agent flush` safety pattern
# (internal/cli/agent_flush.go): a database with real collectors/
# incidents in it is exactly the kind of thing a script must never
# delete silently, even a "dev only" one — see the incident that
# prompted this: an earlier version of this script deleted a real
# .dev/server-data/breach_harbor.db with no confirmation at all.
#
# Extra flags after the mode are passed straight through, e.g.:
#   scripts/dev.sh server --listen :9090
#   scripts/dev.sh agent --enforce --refresh 10s

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DEV_DIR="$ROOT_DIR/.dev"
SERVER_DATA_DIR="$DEV_DIR/server-data"
AGENT_DATA_DIR="$DEV_DIR/agent-data"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status()  { echo -e "${BLUE}[dev]${NC} $1"; }
print_success() { echo -e "${GREEN}[dev]${NC} $1"; }
print_error()   { echo -e "${RED}[dev]${NC} $1"; }

MODE="${1:-server}"
if [ "$#" -gt 0 ]; then
    shift
fi

if [ "$MODE" = "clean" ]; then
    if [ ! -d "$DEV_DIR" ]; then
        print_success "$DEV_DIR does not exist — nothing to clean."
        exit 0
    fi

    print_status "This would remove:"
    find "$DEV_DIR" -type f -exec du -h {} \; 2>/dev/null | sed 's/^/  /'

    YES=0
    for arg in "$@"; do
        if [ "$arg" = "--yes" ] || [ "$arg" = "-y" ]; then
            YES=1
        fi
    done

    if [ "$YES" -ne 1 ]; then
        print_error "Not removed — this deletes real data if you've been using .dev/ for real work, not just throwaway tests."
        print_error "Re-run with --yes to actually delete it: $0 clean --yes"
        exit 1
    fi

    print_status "Removing $DEV_DIR..."
    rm -rf "$DEV_DIR"
    print_success "Clean. Next run starts from a fresh database/state."
    exit 0
fi

if [ "$MODE" != "server" ] && [ "$MODE" != "agent" ]; then
    print_error "Usage: $0 [server|agent|clean] [extra flags...]"
    exit 2
fi

print_status "Building..."
make build

case "$MODE" in
server)
    mkdir -p "$SERVER_DATA_DIR"
    print_success "Starting server: http://localhost:8080 (data dir: $SERVER_DATA_DIR)"
    print_status "--local-agent is on: the dashboard can start an agent against this same box, no enroll needed."
    exec ./bin/breachharbor server run \
        --listen :8080 \
        --data-dir "$SERVER_DATA_DIR" \
        --local-agent \
        "$@"
    ;;
agent)
    mkdir -p "$AGENT_DATA_DIR"
    print_success "Starting agent (data dir: $AGENT_DATA_DIR, dry run unless --enforce is passed)"
    print_status "Not enrolled yet? Run: ./bin/breachharbor agent enroll <server-url> --token <token> --data-dir $AGENT_DATA_DIR"
    exec ./bin/breachharbor agent run \
        --data-dir "$AGENT_DATA_DIR" \
        --refresh 10s \
        "$@"
    ;;
esac
