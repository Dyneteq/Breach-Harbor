#!/bin/bash

# BREACH::HARBOR - DB-IP Lite GeoIP Database Download Script
#
# No-signup alternative to scripts/download-geoip.sh. DB-IP publishes
# free "Lite" City and ASN databases in the same .mmdb format MaxMind
# uses, with a schema compatible with github.com/oschwald/geoip2-golang's
# City()/ASN() readers (see internal/services/location.go). No account
# or license key required, just attribution per the CC BY 4.0 license:
# https://db-ip.com/db/lite.php
#
# Coverage/accuracy is lower than MaxMind's GeoLite2 (Lite editions are
# reduced subsets of DB-IP's commercial data), but it's a drop-in fix
# for the "MaxMind database not available" warnings.
#
# Files are published monthly, named e.g. dbip-city-lite-2026-08.mmdb.gz.
# This script tries the current month and falls back to the previous
# month if this month's file isn't published yet.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DATA_DIR="./data"
BASE_URL="https://download.db-ip.com/free"
TEMP_DIR=$(mktemp -d)

print_status()  { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

mkdir -p "$DATA_DIR"

# download_edition fetches one DB-IP Lite edition (trying this month,
# then last month) and installs it as $DATA_DIR/<dest_name>.mmdb.
download_edition() {
    local dbip_slug="$1"
    local dest_name="$2"
    local gz_file="$TEMP_DIR/${dbip_slug}.mmdb.gz"

    for offset in 0 1; do
        local ym
        ym=$(date -v-"${offset}"m +%Y-%m 2>/dev/null || date -d "-${offset} month" +%Y-%m)
        local url="${BASE_URL}/${dbip_slug}-${ym}.mmdb.gz"

        print_status "Trying ${dbip_slug} for ${ym}..."
        if curl -fsSL "$url" -o "$gz_file" 2>/dev/null; then
            print_status "Downloaded ${dbip_slug}-${ym}.mmdb.gz"
            gunzip -f "$gz_file"
            cp "$TEMP_DIR/${dbip_slug}.mmdb" "$DATA_DIR/${dest_name}.mmdb"
            chmod 644 "$DATA_DIR/${dest_name}.mmdb"
            local file_size
            file_size=$(du -h "$DATA_DIR/${dest_name}.mmdb" | cut -f1)
            print_success "${dest_name}.mmdb installed (${file_size}) at $DATA_DIR/${dest_name}.mmdb"
            return 0
        fi
    done

    print_error "Failed to download ${dbip_slug} for this month or last month"
    return 1
}

download_edition "dbip-city-lite" "GeoLite2-City"
download_edition "dbip-asn-lite" "GeoLite2-ASN"

print_status "Database installation complete!"
print_warning "DB-IP Lite is CC BY 4.0: attribute https://db-ip.com if you display this data."
print_warning "New editions are published monthly; re-run this script periodically to refresh."

echo ""
print_success "You can now start BREACH::HARBOR with IP geolocation/ASN enrichment:"
echo "breachharbor server run"
