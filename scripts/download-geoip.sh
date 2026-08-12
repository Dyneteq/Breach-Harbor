#!/bin/bash

# BREACH::HARBOR - MaxMind GeoIP Database Download Script
# Downloads the latest GeoLite2-City and GeoLite2-ASN databases (the
# ASN edition powers the M2 ISP/ASN/datacenter enrichment in
# internal/services/location.go — same free MaxMind license key).

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MAXMIND_LICENSE_KEY="$1"
DATA_DIR="./data"
DOWNLOAD_URL="https://download.maxmind.com/app/geoip_download"
DB_SUFFIX="tar.gz"
TEMP_DIR=$(mktemp -d)

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to cleanup temporary files
cleanup() {
    rm -rf "$TEMP_DIR"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Validate input
if [ -z "$MAXMIND_LICENSE_KEY" ]; then
    print_error "Usage: $0 <MAXMIND_LICENSE_KEY>"
    print_error "Get your license key from: https://www.maxmind.com/en/geolite2/signup"
    exit 1
fi

# Create data directory
print_status "Creating data directory..."
mkdir -p "$DATA_DIR"

# download_edition fetches one GeoLite2 edition and installs it as
# $DATA_DIR/<dest_name>.mmdb.
download_edition() {
    local edition_id="$1"
    local dest_name="$2"
    local download_file="$TEMP_DIR/${edition_id}.${DB_SUFFIX}"
    local extract_dir="$TEMP_DIR/${edition_id}"

    print_status "Downloading ${edition_id} database..."
    mkdir -p "$extract_dir"

    if command -v curl >/dev/null 2>&1; then
        curl -L "$DOWNLOAD_URL?edition_id=$edition_id&license_key=$MAXMIND_LICENSE_KEY&suffix=$DB_SUFFIX" \
             -o "$download_file" \
             --fail \
             --silent \
             --show-error
    elif command -v wget >/dev/null 2>&1; then
        wget "$DOWNLOAD_URL?edition_id=$edition_id&license_key=$MAXMIND_LICENSE_KEY&suffix=$DB_SUFFIX" \
             -O "$download_file" \
             --quiet
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi

    if [ ! -f "$download_file" ]; then
        print_error "Failed to download ${edition_id} database"
        exit 1
    fi

    print_status "Extracting ${edition_id}..."
    tar -xzf "$download_file" -C "$extract_dir"

    local mmdb_file
    mmdb_file=$(find "$extract_dir" -name "*.mmdb" -type f | head -n 1)
    if [ -z "$mmdb_file" ]; then
        print_error "Could not find .mmdb file in ${edition_id} archive"
        exit 1
    fi

    print_status "Installing ${dest_name}.mmdb..."
    cp "$mmdb_file" "$DATA_DIR/${dest_name}.mmdb"
    chmod 644 "$DATA_DIR/${dest_name}.mmdb"

    if [ -f "$DATA_DIR/${dest_name}.mmdb" ]; then
        local file_size
        file_size=$(du -h "$DATA_DIR/${dest_name}.mmdb" | cut -f1)
        print_success "${dest_name}.mmdb installed (${file_size}) at $DATA_DIR/${dest_name}.mmdb"
    else
        print_error "Failed to install ${dest_name}.mmdb"
        exit 1
    fi
}

download_edition "GeoLite2-City" "GeoLite2-City"
download_edition "GeoLite2-ASN" "GeoLite2-ASN"

print_status "Database installation complete!"
print_warning "Remember to update these databases regularly as MaxMind releases updates."
print_warning "You can run this script again to get the latest versions."

echo ""
print_success "You can now start BREACH::HARBOR with full IP geolocation/ASN enrichment:"
echo "breachharbor server run"
