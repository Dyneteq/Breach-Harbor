#!/bin/bash

# BREACH::HARBOR - MaxMind GeoIP Database Download Script
# This script automatically downloads the latest GeoLite2-City database

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
DB_EDITION="GeoLite2-City"
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

# Download the database
print_status "Downloading GeoLite2-City database..."
DOWNLOAD_FILE="$TEMP_DIR/${DB_EDITION}.${DB_SUFFIX}"

if command -v curl >/dev/null 2>&1; then
    curl -L "$DOWNLOAD_URL?edition_id=$DB_EDITION&license_key=$MAXMIND_LICENSE_KEY&suffix=$DB_SUFFIX" \
         -o "$DOWNLOAD_FILE" \
         --fail \
         --silent \
         --show-error
elif command -v wget >/dev/null 2>&1; then
    wget "$DOWNLOAD_URL?edition_id=$DB_EDITION&license_key=$MAXMIND_LICENSE_KEY&suffix=$DB_SUFFIX" \
         -O "$DOWNLOAD_FILE" \
         --quiet
else
    print_error "Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Verify download
if [ ! -f "$DOWNLOAD_FILE" ]; then
    print_error "Failed to download GeoLite2-City database"
    exit 1
fi

# Extract the database
print_status "Extracting database..."
cd "$TEMP_DIR"
tar -xzf "$DOWNLOAD_FILE"

# Find the .mmdb file
MMDB_FILE=$(find . -name "*.mmdb" -type f | head -n 1)

if [ -z "$MMDB_FILE" ]; then
    print_error "Could not find .mmdb file in downloaded archive"
    exit 1
fi

# Copy to data directory
print_status "Installing database..."
cp "$MMDB_FILE" "$DATA_DIR/GeoLite2-City.mmdb"

# Verify installation
if [ -f "$DATA_DIR/GeoLite2-City.mmdb" ]; then
    FILE_SIZE=$(du -h "$DATA_DIR/GeoLite2-City.mmdb" | cut -f1)
    print_success "GeoLite2-City database installed successfully!"
    print_success "Database size: $FILE_SIZE"
    print_success "Location: $DATA_DIR/GeoLite2-City.mmdb"
else
    print_error "Failed to install database"
    exit 1
fi

# Update permissions
chmod 644 "$DATA_DIR/GeoLite2-City.mmdb"

print_status "Database installation complete!"
print_warning "Remember to update this database regularly as MaxMind releases updates."
print_warning "You can run this script again to get the latest version."

echo ""
print_success "You can now start BREACH::HARBOR with full IP geolocation support:"
echo "go run cmd/server/main.go"