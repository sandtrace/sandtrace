#!/usr/bin/env bash
# update-npm-iocs.sh — Download OpenSSF malicious-packages (OSV format)
# and generate a SandTrace pattern file for known-malicious npm packages.
#
# Usage:
#   ./scripts/update-npm-iocs.sh [output-path]
#
# Default output: ~/.sandtrace/npm-malware.toml
# Source: https://github.com/ossf/malicious-packages (OSV JSON via GCS)

set -euo pipefail

OSV_URL="https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
OUTPUT="${1:-$HOME/.sandtrace/npm-malware.toml}"

# Check dependencies
for cmd in curl unzip jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd is required but not installed" >&2
        exit 1
    fi
done

# Create temp working directory
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading OSV npm data..."
curl -sSL "$OSV_URL" -o "$TMPDIR/all.zip"

echo "Extracting..."
unzip -q "$TMPDIR/all.zip" -d "$TMPDIR/osv"

# Count MAL-* entries
MAL_FILES=("$TMPDIR"/osv/MAL-*.json)
if [[ ! -f "${MAL_FILES[0]}" ]]; then
    echo "error: no MAL-*.json files found in archive" >&2
    exit 1
fi
TOTAL=${#MAL_FILES[@]}
echo "Found $TOTAL malware entries"

# Ensure output directory exists
mkdir -p "$(dirname "$OUTPUT")"

# Write header
{
    echo "# SandTrace npm malware patterns"
    echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# Source: https://github.com/ossf/malicious-packages (OSV format)"
    echo "# Entries: $TOTAL"
} > "$OUTPUT"

# Process each MAL-*.json file
COUNT=0
for f in "${MAL_FILES[@]}"; do
    ID=$(jq -r '.id // empty' "$f" 2>/dev/null) || continue
    NAME=$(jq -r '.affected[0].package.name // empty' "$f" 2>/dev/null) || continue

    # Skip entries missing required fields
    [[ -z "$ID" || -z "$NAME" ]] && continue

    # Escape double quotes in package name (rare but possible)
    ESCAPED_NAME="${NAME//\"/\\\"}"

    cat >> "$OUTPUT" <<EOF

[[custom_patterns]]
id = "osv-${ID}"
description = "Malicious npm package: ${ESCAPED_NAME} (${ID})"
severity = "critical"
match_type = "literal"
pattern = "${ESCAPED_NAME}"
file_extensions = ["json"]
tags = ["ioc", "npm", "malware", "osv"]
EOF

    COUNT=$((COUNT + 1))
done

echo "Wrote $COUNT patterns to $OUTPUT"
echo ""
echo "Add to your ~/.sandtrace/config.toml:"
echo "  pattern_files = [\"$OUTPUT\"]"
