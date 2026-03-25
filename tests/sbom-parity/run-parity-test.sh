#!/usr/bin/env bash
# SBOM Parity Test — Sandtrace vs Syft
# Compares (ecosystem, name, version) tuples from both tools
# Reports precision (how many sandtrace components are real) and
# recall (how many syft components sandtrace found)
set -euo pipefail

SANDTRACE="${SANDTRACE_BIN:-$(dirname "$0")/../../target/release/sandtrace}"
SYFT="${SYFT_BIN:-syft}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$RESULTS_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

if ! command -v "$SYFT" &>/dev/null; then
    echo "Error: syft not found. Install: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s"
    exit 1
fi

if [ ! -x "$SANDTRACE" ]; then
    echo "Error: sandtrace binary not found at $SANDTRACE"
    echo "Build with: cargo build --release"
    exit 1
fi

# Extract (ecosystem, name, version) tuples from CycloneDX JSON
# Normalizes purl to (ecosystem, name, version) for fair comparison
extract_components() {
    local file="$1"
    python3 -c "
import json, sys, urllib.parse

data = json.load(open('$file'))
components = data.get('components', [])
seen = set()
for c in components:
    name = c.get('name', '')
    version = c.get('version', '')
    purl = c.get('purl', '')

    # Extract ecosystem and name from purl for normalization
    eco = ''
    purl_name = name
    if purl.startswith('pkg:'):
        parts = purl.split('?')[0]  # strip qualifiers
        parts = parts.split('#')[0]  # strip subpath
        eco = parts.split(':')[1].split('/')[0]
        # Handle scoped packages: pkg:npm/%40scope/name -> @scope/name
        raw_path = parts.split(':', 1)[1].split('/', 1)[1] if '/' in parts.split(':', 1)[1] else ''
        purl_name = urllib.parse.unquote(raw_path).rsplit('@', 1)[0] if '@' in raw_path and not raw_path.startswith('@') else urllib.parse.unquote(raw_path)
        # Extract version from purl if not in component
        if not version and '@' in raw_path:
            version = raw_path.rsplit('@', 1)[1]

    # Skip non-library ecosystems (github actions, OS packages)
    if eco in ('github', 'deb', 'rpm', 'apk', 'alpine', 'golang', ''):
        if eco == '' and c.get('type') != 'library':
            continue
        elif eco in ('github', 'deb', 'rpm', 'apk', 'alpine'):
            continue

    # Normalize name: lowercase, strip leading @
    norm_name = name.lower()

    # Normalize version: strip leading 'v' prefix (syft keeps it, sandtrace strips it)
    if version.startswith('v') and len(version) > 1 and version[1:2].isdigit():
        version = version[1:]

    key = f'{eco}|{norm_name}|{version}'
    if key not in seen:
        seen.add(key)
        print(key)
" | sort
}

# Compare two component lists, report precision and recall
compare_components() {
    local sandtrace_file="$1"
    local syft_file="$2"
    local repo_name="$3"

    local st_components="$RESULTS_DIR/${repo_name}-sandtrace-components.txt"
    local sy_components="$RESULTS_DIR/${repo_name}-syft-components.txt"

    extract_components "$sandtrace_file" > "$st_components"
    extract_components "$syft_file" > "$sy_components"

    local st_count=$(wc -l < "$st_components")
    local sy_count=$(wc -l < "$sy_components")
    local matched=$(comm -12 "$st_components" "$sy_components" | wc -l)
    local st_only=$(comm -23 "$st_components" "$sy_components" | wc -l)
    local sy_only=$(comm -13 "$st_components" "$sy_components" | wc -l)

    local precision=0
    local recall=0
    if [ "$st_count" -gt 0 ]; then
        precision=$(python3 -c "print(round($matched / $st_count * 100, 1))")
    fi
    if [ "$sy_count" -gt 0 ]; then
        recall=$(python3 -c "print(round($matched / $sy_count * 100, 1))")
    fi

    echo ""
    echo -e "${BOLD}$repo_name${NC}"
    echo "  Sandtrace: $st_count components"
    echo "  Syft:      $sy_count components"
    echo "  Matched:   $matched"
    if [ "$st_only" -gt 0 ]; then
        echo -e "  ${YELLOW}Sandtrace-only: $st_only${NC}"
    fi
    if [ "$sy_only" -gt 0 ]; then
        echo -e "  ${YELLOW}Syft-only: $sy_only${NC}"
    fi
    echo -e "  Precision: ${BOLD}${precision}%${NC} (of sandtrace results, how many match syft)"
    echo -e "  Recall:    ${BOLD}${recall}%${NC} (of syft results, how many sandtrace found)"

    if [ "$(echo "$recall >= 95" | bc -l 2>/dev/null || python3 -c "print(1 if $recall >= 95 else 0)")" = "1" ]; then
        echo -e "  Status:    ${GREEN}PASS${NC} (>= 95% recall)"
    else
        echo -e "  Status:    ${RED}FAIL${NC} (< 95% recall)"
    fi

    # Save detailed diffs
    comm -23 "$st_components" "$sy_components" > "$RESULTS_DIR/${repo_name}-sandtrace-only.txt"
    comm -13 "$st_components" "$sy_components" > "$RESULTS_DIR/${repo_name}-syft-only.txt"

    echo "$repo_name|$st_count|$sy_count|$matched|$precision|$recall"  >> "$RESULTS_DIR/summary.csv"
}

# Clone or update a test repo
ensure_repo() {
    local url="$1"
    local dir="$2"
    if [ -d "$dir" ]; then
        echo "  Using cached $dir"
    else
        echo "  Cloning $url..."
        git clone --depth 1 "$url" "$dir" 2>/dev/null
    fi
}

# Run both tools on a directory
run_tools() {
    local dir="$1"
    local name="$2"
    local st_out="$RESULTS_DIR/${name}-sandtrace.json"
    local sy_out="$RESULTS_DIR/${name}-syft.json"

    echo "  Running sandtrace sbom..."
    "$SANDTRACE" sbom "$dir" > "$st_out" 2>/dev/null || true
    if [ ! -s "$st_out" ]; then
        echo "  Warning: sandtrace produced no output"
    fi

    echo "  Running syft..."
    "$SYFT" scan "dir:$dir" -o cyclonedx-json="$sy_out" 2>/dev/null || true
    if [ ! -s "$sy_out" ]; then
        echo "  Warning: syft produced no output"
    fi

    # Skip comparison if either tool failed
    if [ ! -s "$st_out" ] || [ ! -s "$sy_out" ]; then
        echo -e "  ${YELLOW}SKIPPED — one or both tools produced no output${NC}"
        return 1
    fi
    return 0
}

echo -e "${BOLD}SBOM Parity Test — Sandtrace vs Syft${NC}"
echo "Sandtrace: $($SANDTRACE --version 2>&1 | head -1)"
echo "Syft:      $($SYFT --version 2>&1 | head -1)"
echo ""

echo "repo_name|st_count|sy_count|matched|precision|recall" > "$RESULTS_DIR/summary.csv"

REPOS_DIR="$SCRIPT_DIR/repos"
mkdir -p "$REPOS_DIR"

# --- Test repos (must have committed lockfiles) ---

# 1. cargo: ripgrep (Cargo.lock committed)
echo "1/5: ripgrep (cargo)"
ensure_repo "https://github.com/BurntSushi/ripgrep.git" "$REPOS_DIR/ripgrep"
if run_tools "$REPOS_DIR/ripgrep" "ripgrep"; then
    compare_components "$RESULTS_DIR/ripgrep-sandtrace.json" "$RESULTS_DIR/ripgrep-syft.json" "ripgrep"
fi

# 2. cargo: sandtrace itself (Cargo.lock committed)
echo "2/5: sandtrace (cargo)"
if run_tools "$SCRIPT_DIR/../.." "sandtrace"; then
    compare_components "$RESULTS_DIR/sandtrace-sandtrace.json" "$RESULTS_DIR/sandtrace-syft.json" "sandtrace"
fi

# 3. composer: sandtrace-web (composer.lock committed)
echo "3/5: sandtrace-web (composer)"
SANDTRACE_WEB="${SANDTRACE_WEB_DIR:-$SCRIPT_DIR/../../../web}"
if [ -d "$SANDTRACE_WEB" ] && [ -f "$SANDTRACE_WEB/composer.lock" ]; then
    if run_tools "$SANDTRACE_WEB" "sandtrace-web"; then
        compare_components "$RESULTS_DIR/sandtrace-web-sandtrace.json" "$RESULTS_DIR/sandtrace-web-syft.json" "sandtrace-web"
    fi
else
    echo "  Skipped — sandtrace-web not found at $SANDTRACE_WEB"
fi

# 4. npm: got (package-lock.json committed)
echo "4/5: got (npm)"
ensure_repo "https://github.com/sindresorhus/got.git" "$REPOS_DIR/got"
if run_tools "$REPOS_DIR/got" "got"; then
    compare_components "$RESULTS_DIR/got-sandtrace.json" "$RESULTS_DIR/got-syft.json" "got"
fi

# 5. npm: next.js (pnpm-lock committed)
echo "5/5: next.js (pnpm)"
ensure_repo "https://github.com/vercel/next.js.git" "$REPOS_DIR/nextjs"
if run_tools "$REPOS_DIR/nextjs" "nextjs"; then
    compare_components "$RESULTS_DIR/nextjs-sandtrace.json" "$RESULTS_DIR/nextjs-syft.json" "nextjs"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}SUMMARY${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""
printf "%-15s %8s %8s %8s %10s %10s\n" "REPO" "ST" "SYFT" "MATCH" "PRECISION" "RECALL"
printf "%-15s %8s %8s %8s %10s %10s\n" "───────────" "────" "────" "─────" "─────────" "──────"
while IFS='|' read -r name st sy matched prec rec; do
    [ "$name" = "repo_name" ] && continue
    printf "%-15s %8s %8s %8s %9s%% %9s%%\n" "$name" "$st" "$sy" "$matched" "$prec" "$rec"
done < "$RESULTS_DIR/summary.csv"
echo ""
echo "Detailed diffs saved to: $RESULTS_DIR/"
echo "Target: >= 95% recall on (ecosystem, name, version) tuples"
