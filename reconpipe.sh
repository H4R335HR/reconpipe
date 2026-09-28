#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  reconpipe.sh — Automated Bug Bounty Recon Pipeline
#
#  Usage:
#    ./reconpipe.sh -d target.com
#    ./reconpipe.sh -d target.com -w /path/to/wordlist.txt
#    ./reconpipe.sh -d target.com -w wordlist.txt -p 500 -c 50
#
#  Pipeline:
#    subfinder → dnsx → httpx + naabu → httpx (all ports)
#    → vhost discovery → gau + katana + ffuf → nuclei
#
#  All outputs saved to: ./reconpipe/<domain>/<timestamp>/
# ──────────────────────────────────────────────────────────────

set -uo pipefail
# NOTE: intentionally no -e flag. Tools like httpx, naabu, nuclei return
# non-zero exit codes during normal operation (e.g. unreachable hosts).
# With -e, the script dies silently at the first tool that has partial failures.

# ─── Colors & Helpers ─────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║           reconpipe — Bug Bounty Recon               ║"
    echo "║  subfinder → dnsx → httpx → naabu → gau          ║"
    echo "║  katana → ffuf → nuclei                           ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

info()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; }
section() { echo -e "\n${CYAN}${BOLD}━━━ $* ━━━${RESET}\n"; }

elapsed() {
    local secs=$1
    printf '%02dh:%02dm:%02ds' $((secs/3600)) $((secs%3600/60)) $((secs%60))
}

# ─── Binary Detection (Kali / BlackArch Compatibility) ───────
# Kali packages ProjectDiscovery's httpx as "httpx-toolkit"
# to avoid conflict with the Python httpx library.
# BlackArch ships gau as "getallurls" (the upstream binary name).

if command -v httpx-toolkit &>/dev/null; then
    HTTPX_BIN="httpx-toolkit"
elif command -v httpx &>/dev/null; then
    # Verify it's ProjectDiscovery httpx, not Python httpx
    if httpx -version 2>&1 | grep -qi "projectdiscovery"; then
        HTTPX_BIN="httpx"
    elif httpx-toolkit -version &>/dev/null 2>&1; then
        HTTPX_BIN="httpx-toolkit"
    else
        HTTPX_BIN="httpx"
    fi
else
    HTTPX_BIN="httpx"
fi

# gau: Kali installs as 'gau', BlackArch as 'getallurls'
if command -v gau &>/dev/null; then
    GAU_BIN="gau"
elif command -v getallurls &>/dev/null; then
    GAU_BIN="getallurls"
else
    GAU_BIN="gau"   # will be caught by check_tools
fi

# ─── Default Configuration ────────────────────────────────────

DOMAIN=""
WORDLIST=""
TOP_PORTS=1000
CONCURRENCY=50
KATANA_DEPTH=3
FFUF_THREADS=40
NUCLEI_SEVERITY="low,medium,high,critical"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SKIP_FFUF=false
RESUME=false
NUCLEI_URLS=false
NUCLEI_PARAMS=false
ENABLE_VHOSTS=auto
VHOST_WORDLIST=""
TARGET_IS_IP=false   # set automatically when -d is an IP address

# ─── Argument Parsing ─────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Required:
  -d <target>         Target domain (e.g. target.com) OR IP address (e.g. 10.0.0.1)
                      When an IP is given, subfinder/dnsx/gau/vhost phases are skipped
                      and the IP is probed directly with httpx + naabu.

Optional:
  -w <wordlist>       Wordlist for ffuf (default: auto-detect common paths)
  -p <ports>          Top N ports for naabu (default: 1000)
  -c <concurrency>    General concurrency/threads (default: 50)
  -k <depth>          Katana crawl depth (default: 3)
  -s <severity>       Nuclei severity filter (default: low,medium,high,critical)
  --skip-ffuf         Skip ffuf directory brute-forcing
  --nuclei-urls       Also scan all discovered URLs with nuclei (slow)
  --nuclei-params     Also scan parameterized URLs with nuclei (slow)
  --nuclei-full       Enable both --nuclei-urls and --nuclei-params
  -V <wordlist>       Wordlist for vhost discovery (default: auto-detect)
  --enable-vhosts     Force vhost discovery (auto-enabled when no subdomains found)
  --resume            Resume the most recent incomplete run for this domain
  -h                  Show this help
EOF
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) DOMAIN="$2"; shift 2 ;;
        -w) WORDLIST="$2"; shift 2 ;;
        -p) TOP_PORTS="$2"; shift 2 ;;
        -c) CONCURRENCY="$2"; shift 2 ;;
        -k) KATANA_DEPTH="$2"; shift 2 ;;
        -s) NUCLEI_SEVERITY="$2"; shift 2 ;;
        --skip-ffuf) SKIP_FFUF=true; shift ;;
        --nuclei-urls) NUCLEI_URLS=true; shift ;;
        --nuclei-params) NUCLEI_PARAMS=true; shift ;;
        --nuclei-full) NUCLEI_URLS=true; NUCLEI_PARAMS=true; shift ;;
        --resume) RESUME=true; shift ;;
        -V) VHOST_WORDLIST="$2"; shift 2 ;;
        --enable-vhosts) ENABLE_VHOSTS=true; shift ;;
        -h|--help) usage ;;
        *) error "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$DOMAIN" ]] && { error "Target (-d) is required."; usage; }

# ─── IP vs Domain Detection ───────────────────────────────────
# Matches IPv4 (1.2.3.4) and IPv6 (with or without brackets).
is_ip() {
    local target="${1#[}"; target="${target%]}"   # strip optional [ ] from IPv6
    # IPv4
    if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi
    # IPv6 (contains at least one colon)
    if [[ "$target" =~ : ]]; then
        return 0
    fi
    return 1
}

if is_ip "$DOMAIN"; then
    TARGET_IS_IP=true
    warn "IP address detected — skipping subfinder / dnsx / gau / vhost phases"
fi

# Sanitize DOMAIN for use in directory names (IPv6 colons → underscores)
DOMAIN_SAFE=$(echo "$DOMAIN" | tr ':' '_' | tr -d '[]')

# ─── Output Directory Structure ───────────────────────────────

if [[ "$RESUME" == true ]]; then
    # Find the most recent run for this domain that didn't finish
    LATEST=$(find "./reconpipe/${DOMAIN_SAFE}" -maxdepth 1 -mindepth 1 -type d 2>/dev/null \
        | sort -r | head -1)
    if [[ -n "$LATEST" && ! -f "$LATEST/.done" ]]; then
        BASE_DIR="$LATEST"
        info "Resuming incomplete run: $BASE_DIR"
    elif [[ -n "$LATEST" && -f "$LATEST/.done" ]]; then
        warn "Last run already completed. Starting fresh."
        RESUME=false
        BASE_DIR="./reconpipe/${DOMAIN_SAFE}/${TIMESTAMP}"
    else
        warn "No previous run found for ${DOMAIN_SAFE}. Starting fresh."
        RESUME=false
        BASE_DIR="./reconpipe/${DOMAIN_SAFE}/${TIMESTAMP}"
    fi
else
    BASE_DIR="./reconpipe/${DOMAIN_SAFE}/${TIMESTAMP}"
fi

mkdir -p "$BASE_DIR"/{subdomains,dns,httpx,ports,urls,fuzzing,vulnerabilities,screenshots,logs,vhosts}

LOGFILE="$BASE_DIR/logs/reconpipe.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Shorthand paths
SUBS="$BASE_DIR/subdomains"
DNS="$BASE_DIR/dns"
HTTPX_DIR="$BASE_DIR/httpx"
PORTS="$BASE_DIR/ports"
URLS="$BASE_DIR/urls"
FUZZ="$BASE_DIR/fuzzing"
VULNS="$BASE_DIR/vulnerabilities"
LOGS="$BASE_DIR/logs"

# ─── Checkpoint Helpers ───────────────────────────────────────
# Each phase marks itself done. On resume, completed phases are skipped.

phase_done()    { touch "$BASE_DIR/.phase_${1}_done"; }
phase_check()   {
    if [[ -f "$BASE_DIR/.phase_${1}_done" ]]; then
        info "Phase '$1' already complete — skipping"
        return 0
    fi
    return 1
}

# ─── Dependency Check ─────────────────────────────────────────

check_tools() {
    section "Checking Dependencies"

    # Required tools differ between IP mode and domain mode
    local required_always=(naabu katana nuclei)
    local required_domain=(subfinder dnsx)   # not needed for IP targets
    local required_gau=true                  # gau skipped in IP mode
    local optional=(ffuf anew gowitness notify uro)
    local missing=()

    # Detect distro hint for install suggestions
    local distro="unknown"
    if grep -qi "blackarch" /etc/os-release 2>/dev/null; then
        distro="blackarch"
    elif grep -qi "kali" /etc/os-release 2>/dev/null; then
        distro="kali"
    elif grep -qi "arch" /etc/os-release 2>/dev/null; then
        distro="arch"
    fi
    [[ "$distro" != "unknown" ]] && info "Detected distro: $distro"

    # httpx check — Kali uses httpx-toolkit
    if command -v "$HTTPX_BIN" &>/dev/null; then
        info "httpx — found as '$HTTPX_BIN' ($(which "$HTTPX_BIN"))"
    else
        error "httpx — NOT FOUND (tried httpx and httpx-toolkit)"
        missing+=("httpx")
    fi

    # Verify it's ProjectDiscovery's httpx, not Python's httpx
    if command -v httpx &>/dev/null; then
        if httpx -version 2>&1 | grep -qi "projectdiscovery\|Current Version"; then
            info "httpx — confirmed ProjectDiscovery version"
        elif httpx --version 2>&1 | grep -qiE "^httpx.*python|^[0-9]+\.[0-9]+\.[0-9]+$"; then
            error "Wrong httpx detected! You have Python's httpx, not ProjectDiscovery's."
            error "Install the correct one: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
            error "Then ensure ~/go/bin is first in your PATH: export PATH=\"\$HOME/go/bin:\$PATH\""
            exit 1
        fi
    fi

    # gau / getallurls (BlackArch ships it as 'getallurls')
    if [[ "$TARGET_IS_IP" == false ]]; then
        if command -v "$GAU_BIN" &>/dev/null; then
            info "gau — found as '$GAU_BIN' ($(which "$GAU_BIN"))"
        else
            error "gau — NOT FOUND (tried gau and getallurls)"
            missing+=("gau")
        fi
    else
        warn "gau — skipped (IP target, no web archive data)"
    fi

    for tool in "${required_always[@]}"; do
        if command -v "$tool" &>/dev/null; then
            info "$tool — found ($(which "$tool"))"
        else
            error "$tool — NOT FOUND"
            missing+=("$tool")
        fi
    done

    if [[ "$TARGET_IS_IP" == false ]]; then
        for tool in "${required_domain[@]}"; do
            if command -v "$tool" &>/dev/null; then
                info "$tool — found ($(which "$tool"))"
            else
                error "$tool — NOT FOUND"
                missing+=("$tool")
            fi
        done
    else
        for tool in "${required_domain[@]}"; do
            warn "$tool — skipped (IP target)"
        done
    fi

    for tool in "${optional[@]}"; do
        if command -v "$tool" &>/dev/null; then
            info "$tool — found (optional)"
        else
            warn "$tool — not found (optional, skipping its steps)"
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"
        error "Install them and re-run. Aborting."
        exit 1
    fi

    # Wordlist detection for ffuf
    if [[ "$SKIP_FFUF" == false && -z "$WORDLIST" ]]; then
        local common_paths=(
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            "/usr/share/wordlists/dirb/common.txt"
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
            "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
            "$HOME/wordlists/common.txt"
        )
        for wl in "${common_paths[@]}"; do
            if [[ -f "$wl" ]]; then
                WORDLIST="$wl"
                info "Auto-detected wordlist: $WORDLIST"
                break
            fi
        done
        if [[ -z "$WORDLIST" ]]; then
            warn "No wordlist found. ffuf will be skipped."
            warn "Supply one with -w or install SecLists."
            SKIP_FFUF=true
        fi
    fi
}

# ─── Utility: deduplicate append ──────────────────────────────

dedup_append() {
    # Usage: dedup_append source_file target_file
    # Like anew but works without it
    if command -v anew &>/dev/null; then
        cat "$1" | anew "$2"
    else
        cat "$1" >> "$2" 2>/dev/null || true
        sort -u -o "$2" "$2"
    fi
}

# ─── Phase 1: Subdomain Enumeration ──────────────────────────

phase_subdomains() {
    if [[ "$TARGET_IS_IP" == true ]]; then
        info "Phase 1 — Subdomain Enumeration: skipped (IP target)"
        # Create empty placeholder so downstream phases don't fail on missing file
        touch "$SUBS/all_subdomains.txt"
        phase_done "subdomains"
        return 0
    fi
    phase_check "subdomains" && return 0
    section "Phase 1 — Subdomain Enumeration (subfinder)"
    local start=$SECONDS

    subfinder -d "$DOMAIN" -all -silent -o "$SUBS/subfinder_raw.txt" 2>"$LOGS/subfinder_errors.log" || true

    # Deduplicate and clean
    sort -u "$SUBS/subfinder_raw.txt" -o "$SUBS/all_subdomains.txt"

    local count
    count=$(wc -l < "$SUBS/all_subdomains.txt")
    info "Found $count unique subdomains in $(elapsed $((SECONDS - start)))"
    info "Output → $SUBS/all_subdomains.txt"
    phase_done "subdomains"
}

# ─── Phase 2: DNS Resolution ─────────────────────────────────

phase_dns() {
    if [[ "$TARGET_IS_IP" == true ]]; then
        info "Phase 2 — DNS Resolution: skipped (IP target)"
        # Write the IP directly as the resolved hosts file
        echo "$DOMAIN" > "$DNS/resolved_hosts.txt"
        touch "$DNS/resolved_full.txt" "$DNS/cnames.txt"
        info "Using IP directly as resolved host: $DOMAIN"
        phase_done "dns"
        return 0
    fi
    phase_check "dns" && return 0
    section "Phase 2 — DNS Resolution (dnsx)"
    local start=$SECONDS

    dnsx -l "$SUBS/all_subdomains.txt" \
         -silent \
         -a -resp \
         -o "$DNS/resolved_full.txt" \
         2>"$LOGS/dnsx_errors.log"

    # Extract just the hostnames (strip the response data)
    awk '{print $1}' "$DNS/resolved_full.txt" | sort -u > "$DNS/resolved_hosts.txt"

    # Check for CNAME records (subdomain takeover candidates)
    dnsx -l "$SUBS/all_subdomains.txt" \
         -silent \
         -cname -resp \
         -o "$DNS/cnames.txt" \
         2>>"$LOGS/dnsx_errors.log" || true

    local resolved
    resolved=$(wc -l < "$DNS/resolved_hosts.txt")
    local cnames
    cnames=$(wc -l < "$DNS/cnames.txt" 2>/dev/null || echo 0)
    info "Resolved $resolved hosts (from $(wc -l < "$SUBS/all_subdomains.txt") subdomains)"
    info "Found $cnames CNAME records (check for subdomain takeover)"
    info "Output → $DNS/resolved_hosts.txt"
    phase_done "dns"
}

# ─── Phase 3: HTTP Probing (Standard Ports) ───────────────────

phase_httpx_standard() {
    phase_check "httpx_standard" && return 0
    section "Phase 3a — HTTP Probing, Standard Ports (httpx)"
    local start=$SECONDS

    $HTTPX_BIN -l "$DNS/resolved_hosts.txt" \
          -silent \
          -status-code -title -tech-detect -content-length \
          -follow-redirects \
          -timeout 10 \
          -retries 2 \
          -threads "$CONCURRENCY" \
          -o "$HTTPX_DIR/alive_standard_full.txt" \
          2>"$LOGS/httpx_standard_errors.log" || true

    # Extract just the URLs for downstream tools
    awk '{print $1}' "$HTTPX_DIR/alive_standard_full.txt" | sort -u > "$HTTPX_DIR/alive_standard_urls.txt"

    local count
    count=$(wc -l < "$HTTPX_DIR/alive_standard_urls.txt")
    info "Found $count live hosts on standard ports in $(elapsed $((SECONDS - start)))"
    info "Output → $HTTPX_DIR/alive_standard_urls.txt"
    phase_done "httpx_standard"
}

# ─── Phase 4: Port Scanning ──────────────────────────────────

phase_naabu() {
    phase_check "naabu" && return 0
    section "Phase 3b — Port Scanning (naabu)"
    local start=$SECONDS

    naabu -list "$DNS/resolved_hosts.txt" \
          -top-ports "$TOP_PORTS" \
          -silent \
          -timeout 5000 \
          -o "$PORTS/naabu_raw.txt" \
          2>"$LOGS/naabu_errors.log" || true

    local open
    open=$(wc -l < "$PORTS/naabu_raw.txt")
    info "Found $open open host:port pairs in $(elapsed $((SECONDS - start)))"
    info "Output → $PORTS/naabu_raw.txt"
    phase_done "naabu"
}

# ─── Phase 5: HTTP Probing on All Discovered Ports ────────────

phase_httpx_allports() {
    phase_check "httpx_allports" && return 0
    section "Phase 3c — HTTP Probing, All Ports (httpx on naabu output)"
    local start=$SECONDS

    $HTTPX_BIN -l "$PORTS/naabu_raw.txt" \
          -silent \
          -status-code -title -tech-detect -content-length \
          -follow-redirects \
          -timeout 10 \
          -retries 2 \
          -threads "$CONCURRENCY" \
          -o "$HTTPX_DIR/alive_allports_full.txt" \
          2>"$LOGS/httpx_allports_errors.log" || true

    awk '{print $1}' "$HTTPX_DIR/alive_allports_full.txt" | sort -u > "$HTTPX_DIR/alive_allports_urls.txt"

    # ─── Merge both httpx runs into a master alive list ───────
    cat "$HTTPX_DIR/alive_standard_urls.txt" "$HTTPX_DIR/alive_allports_urls.txt" \
        | sort -u > "$HTTPX_DIR/alive_merged_raw.txt"

    # ─── Normalize schemes: http on 443 → https, https on 80 → http ──
    # httpx probing host:443 over plain HTTP gets a 400 response which
    # registers as "alive", leaving http://host:443 in the list.
    # Gowitness then screenshots the error page instead of the real site.
    sed -E \
        -e 's|^http://([^/:]+):443(/\|$)|https://\1\2|' \
        -e 's|^https://([^/:]+):80(/\|$)|http://\1\2|' \
        -e 's|^http://([^/:]+):8443(/\|$)|https://\1:8443\2|' \
        -e 's|^http://([^/:]+):9443(/\|$)|https://\1:9443\2|' \
        "$HTTPX_DIR/alive_merged_raw.txt" | sort -u > "$HTTPX_DIR/alive_final.txt"

    local normalized
    normalized=$(diff --suppress-common-lines <(sort "$HTTPX_DIR/alive_merged_raw.txt") <(sort "$HTTPX_DIR/alive_final.txt") | grep -c '^[<>]' || true)
    [[ "$normalized" -gt 0 ]] && info "Normalized $((normalized/2)) URLs with mismatched scheme/port"

    local standard allports merged
    standard=$(wc -l < "$HTTPX_DIR/alive_standard_urls.txt")
    allports=$(wc -l < "$HTTPX_DIR/alive_allports_urls.txt")
    merged=$(wc -l < "$HTTPX_DIR/alive_final.txt")
    info "Standard ports: $standard | All ports: $allports | Merged (deduped): $merged"
    info "Extra targets from non-standard ports: $((merged - standard))"
    info "Master alive list → $HTTPX_DIR/alive_final.txt"
    phase_done "httpx_allports"
}

# ─── Phase 3d: Virtual Host Discovery ────────────────────

phase_vhosts() {
    if [[ "$TARGET_IS_IP" == true && "$ENABLE_VHOSTS" != "true" ]]; then
        # For IPs, vhost fuzzing uses "Host: FUZZ.<IP>" which is nonsensical.
        # Skip unless the user has explicitly forced it with --enable-vhosts.
        info "Phase 3d — Vhost Discovery: skipped (IP target; use --enable-vhosts to force)"
        phase_done "vhosts"
        return 0
    fi
    if ! command -v ffuf &>/dev/null; then
        warn "ffuf not found — skipping vhost discovery"
        return 0
    fi
    phase_check "vhosts" && return 0

    # Auto mode: only run when subfinder found no subdomains
    if [[ "$ENABLE_VHOSTS" == "auto" ]]; then
        local sub_count
        sub_count=$(wc -l < "$SUBS/all_subdomains.txt" 2>/dev/null || echo 0)
        if [[ "$sub_count" -gt 0 ]]; then
            info "Subdomains found ($sub_count) — skipping vhost discovery"
            info "Use --enable-vhosts to force vhost scanning"
            phase_done "vhosts"
            return 0
        fi
        info "No subdomains found — auto-enabling vhost discovery"
    fi

    section "Phase 3d — Virtual Host Discovery (ffuf)"
    local start=$SECONDS

    # ─── Locate a subdomain/vhost wordlist ────────────────────
    local vhost_wl="$VHOST_WORDLIST"
    if [[ -z "$vhost_wl" ]]; then
        local vhost_paths=(
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            "/usr/share/seclists/Discovery/DNS/namelist.txt"
            "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
            "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"
            "$HOME/wordlists/subdomains.txt"
        )
        for wl in "${vhost_paths[@]}"; do
            if [[ -f "$wl" ]]; then
                vhost_wl="$wl"
                break
            fi
        done
    fi

    if [[ -z "$vhost_wl" ]]; then
        warn "No vhost/subdomain wordlist found — skipping vhost discovery"
        warn "Supply one with -V or install SecLists"
        phase_done "vhosts"
        return 0
    fi

    info "Vhost wordlist: $vhost_wl ($(wc -l < "$vhost_wl") entries)"
    mkdir -p "$BASE_DIR/vhosts/per_host"

    # ─── Build fuzz targets ───────────────────────────────────
    # Extract unique scheme://host:port origins from the alive list.
    # We fuzz each origin to catch vhosts on non-standard ports too.
    local targets="$BASE_DIR/vhosts/fuzz_targets.txt"
    sed -E 's|(https?://[^/]+).*|\1|' "$HTTPX_DIR/alive_final.txt" \
        | sort -u > "$targets"

    local total current=0
    total=$(wc -l < "$targets")
    info "Fuzzing $total unique origin(s) for virtual hosts..."

    # ─── Fuzz each origin with Host header ────────────────────
    while IFS= read -r base_url; do
        ((current++))
        local safename
        safename=$(echo "$base_url" | sed 's|https\?://||;s|[:/]|_|g')
        info "[$current/$total] Vhost fuzzing $base_url → Host: FUZZ.${DOMAIN}"

        ffuf -u "${base_url}/" \
             -H "Host: FUZZ.${DOMAIN}" \
             -w "$vhost_wl" \
             -ac \
             -t "$FFUF_THREADS" \
             -timeout 10 \
             -sf \
             -s \
             -o "$BASE_DIR/vhosts/per_host/${safename}.json" \
             -of json \
             2>>"$LOGS/vhost_errors.log" || true

    done < "$targets"

    # ─── Parse discovered vhosts from ffuf JSON ────────────────
    # Extract the FUZZ input value and reconstruct the full hostname.
    find "$BASE_DIR/vhosts/per_host" -name "*.json" -exec cat {} + 2>/dev/null \
        | grep -o '"FUZZ":"[^"]*"' \
        | sed 's/"FUZZ":"//;s/"//' \
        | sort -u \
        | while IFS= read -r name; do echo "${name}.${DOMAIN}"; done \
        > "$BASE_DIR/vhosts/discovered_vhosts.txt" 2>/dev/null || true

    local count
    count=$(wc -l < "$BASE_DIR/vhosts/discovered_vhosts.txt" 2>/dev/null || echo 0)

    if [[ "$count" -gt 0 ]]; then
        info "Discovered $count virtual host(s):"
        while IFS= read -r vhost; do
            info "  → $vhost"
        done < "$BASE_DIR/vhosts/discovered_vhosts.txt"

        # Probe vhosts with httpx — works only if they resolve in DNS.
        # Vhosts without DNS records are still logged for manual testing.
        info "Probing discovered vhosts with httpx (best-effort DNS)..."
        $HTTPX_BIN -l "$BASE_DIR/vhosts/discovered_vhosts.txt" \
              -silent \
              -status-code -title -tech-detect -content-length \
              -follow-redirects \
              -timeout 10 \
              -threads "$CONCURRENCY" \
              -o "$BASE_DIR/vhosts/vhosts_httpx_full.txt" \
              2>"$LOGS/vhosts_httpx_errors.log" || true

        local resolved
        resolved=$(wc -l < "$BASE_DIR/vhosts/vhosts_httpx_full.txt" 2>/dev/null || echo 0)

        if [[ "$resolved" -gt 0 ]]; then
            awk '{print $1}' "$BASE_DIR/vhosts/vhosts_httpx_full.txt" \
                | sort -u > "$BASE_DIR/vhosts/vhosts_alive_urls.txt"

            # Merge resolvable vhost URLs into the master alive list
            local before_merge
            before_merge=$(wc -l < "$HTTPX_DIR/alive_final.txt")

            cat "$HTTPX_DIR/alive_final.txt" "$BASE_DIR/vhosts/vhosts_alive_urls.txt" \
                | sort -u > "$HTTPX_DIR/alive_final_tmp.txt"
            mv "$HTTPX_DIR/alive_final_tmp.txt" "$HTTPX_DIR/alive_final.txt"

            local after_merge
            after_merge=$(wc -l < "$HTTPX_DIR/alive_final.txt")
            info "Master alive list: $before_merge → $after_merge targets (+$((after_merge - before_merge)) from vhosts)"
        fi

        local dns_less=$((count - resolved))
        if [[ "$dns_less" -gt 0 ]]; then
            warn "$dns_less vhost(s) have no DNS record (add to /etc/hosts for deeper testing)"
        fi
    else
        info "No additional virtual hosts discovered"
    fi

    info "Completed in $(elapsed $((SECONDS - start)))"
    info "Output → $BASE_DIR/vhosts/"
    phase_done "vhosts"
}

# ─── Phase 6: Passive URL Collection ─────────────────────────

phase_gau() {
    if [[ "$TARGET_IS_IP" == true ]]; then
        info "Phase 4a — Passive URL Collection: skipped (IP target, no web archive data)"
        touch "$URLS/gau_urls.txt"   # empty placeholder for merge phase
        phase_done "gau"
        return 0
    fi
    phase_check "gau" && return 0
    section "Phase 4a — Passive URL Collection ($GAU_BIN)"
    local start=$SECONDS
    local gau_timeout=300   # 5 minute timeout for gau

    # Build domain list for gau
    sed 's|https\?://||;s|/.*||' "$HTTPX_DIR/alive_final.txt" \
        | sort -u > "$URLS/gau_domains.txt"

    local domain_count
    domain_count=$(wc -l < "$URLS/gau_domains.txt")
    info "Querying $domain_count domains from web archives via '$GAU_BIN' (timeout: ${gau_timeout}s)..."

    # Background progress reporter — prints URL count every 15s
    (
        while true; do
            sleep 15
            if [[ -f "$URLS/gau_raw.txt" ]]; then
                local c
                c=$(wc -l < "$URLS/gau_raw.txt" 2>/dev/null || echo 0)
                echo -e "${YELLOW}[!]${RESET} gau progress: $c URLs collected so far... ($(elapsed $((SECONDS - start))))"
            fi
        done
    ) &
    local progress_pid=$!

    # Run gau/getallurls with timeout, increased threads, and explicit output file
    timeout "${gau_timeout}" bash -c '
        cat "'"$URLS/gau_domains.txt"'" \
            | "'"$GAU_BIN"'" --threads 5 \
                  --subs \
                  --timeout 30 \
                  --o "'"$URLS/gau_raw.txt"'" \
                  2>"'"$LOGS/gau_errors.log"'"
    ' || true

    # Kill the progress reporter
    kill "$progress_pid" 2>/dev/null; wait "$progress_pid" 2>/dev/null || true

    # Fallback: if --o didn't write (some gau versions), try stdout redirect
    [[ ! -s "$URLS/gau_raw.txt" ]] && {
        info "Retrying $GAU_BIN with stdout redirect..."
        timeout "${gau_timeout}" bash -c '
            cat "'"$URLS/gau_domains.txt"'" \
                | "'"$GAU_BIN"'" --threads 5 --subs --timeout 30 \
                > "'"$URLS/gau_raw.txt"'" 2>"'"$LOGS/gau_errors.log"'"
        ' || true
    }

    sort -u "$URLS/gau_raw.txt" -o "$URLS/gau_urls.txt" 2>/dev/null || true

    local count
    count=$(wc -l < "$URLS/gau_urls.txt" 2>/dev/null || echo 0)
    info "Collected $count historical URLs in $(elapsed $((SECONDS - start)))"
    info "Output → $URLS/gau_urls.txt"
    phase_done "gau"
}

# ─── Phase 7: Active Crawling ────────────────────────────────

phase_katana() {
    phase_check "katana" && return 0
    section "Phase 4b — Active Crawling (katana)"
    local start=$SECONDS

    katana -list "$HTTPX_DIR/alive_final.txt" \
           -d "$KATANA_DEPTH" \
           -jc \
           -silent \
           -concurrency "$CONCURRENCY" \
           -o "$URLS/katana_raw.txt" \
           2>"$LOGS/katana_errors.log"

    sort -u "$URLS/katana_raw.txt" -o "$URLS/katana_urls.txt"

    local count
    count=$(wc -l < "$URLS/katana_urls.txt")
    info "Crawled $count URLs in $(elapsed $((SECONDS - start)))"
    info "Output → $URLS/katana_urls.txt"
    phase_done "katana"
}

# ─── Phase 8: Directory Brute-Forcing ─────────────────────────

phase_ffuf() {
    if [[ "$SKIP_FFUF" == true ]]; then
        warn "Skipping ffuf (--skip-ffuf or no wordlist found)"
        return 0
    fi
    phase_check "ffuf" && return 0

    section "Phase 4c — Directory Brute-Forcing (ffuf)"
    local start=$SECONDS
    local count=0
    local total
    total=$(wc -l < "$HTTPX_DIR/alive_final.txt")
    local current=0

    mkdir -p "$FUZZ/per_host"

    while IFS= read -r host; do
        ((current++))
        local safename
        safename=$(echo "$host" | sed 's|https\?://||;s|[:/]|_|g')
        info "[$current/$total] Fuzzing $host"

        ffuf -u "${host}/FUZZ" \
             -w "$WORDLIST" \
             -mc 200,201,204,301,302,307,401,403,405 \
             -t "$FFUF_THREADS" \
             -sf \
             -s \
             -o "$FUZZ/per_host/${safename}.json" \
             -of json \
             2>>"$LOGS/ffuf_errors.log" || true

    done < "$HTTPX_DIR/alive_final.txt"

    # Consolidate all ffuf results into one file
    find "$FUZZ/per_host" -name "*.json" -exec cat {} + 2>/dev/null \
        | grep -oP '"url"\s*:\s*"\K[^"]+' \
        | sort -u > "$FUZZ/ffuf_all_urls.txt" 2>/dev/null || true

    count=$(wc -l < "$FUZZ/ffuf_all_urls.txt" 2>/dev/null || echo 0)
    info "ffuf discovered $count unique URLs in $(elapsed $((SECONDS - start)))"
    info "Output → $FUZZ/ffuf_all_urls.txt"
    phase_done "ffuf"
}

# ─── Phase 9: Merge All URLs ─────────────────────────────────

phase_merge_urls() {
    phase_check "merge_urls" && return 0
    section "Merging All Discovered URLs"

    cat "$URLS/gau_urls.txt" \
        "$URLS/katana_urls.txt" \
        "$FUZZ/ffuf_all_urls.txt" \
        2>/dev/null | sort -u > "$URLS/all_urls.txt"

    # Create filtered lists for specific content types
    grep -iE '\.(js|jsx|ts|tsx)(\?|$)' "$URLS/all_urls.txt" > "$URLS/js_files.txt" 2>/dev/null || true
    grep -iE '\.(json|xml|yaml|yml|conf|cfg|env|ini|toml)(\?|$)' "$URLS/all_urls.txt" > "$URLS/config_files.txt" 2>/dev/null || true
    grep -iE '\.(php|asp|aspx|jsp|cgi|do|action)(\?|$)' "$URLS/all_urls.txt" > "$URLS/dynamic_endpoints.txt" 2>/dev/null || true
    grep -iE '[\?&][a-zA-Z0-9_]+=' "$URLS/all_urls.txt" > "$URLS/parameterized_urls.txt" 2>/dev/null || true

    local total js config dynamic params
    total=$(wc -l < "$URLS/all_urls.txt")
    js=$(wc -l < "$URLS/js_files.txt" 2>/dev/null || echo 0)
    config=$(wc -l < "$URLS/config_files.txt" 2>/dev/null || echo 0)
    dynamic=$(wc -l < "$URLS/dynamic_endpoints.txt" 2>/dev/null || echo 0)
    params=$(wc -l < "$URLS/parameterized_urls.txt" 2>/dev/null || echo 0)

    info "Total unique URLs: $total"
    info "  JavaScript files: $js"
    info "  Config/sensitive files: $config"
    info "  Dynamic endpoints: $dynamic"
    info "  Parameterized URLs: $params"
    info "Master URL list → $URLS/all_urls.txt"
    phase_done "merge_urls"
}

# ─── Phase 10: Screenshots (Optional) ────────────────────────

phase_screenshots() {
    if ! command -v gowitness &>/dev/null; then
        warn "gowitness not found — skipping screenshots"
        return 0
    fi
    phase_check "screenshots" && return 0

    section "Phase 5 — Visual Recon (gowitness)"
    local start=$SECONDS

    # gowitness v3 CLI: gowitness scan file -f <file>
    # v3 uses subcommands under "scan" (file, single, nmap, nessus, ...)
    if gowitness scan file --help &>/dev/null; then
        # v3+: gowitness scan file -f <file> -s <screenshot-path>
        gowitness scan file \
            -f "$HTTPX_DIR/alive_final.txt" \
            -s "$BASE_DIR/screenshots" \
            -t 10 \
            2>"$LOGS/gowitness_errors.log" || true
    else
        # v2: gowitness file -f file -P dir
        gowitness file \
            -f "$HTTPX_DIR/alive_final.txt" \
            -P "$BASE_DIR/screenshots" \
            --threads 10 \
            2>"$LOGS/gowitness_errors.log" || true
    fi

    local count
    count=$(find "$BASE_DIR/screenshots" -type f \( -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" \) 2>/dev/null | wc -l)
    info "Captured $count screenshots in $(elapsed $((SECONDS - start)))"
    info "Output → $BASE_DIR/screenshots/"
    phase_done "screenshots"
}

# ─── Phase 11: Vulnerability Scanning ─────────────────────────

phase_nuclei() {
    phase_check "nuclei" && return 0
    section "Phase 6 — Vulnerability Scanning (nuclei)"
    local start=$SECONDS

    info "Updating nuclei templates..."
    nuclei -update-templates 2>"$LOGS/nuclei_update.log" || true

    # ─── Deduplicate URLs by path pattern ─────────────────────
    # gau+katana can return 50k+ URLs where most are the same endpoint
    # with different parameter values. Nuclei re-scans each one.
    # Dedup by stripping param values → unique endpoint patterns only.

    local raw_count deduped_count
    raw_count=$(wc -l < "$URLS/all_urls.txt" 2>/dev/null || echo 0)

    if command -v uro &>/dev/null; then
        # uro is purpose-built for this — removes duplicate URL patterns
        cat "$URLS/all_urls.txt" | uro > "$URLS/all_urls_deduped.txt" 2>/dev/null
    else
        # Fallback: keep one URL per unique path (strip query values)
        awk -F'?' '{
            path = $1
            if (!seen[path]++) print
        }' "$URLS/all_urls.txt" | sort -u > "$URLS/all_urls_deduped.txt"
    fi

    deduped_count=$(wc -l < "$URLS/all_urls_deduped.txt" 2>/dev/null || echo 0)
    info "URL dedup: $raw_count → $deduped_count unique patterns ($(( raw_count - deduped_count )) duplicates removed)"

    # ─── Scan 1: Alive hosts (misconfigs, tech-specific CVEs) ─
    info "Scanning alive hosts ($(wc -l < "$HTTPX_DIR/alive_final.txt") targets)..."
    nuclei -l "$HTTPX_DIR/alive_final.txt" \
           -severity "$NUCLEI_SEVERITY" \
           -silent \
           -concurrency "$CONCURRENCY" \
           -stats -stats-interval 30 \
           -o "$VULNS/nuclei_hosts.txt" \
           2>"$LOGS/nuclei_hosts_errors.log" || true

    local hosts_found
    hosts_found=$(wc -l < "$VULNS/nuclei_hosts.txt" 2>/dev/null || echo 0)
    info "Host scan done — $hosts_found findings"

    # ─── Scan 2: Deduped URLs (targeted templates only) ───────
    if [[ "$NUCLEI_URLS" == true ]]; then
        info "Scanning $deduped_count deduplicated URLs (targeted templates)..."
        nuclei -l "$URLS/all_urls_deduped.txt" \
               -t http/cves/ \
               -t http/vulnerabilities/ \
               -t http/exposures/ \
               -t http/misconfiguration/ \
               -severity "$NUCLEI_SEVERITY" \
               -silent \
               -concurrency "$CONCURRENCY" \
               -stats -stats-interval 30 \
               -o "$VULNS/nuclei_urls.txt" \
               2>"$LOGS/nuclei_urls_errors.log" || true

        local urls_found
        urls_found=$(wc -l < "$VULNS/nuclei_urls.txt" 2>/dev/null || echo 0)
        info "URL scan done — $urls_found findings"
    else
        warn "Skipping URL scan (use --nuclei-urls or --nuclei-full to enable)"
    fi

    # ─── Scan 3: Parameterized URLs (injection-focused) ───────
    if [[ "$NUCLEI_PARAMS" == true && -s "$URLS/parameterized_urls.txt" ]]; then
        local param_count
        param_count=$(wc -l < "$URLS/parameterized_urls.txt")

        # Dedup parameterized URLs too
        if command -v uro &>/dev/null; then
            cat "$URLS/parameterized_urls.txt" | uro > "$URLS/parameterized_deduped.txt" 2>/dev/null
        else
            awk -F'?' '{path=$1; if (!seen[path]++) print}' \
                "$URLS/parameterized_urls.txt" | sort -u > "$URLS/parameterized_deduped.txt"
        fi

        local param_deduped
        param_deduped=$(wc -l < "$URLS/parameterized_deduped.txt" 2>/dev/null || echo 0)
        info "Scanning $param_deduped parameterized URLs (from $param_count, injection candidates)..."

        nuclei -l "$URLS/parameterized_deduped.txt" \
               -t http/vulnerabilities/ \
               -t http/cves/ \
               -severity "$NUCLEI_SEVERITY" \
               -silent \
               -concurrency "$CONCURRENCY" \
               -stats -stats-interval 30 \
               -o "$VULNS/nuclei_params.txt" \
               2>"$LOGS/nuclei_params_errors.log" || true
    elif [[ "$NUCLEI_PARAMS" == false ]]; then
        warn "Skipping parameterized URL scan (use --nuclei-params or --nuclei-full to enable)"
    fi

    # ─── Scan 4: CNAME subdomain takeover ─────────────────────
    if [[ -s "$DNS/cnames.txt" ]]; then
        info "Checking CNAMEs for subdomain takeover..."
        awk '{print $1}' "$DNS/cnames.txt" | \
        nuclei -t http/takeovers/ \
               -silent \
               -o "$VULNS/nuclei_takeovers.txt" \
               2>"$LOGS/nuclei_takeover_errors.log" || true
    fi

    # ─── Merge all findings ───────────────────────────────────
    cat "$VULNS"/nuclei_*.txt 2>/dev/null | sort -u > "$VULNS/all_findings.txt"

    local findings
    findings=$(wc -l < "$VULNS/all_findings.txt" 2>/dev/null || echo 0)
    info "Total unique findings: $findings in $(elapsed $((SECONDS - start)))"
    info "Output → $VULNS/all_findings.txt"
    phase_done "nuclei"
}

# ─── Summary Report ───────────────────────────────────────────

generate_report() {
    section "Generating Summary Report"

    local report="$BASE_DIR/REPORT.md"
    cat > "$report" <<EOF
# Recon Report: ${DOMAIN}
**Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Duration:** $(elapsed $((SECONDS - GLOBAL_START)))

---

## Scope
- **Target:** ${DOMAIN}
- **Top ports scanned:** ${TOP_PORTS}
- **Katana depth:** ${KATANA_DEPTH}
- **Nuclei severity:** ${NUCLEI_SEVERITY}

## Asset Discovery
| Metric | Count |
|--------|-------|
| Subdomains found | $(wc -l < "$SUBS/all_subdomains.txt" 2>/dev/null || echo 0) |
| DNS resolved | $(wc -l < "$DNS/resolved_hosts.txt" 2>/dev/null || echo 0) |
| CNAME records | $(wc -l < "$DNS/cnames.txt" 2>/dev/null || echo 0) |
| Virtual hosts (vhosts) | $(wc -l < "$BASE_DIR/vhosts/discovered_vhosts.txt" 2>/dev/null || echo 0) |
| Alive (standard ports) | $(wc -l < "$HTTPX_DIR/alive_standard_urls.txt" 2>/dev/null || echo 0) |
| Alive (all ports) | $(wc -l < "$HTTPX_DIR/alive_final.txt" 2>/dev/null || echo 0) |
| Open ports (naabu) | $(wc -l < "$PORTS/naabu_raw.txt" 2>/dev/null || echo 0) |

## URL Discovery
| Source | URLs |
|--------|------|
| gau (passive) | $(wc -l < "$URLS/gau_urls.txt" 2>/dev/null || echo 0) |
| katana (active) | $(wc -l < "$URLS/katana_urls.txt" 2>/dev/null || echo 0) |
| ffuf (brute-force) | $(wc -l < "$FUZZ/ffuf_all_urls.txt" 2>/dev/null || echo 0) |
| **Total unique** | **$(wc -l < "$URLS/all_urls.txt" 2>/dev/null || echo 0)** |

## URL Breakdown
| Type | Count |
|------|-------|
| JavaScript files | $(wc -l < "$URLS/js_files.txt" 2>/dev/null || echo 0) |
| Config/sensitive | $(wc -l < "$URLS/config_files.txt" 2>/dev/null || echo 0) |
| Dynamic endpoints | $(wc -l < "$URLS/dynamic_endpoints.txt" 2>/dev/null || echo 0) |
| Parameterized URLs | $(wc -l < "$URLS/parameterized_urls.txt" 2>/dev/null || echo 0) |

## Vulnerability Findings
| Scan | Findings |
|------|----------|
| Host-based | $(wc -l < "$VULNS/nuclei_hosts.txt" 2>/dev/null || echo 0) |
| URL-based | $(wc -l < "$VULNS/nuclei_urls.txt" 2>/dev/null || echo 0) |
| Parameter-based | $(wc -l < "$VULNS/nuclei_params.txt" 2>/dev/null || echo 0) |
| Subdomain takeover | $(wc -l < "$VULNS/nuclei_takeovers.txt" 2>/dev/null || echo 0) |
| **Total unique** | **$(wc -l < "$VULNS/all_findings.txt" 2>/dev/null || echo 0)** |

## Output Directory
\`\`\`
${BASE_DIR}/
├── subdomains/          # Subdomain enumeration
├── dns/                 # DNS resolution & CNAMEs
├── httpx/               # Live host probing
├── ports/               # Port scan results
├── urls/                # All discovered URLs
├── fuzzing/             # ffuf results per host
├── vulnerabilities/     # Nuclei findings
├── screenshots/         # gowitness captures
└── logs/                # Tool error logs
\`\`\`

## Next Steps
1. Review \`vulnerabilities/all_findings.txt\` for quick wins
2. Check \`dns/cnames.txt\` for subdomain takeover candidates
3. Inspect \`urls/config_files.txt\` for exposed configs
4. Open \`urls/parameterized_urls.txt\` in Burp for manual testing
5. Review \`urls/js_files.txt\` for secrets / API keys
6. Browse screenshots in \`screenshots/\` for visual triage
EOF

    info "Report saved → $report"
}

# ─── Notification (Optional) ─────────────────────────────────

send_notification() {
    if ! command -v notify &>/dev/null; then
        return 0
    fi

    local findings
    findings=$(wc -l < "$VULNS/all_findings.txt" 2>/dev/null || echo 0)

    echo "reconpipe complete for ${DOMAIN}: ${findings} findings" | notify -silent 2>/dev/null || true
    info "Notification sent via notify"
}

# ─── Main Execution ───────────────────────────────────────────

main() {
    GLOBAL_START=$SECONDS
    banner

    info "Target: ${DOMAIN}$([ "$TARGET_IS_IP" == true ] && echo ' [IP mode]' || echo ' [domain mode]')"
    info "Output: ${BASE_DIR}/"
    info "Started: $(date '+%Y-%m-%d %H:%M:%S %Z')"

    check_tools

    phase_subdomains
    phase_dns
    phase_httpx_standard
    phase_naabu
    phase_httpx_allports
    phase_vhosts
    phase_gau
    phase_katana
    phase_ffuf
    phase_merge_urls
    phase_screenshots
    phase_nuclei

    generate_report
    send_notification

    section "Done"
    touch "$BASE_DIR/.done"
    info "Total time: $(elapsed $((SECONDS - GLOBAL_START)))"
    info "All outputs: ${BASE_DIR}/"
    info "Report: ${BASE_DIR}/REPORT.md"
    info "Findings: ${BASE_DIR}/vulnerabilities/all_findings.txt"
    echo ""
}

main
