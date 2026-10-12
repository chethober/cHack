#!/bin/bash

# Configuration
TARGETS_DIR="../targets"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/cHack.log"
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

# Ensure GRAPHQL_ENDPOINT defaults to BACKEND_URL/graphql if not explicitly defined
if [ -z "$GRAPHQL_ENDPOINT" ] && [ -n "$BACKEND_URL" ]; then
    GRAPHQL_ENDPOINT="${BACKEND_URL%/}/graphql"
fi
export BACKEND_URL
export GRAPHQL_ENDPOINT

# Concurrency & thread settings (can be overridden by env, .env, or -t/--threads)
THREADS="${THREADS:-50}"

# Opt-in active secret verification. When enabled, the JS scanner pings each
# provider's read-only API to confirm which matched credentials are actually
# live, promoting them to "confirmed-live" and discarding dead ones. This sends
# captured tokens to third parties, so it is OFF by default — only enable it for
# targets you are explicitly authorized to test. Set VERIFY_SECRETS=1 to enable.
VERIFY_SECRETS="${VERIFY_SECRETS:-0}"
export VERIFY_SECRETS

# Ensure extended PATH includes all Go, Python, and local binaries
if command -v go >/dev/null 2>&1; then
    _gopath="$(go env GOPATH 2>/dev/null)"
    [ -n "$_gopath" ] && [ -d "$_gopath/bin" ] && export PATH="$_gopath/bin:$PATH"
fi
export PATH="$HOME/go/bin:/usr/local/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

log_info() {
    local timestamp=$(date '+%H:%M:%S')
    echo -e "\033[0;32m[INFO][$timestamp]\033[0m $1" >&2
    echo "[INFO][$timestamp] $1" >> "$LOG_FILE"
}

log_warn() {
    local timestamp=$(date '+%H:%M:%S')
    echo -e "\033[0;33m[WARN][$timestamp]\033[0m $1" >&2
    echo "[WARN][$timestamp] $1" >> "$LOG_FILE"
}

log_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[0;31m[ERROR][$timestamp]\033[0m $1" >&2
    echo "[ERROR][$timestamp] $1" >> "$LOG_FILE"
}

log_phase() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\n\033[0;34m[$timestamp]\033[0m $1" >&2
    echo -e "\n[PHASE][$timestamp] $1" >> "$LOG_FILE"
}

count_lines() {
    local file="$1"
    if [ -s "$file" ]; then
        wc -l < "$file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# Required Tools (Imported from Reconner)
REQUIRED_GO_TOOLS=(
    "subfinder"
    "httpx"
    "naabu"
    "katana"
    "nuclei"
    "dnsx"
    "alterx"
    "assetfinder"
    "gau"
    "waybackurls"
    "hakrawler"
    "dalfox"
    "subzy"
)

OPTIONAL_TOOLS=(
    "puredns"
    "gowitness"
    "scilla"
    "dirsearch"
    "waymore"
    "uro"
    "sqlmap"
    "findomain"
    "feroxbuster"
    "nmap"
)

get_tool_package() {
    case "$1" in
        httpx) echo "github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
        naabu) echo "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" ;;
        subfinder) echo "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
        assetfinder) echo "github.com/tomnomnom/assetfinder@latest" ;;
        katana) echo "github.com/projectdiscovery/katana/cmd/katana@latest" ;;
        nuclei) echo "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
        dnsx) echo "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" ;;
        alterx) echo "github.com/projectdiscovery/alterx/cmd/alterx@latest" ;;
        gau) echo "github.com/lc/gau/v2/cmd/gau@latest" ;;
        waybackurls) echo "github.com/tomnomnom/waybackurls@latest" ;;
        hakrawler) echo "github.com/hakluke/hakrawler@latest" ;;
        dalfox) echo "github.com/hahwul/dalfox/v2@latest" ;;
        subzy) echo "github.com/PentestPad/subzy@latest" ;;
        scilla) echo "github.com/edoardottt/scilla/cmd/scilla@latest" ;;
        puredns) echo "github.com/d3mondev/puredns/v2@latest" ;;
        gowitness) echo "github.com/sensepost/gowitness@latest" ;;
    esac
}

check_requirements() {
    # Check system tool requirements
    local system_tools=("jq" "curl" "whois" "python3")
    local missing_system=()
    for tool in "${system_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_system+=("$tool")
        fi
    done

    if [ ${#missing_system[@]} -gt 0 ]; then
        log_error "Missing required system dependencies: ${missing_system[*]}. Please install them via your package manager."
        return 1
    fi

    # Check if go is installed
    if ! command -v go >/dev/null 2>&1; then
        log_error "Go language (go) is required. Please ensure Go >= 1.23 is installed."
        return 1
    fi

    # Check required Go tools
    local missing_tools=()
    for tool in "${REQUIRED_GO_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        elif [ "$tool" = "httpx" ] && ! httpx -version 2>&1 | grep -qi "projectdiscovery"; then
            if [ -x "$HOME/go/bin/httpx" ]; then
                export PATH="$HOME/go/bin:$PATH"
            else
                missing_tools+=("httpx")
            fi
        fi
    done

    # If any tools are missing, install them synchronously
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_info "Missing required tools: ${missing_tools[*]}. Installing now..."
        for tool in "${missing_tools[@]}"; do
            local pkg
            pkg=$(get_tool_package "$tool")
            if [ -n "$pkg" ]; then
                log_info "Installing $tool ($pkg)..."
                if go install "$pkg" >/dev/null 2>&1; then
                    log_info "Successfully installed $tool"
                else
                    log_error "Failed to install $tool"
                fi
            fi
        done
    fi

    # Auto-update check: run once every 7 days in the background
    local last_check_file="$SCRIPT_DIR/.last_update_check"
    local current_time=$(date +%s)
    local last_check=0
    if [ -f "$last_check_file" ]; then
        last_check=$(cat "$last_check_file" 2>/dev/null || echo 0)
    fi

    local elapsed=$((current_time - last_check))
    # 604800 seconds = 7 days
    if [ $elapsed -gt 604800 ]; then
        log_info "Periodic tool update check scheduled in the background..."
        echo "$current_time" > "$last_check_file"
        (
            for tool in "${REQUIRED_GO_TOOLS[@]}"; do
                local pkg
                pkg=$(get_tool_package "$tool")
                if [ -n "$pkg" ]; then
                    go install "$pkg" >/dev/null 2>&1
                fi
            done
        ) &
    fi
    return 0
}

SENDER_ID=""

send_telegram_notification() {
    local message="$1"
    if [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$SENDER_ID" ]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${SENDER_ID}" \
            --data-urlencode "text=${message}" \
            -d "parse_mode=HTML" >/dev/null 2>&1
    fi
}

escape_sql() {
    echo "$1" | sed "s/'/''/g"
}

strip_scheme() {
    echo "$1" | sed -E 's|^https?://||'
}

execute_graphql() {
    local query="$1"
    local variables="$2"
    if [ -z "$variables" ]; then
        variables="{}"
    fi

    # Auto-resolve GRAPHQL_ENDPOINT from BACKEND_URL if unset or pointing to localhost when remote backend is used
    if [ -z "$GRAPHQL_ENDPOINT" ] && [ -n "$BACKEND_URL" ]; then
        GRAPHQL_ENDPOINT="${BACKEND_URL%/}/graphql"
    elif [[ "$GRAPHQL_ENDPOINT" == *"localhost"* || "$GRAPHQL_ENDPOINT" == *"127.0.0.1"* ]] && [[ -n "$BACKEND_URL" && "$BACKEND_URL" != *"localhost"* && "$BACKEND_URL" != *"127.0.0.1"* ]]; then
        GRAPHQL_ENDPOINT="${BACKEND_URL%/}/graphql"
    fi

    local payload
    if ! payload=$(jq -n --arg query "$query" --arg vars "$variables" '{query: $query, variables: ($vars | fromjson)}' 2>&1); then
        log_error "Failed to construct GraphQL payload: $payload"
        return 1
    fi

    local response
    local success=false

    if [ -n "$GRAPHQL_ENDPOINT" ]; then
        if response=$(curl -s --connect-timeout 10 -m 15 -X POST "$GRAPHQL_ENDPOINT" \
            -H "Content-Type: application/json" \
            -d "$payload" 2>&1); then
            if ! echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
                success=true
            fi
        fi
    fi

    if [ "$success" = true ]; then
        local temp_gql_in
        local temp_gql_res
        if temp_gql_in=$(mktemp 2>/dev/null) && temp_gql_res=$(mktemp 2>/dev/null); then
            echo "$payload" > "$temp_gql_in"
            echo "$response" > "$temp_gql_res"
            python3 "$SCRIPT_DIR/db_sqlite.py" graphql "$temp_gql_in" "$temp_gql_res" >/dev/null 2>&1 &
        fi
        echo "$response"
        return 0
    else
        log_info "Resolving mutation/query locally via SQLite mirror..."
        local temp_gql_in
        if temp_gql_in=$(mktemp 2>/dev/null); then
            echo "$payload" > "$temp_gql_in"
            if response=$(python3 "$SCRIPT_DIR/db_sqlite.py" query "$temp_gql_in" 2>/dev/null); then
                echo "$response"
                return 0
            else
                log_error "GraphQL local SQLite resolution failed."
                return 1
            fi
        fi
    fi
}

db_add_user() {
    local username="$1"
    local number_id="$2"
    local first_name="$3"
    local last_name="$4"

    local query="mutation CreateUser(\$username: String!, \$number_id: BigInt, \$first_name: String, \$last_name: String) {
        createUser(username: \$username, number_id: \$number_id, first_name: \$first_name, last_name: \$last_name) {
            id
            username
        }
    }"

    local variables
    variables=$(jq -n \
        --arg u "$username" \
        --arg n "$number_id" \
        --arg f "$first_name" \
        --arg l "$last_name" \
        '{
            username: $u,
            number_id: (if $n == "" then null else ($n | tonumber) end),
            first_name: (if $f == "" then null else $f end),
            last_name: (if $l == "" then null else $l end)
        }')

    local response
    response=$(execute_graphql "$query" "$variables")
    if [ $? -eq 0 ]; then
        local user_id
        user_id=$(echo "$response" | jq -r '.data.createUser.id // empty')
        log_info "User '$username' created successfully with ID: $user_id"
        echo "$user_id"
    else
        log_error "Failed to create user '$username'"
        return 1
    fi
}

db_add_company() {
    local name="$1"
    local slug="$2"
    local description="$3"
    local owner_user_id="$4"
    local data="$5"

    if [ -z "$data" ]; then
        data="{}"
    fi

    local query="mutation CreateCompany(\$input: CompanyInput!) {
        createCompany(input: \$input) {
            id
            name
            slug
        }
    }"

    local variables
    variables=$(jq -n \
        --arg name "$name" \
        --arg slug "$slug" \
        --arg desc "$description" \
        --arg owner "$owner_user_id" \
        --argjson data "$data" \
        '{
            input: {
                name: $name,
                slug: (if $slug == "" then null else $slug end),
                description: (if $desc == "" then null else $desc end),
                owner_user_id: (if $owner == "" then null else $owner end),
                data: $data
            }
        }')

    local response
    response=$(execute_graphql "$query" "$variables")
    if [ $? -eq 0 ]; then
        local company_id
        company_id=$(echo "$response" | jq -r '.data.createCompany.id // empty')
        log_info "Company '$name' created successfully with ID: $company_id"
        echo "$company_id"
    else
        log_error "Failed to create company '$name'"
        return 1
    fi
}

db_add_person() {
    local company_id="$1"
    local given_name="$2"
    local family_name="$3"
    local emails="$4"
    local phones="$5"
    local notes="$6"
    local data="$7"
    local created_by="$8"

    if [ -z "$emails" ]; then emails="[]"; fi
    if [ -z "$phones" ]; then phones="[]"; fi
    if [ -z "$data" ]; then data="{}"; fi

    local query="mutation CreatePerson(\$input: PeopleInput!) {
        createPeople(input: \$input) {
            id
            given_name
            family_name
        }
    }"

    local variables
    variables=$(jq -n \
        --arg cid "$company_id" \
        --arg gn "$given_name" \
        --arg fn "$family_name" \
        --argjson em "$emails" \
        --argjson ph "$phones" \
        --arg nt "$notes" \
        --argjson dt "$data" \
        --arg cb "$created_by" \
        '{
            input: {
                company_id: $cid,
                given_name: (if $gn == "" then null else $gn end),
                family_name: (if $fn == "" then null else $fn end),
                emails: $em,
                phones: $ph,
                notes: (if $nt == "" then null else $nt end),
                data: $dt
            }
        }')

    local response
    response=$(execute_graphql "$query" "$variables")
    if [ $? -eq 0 ]; then
        local person_id
        person_id=$(echo "$response" | jq -r '.data.createPeople.id // empty')
        log_info "Person '$given_name $family_name' created with ID: $person_id"
        echo "$person_id"
    else
        log_error "Failed to create person '$given_name $family_name'"
        return 1
    fi
}

db_get_company_by_slug() {
    local slug="$1"
    local query="query GetCompanyBySlug(\$slug: String!) {
        companyBySlug(slug: \$slug) {
            id
        }
    }"
    local variables
    variables=$(jq -n --arg s "$slug" '{slug: $s}')

    local response
    response=$(execute_graphql "$query" "$variables")
    if [ $? -eq 0 ]; then
        echo "$response" | jq -r '.data.companyBySlug.id // empty'
    fi
}

db_add_domain() {
    local company_id="$1"
    local host="$2"
    local canonical_url="$3"
    local data="$4"

    if [ -z "$data" ]; then
        data="{}"
    fi

    local query="mutation CreateDomain(\$input: DomainInput!) {
        createDomain(input: \$input) {
            id
            host
        }
    }"

    local variables
    variables=$(jq -n \
        --arg cid "$company_id" \
        --arg h "$host" \
        --arg u "$canonical_url" \
        --argjson d "$data" \
        '{
            input: {
                company_id: $cid,
                host: $h,
                canonical_url: (if $u == "" then null else $u end),
                data: $d
            }
        }')

    local response
    response=$(execute_graphql "$query" "$variables")
    if [ $? -eq 0 ]; then
        echo "$response" | jq -r '.data.createDomain.id // empty'
    fi
}

insert_company_and_domains() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local httpx_file="$output_dir/httpx.json"
    local live_hosts_file="$output_dir/live_hosts"

    log_info "Checking if company exists for domain: $domain"
    local company_id
    company_id=$(db_get_company_by_slug "$domain")

    if [ -z "$company_id" ]; then
        log_info "Company does not exist. Creating company: $domain"
        company_id=$(db_add_company "$domain" "$domain" "Target company created automatically for $domain" "" '{"phase": "1"}')
    fi

    if [ -z "$company_id" ]; then
        log_error "Failed to retrieve or create company for domain: $domain"
        return 1
    fi

    # Only insert active subdomains that responded with a status code during HTTPX probing
    local active_subs_file="$output_dir/active_subdomains"
    if [ -s "$httpx_file" ]; then
        # Extract unique hosts from httpx.json (prefer input hostname, fallback to url domain)
        jq -r '(.input // (.url | sub("^https?://"; "") | sub("[:/].*"; "")) // empty)' "$httpx_file" 2>/dev/null | tr '[:upper:]' '[:lower:]' | grep -v '^$' | sort -u > "$active_subs_file"
    elif [ -s "$live_hosts_file" ]; then
        sed -E 's|^https?://||; s|[:/].*$||' "$live_hosts_file" | tr '[:upper:]' '[:lower:]' | grep -v '^$' | sort -u > "$active_subs_file"
    else
        log_info "No active subdomains found responding to HTTP probes. Skipping subdomain DB insertion."
        return 0
    fi

    local active_count
    active_count=$(count_lines "$active_subs_file")
    log_info "Inserting $active_count active subdomain(s) into database with parallel workers..."

    local db_workers=10
    local running=0
    while IFS= read -r host; do
        if [ -n "$host" ]; then
            ( db_add_domain "$company_id" "$host" "https://$host" "{}" >/dev/null 2>&1 ) &
            running=$((running + 1))
            if [ $running -ge $db_workers ]; then
                wait -n 2>/dev/null || wait
                running=$((running - 1))
            fi
        fi
    done < "$active_subs_file"
    wait

    log_info "Successfully processed company $domain (ID: $company_id) and inserted $active_count active subdomains"
}

update_httpx_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    if [ ! -s "$output_dir/httpx.json" ]; then
        log_info "httpx.json is empty. Skipping results processing."
        return
    fi

    log_info "GraphQL: Uploading httpx results..."
    local results_json
    results_json=$(jq -s '.' "$output_dir/httpx.json")

    local query="mutation UpdateHttpxResults(\$domain: String!, \$results: [JSON!]!) {
        updateHttpxResults(domain: \$domain, results: \$results)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson res "$results_json" '{domain: $dom, results: $res}')
    execute_graphql "$query" "$variables" >/dev/null
}

update_port_scan_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    if [ ! -s "$output_dir/ports.json" ]; then
        return
    fi

    local ports_json
    ports_json=$(jq -c . "$output_dir/ports.json")

    local ips_json="[]"
    if [ -s "$output_dir/ips" ]; then
        ips_json=$(jq -R . < "$output_dir/ips" | jq -s .)
    fi

    log_info "GraphQL: Uploading port scan results..."
    local query="mutation UpdatePortScanResults(\$domain: String!, \$ports: JSON!, \$ips: JSON!) {
        updatePortScanResults(domain: \$domain, ports: \$ports, ips: \$ips)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson ports "$ports_json" --argjson ips "$ips_json" '{domain: $dom, ports: $ports, ips: $ips}')
    execute_graphql "$query" "$variables" >/dev/null
}

update_findings_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local findings_file="$output_dir/all_findings.json"

    if [ ! -s "$findings_file" ]; then
        return
    fi

    log_info "GraphQL: Uploading vulnerability findings..."
    local findings_json
    findings_json=$(cat "$findings_file")

    local query="mutation CreateFindingsBatch(\$domain: String!, \$findings: [FindingInput!]!) {
        createFindingsBatch(domain: \$domain, findings: \$findings)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson f "$findings_json" '{domain: $dom, findings: $f}')
    execute_graphql "$query" "$variables" >/dev/null
}

update_endpoints_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local endpoints_file="$output_dir/all_endpoints.json"

    if [ ! -s "$endpoints_file" ]; then
        return
    fi

    log_info "GraphQL: Uploading discovered endpoints..."
    local endpoints_json
    endpoints_json=$(cat "$endpoints_file")

    local query="mutation CreateEndpointsBatch(\$domain: String!, \$endpoints: [EndpointInput!]!) {
        createEndpointsBatch(domain: \$domain, endpoints: \$endpoints)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson ep "$endpoints_json" '{domain: $dom, endpoints: $ep}')
    execute_graphql "$query" "$variables" >/dev/null
}

update_secrets_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local secrets_file="$output_dir/all_secrets.json"

    if [ ! -s "$secrets_file" ]; then
        return
    fi

    log_info "GraphQL: Uploading discovered secrets & API keys..."
    local secrets_json
    secrets_json=$(cat "$secrets_file")

    local query="mutation CreateSecretsBatch(\$domain: String!, \$secrets: [SecretInput!]!) {
        createSecretsBatch(domain: \$domain, secrets: \$secrets)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson sec "$secrets_json" '{domain: $dom, secrets: $sec}')
    execute_graphql "$query" "$variables" >/dev/null
}

update_js_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local findings_file="$output_dir/js_findings.json"

    if [ ! -s "$findings_file" ]; then
        return
    fi

    log_info "GraphQL: Syncing JS analysis findings & endpoints..."
    local findings_json
    local endpoints_json
    findings_json=$(jq '.secrets // []' "$findings_file" 2>/dev/null || echo "[]")
    endpoints_json=$(jq '.endpoints // []' "$findings_file" 2>/dev/null || echo "[]")

    local query="mutation UpdateJsResults(\$domain: String!, \$results: [JSON!]!) {
        updateJsResults(domain: \$domain, results: \$results)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson find "$findings_json" --argjson ep "$endpoints_json" \
        '{domain: $dom, results: [{host: $dom, findings: $find, endpoints: $ep}]}')
    execute_graphql "$query" "$variables" >/dev/null
}

update_network_services_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local services_file="$output_dir/network_services.json"

    if [ ! -s "$services_file" ]; then
        return
    fi

    log_info "GraphQL: Uploading network services & banners..."
    local services_json
    services_json=$(cat "$services_file")

    local query="mutation CreateNetworkServicesBatch(\$domain: String!, \$services: [NetworkServiceInput!]!) {
        createNetworkServicesBatch(domain: \$domain, services: \$services)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson srv "$services_json" '{domain: $dom, services: $srv}')
    execute_graphql "$query" "$variables" >/dev/null
}

# ==============================================================================
# PHASE 1: Subdomain Discovery & Takeover Verification
# ==============================================================================
run_subdomain_enum() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    mkdir -p "$output_dir"

    log_phase "Phase 1: Subdomain Enumeration & Takeover Checks"
    log_info "Target domain: $domain"

    # 1. Passive Tools in Parallel
    log_info "Running passive subdomain discovery tools in parallel (subfinder, assetfinder, findomain, gau)..."
    ( timeout 180 subfinder -d "$domain" -silent -t "$THREADS" -disable-update-check > "$output_dir/subfinder" 2>/dev/null || touch "$output_dir/subfinder" ) &
    local pid_subfinder=$!

    ( timeout 120 assetfinder --subs-only "$domain" > "$output_dir/assetfinder" 2>/dev/null || touch "$output_dir/assetfinder" ) &
    local pid_assetfinder=$!

    local pid_findomain=""
    if command -v findomain >/dev/null 2>&1; then
        ( timeout 120 findomain -t "$domain" -q > "$output_dir/findomain" 2>/dev/null || touch "$output_dir/findomain" ) &
        pid_findomain=$!
    fi

    local pid_gau=""
    if command -v gau >/dev/null 2>&1; then
        ( timeout 60 gau --subs "$domain" --threads 10 2>/dev/null | grep -Eo "([a-zA-Z0-9_-]+\.)+${domain}" | sort -u > "$output_dir/gau_subs" || touch "$output_dir/gau_subs" ) &
        pid_gau=$!
    fi

    # Synchronize all passive tools
    wait $pid_subfinder $pid_assetfinder ${pid_findomain:+$pid_findomain} ${pid_gau:+$pid_gau} 2>/dev/null

    # Combine passive subdomains
    cat "$output_dir/subfinder" "$output_dir/assetfinder" "$output_dir/findomain" "$output_dir/gau_subs" 2>/dev/null | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' | sort -u | grep -E "\.${domain}$|^${domain}$" > "$output_dir/subdomains_raw"

    # Always ensure the apex domain and www subdomain are included for probing
    printf "%s\nwww.%s\n" "$domain" "$domain" >> "$output_dir/subdomains_raw"
    sort -u -o "$output_dir/subdomains_raw" "$output_dir/subdomains_raw"

    # 2. Active Permutations (Alterx) if available
    if command -v alterx >/dev/null 2>&1 && [ -s "$output_dir/subdomains_raw" ]; then
        log_info "Running alterx permutations..."
        head -n 50 "$output_dir/subdomains_raw" | alterx -silent 2>/dev/null | head -n 300 > "$output_dir/alterx_subs"
        cat "$output_dir/subdomains_raw" "$output_dir/alterx_subs" 2>/dev/null | sort -u > "$output_dir/subdomains"
    else
        cp "$output_dir/subdomains_raw" "$output_dir/subdomains"
    fi

    local sub_count
    sub_count=$(count_lines "$output_dir/subdomains")
    log_info "Subdomain enumeration completed. Total unique subdomains: $sub_count"

    # 3. Subdomain Takeover Check (subzy)
    if command -v subzy >/dev/null 2>&1 && [ -s "$output_dir/subdomains" ]; then
        log_info "Checking subdomains for takeover vulnerabilities (subzy)..."
        subzy run --targets "$output_dir/subdomains" --hide_fails > "$output_dir/subzy.log" 2>/dev/null || true
        
        # Parse takeover findings
        if grep -qi "vulnerable" "$output_dir/subzy.log" 2>/dev/null; then
            log_info "🚨 Subdomain takeover finding identified!"
            grep -i "vulnerable" "$output_dir/subzy.log" | while read -r line; do
                local t_sub=$(echo "$line" | grep -oE "([a-zA-Z0-9_-]+\.)+${domain}")
                if [ -n "$t_sub" ]; then
                    send_telegram_notification "🚨 <b>CRITICAL: Subdomain Takeover Found!</b>
• Subdomain: <code>$t_sub</code>
• Evidence: <i>$line</i>"
                fi
            done
        fi
    fi
}

# ==============================================================================
# PHASE 2: Live HTTP Resolution, Tech & Visual Recon
# ==============================================================================
run_httpx() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    log_phase "Phase 2: Live HTTP Probing & Fingerprinting (HTTPX)"

    if [ ! -s "$output_dir/subdomains" ]; then
        log_info "No subdomains to scan. Skipping HTTPX."
        echo "[]" > "$output_dir/httpx.json"
        touch "$output_dir/live_hosts"
        touch "$output_dir/ips"
        return
    fi

    log_info "Probing $(count_lines "$output_dir/subdomains") subdomains with httpx..."

    local httpx_err
    httpx_err=$(mktemp)

    timeout 300 httpx -list "$output_dir/subdomains" \
        -silent \
        -nc \
        -sc \
        -title \
        -ip \
        -server \
        -json \
        -td \
        -fr \
        -t "$THREADS" \
        -timeout 6 \
        -retries 1 \
        -disable-update-check \
        -o "$output_dir/httpx.json" 2>"$httpx_err"
    local exit_code=$?

    if [ $exit_code -ne 0 ] && [ $exit_code -ne 124 ]; then
        local err_msg
        err_msg=$(head -n 2 "$httpx_err" 2>/dev/null | tr '\n' ' ')
        log_error "httpx failed (exit code $exit_code): ${err_msg:-check tool logs}"
        rm -f "$httpx_err"
        touch "$output_dir/live_hosts"
        touch "$output_dir/ips"
        return 1
    elif [ $exit_code -eq 124 ]; then
        log_warn "httpx timed out after 300 seconds."
    fi
    rm -f "$httpx_err"

    if [ ! -s "$output_dir/httpx.json" ]; then
        log_info "HTTPX probe completed: 0 live web endpoints responded for $domain."
        touch "$output_dir/live_hosts"
        touch "$output_dir/ips"
        return 0
    fi

    # Extract live hosts and IPs
    jq -r '.url // empty' "$output_dir/httpx.json" | sort -u > "$output_dir/live_hosts"
    jq -r '[(.host // empty), (.host_ip // empty), ((.a // [])[])] | .[]' "$output_dir/httpx.json" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "$output_dir/ips"

    local live_count=$(count_lines "$output_dir/live_hosts")
    log_info "HTTPX scan completed. Found $live_count live web endpoints."

    # Visual Recon (gowitness) if available
    if command -v gowitness >/dev/null 2>&1 && [ -s "$output_dir/live_hosts" ]; then
        log_info "Capturing web screenshots (gowitness)..."
        mkdir -p "$output_dir/screenshots"
        timeout 180 gowitness scan file -f "$output_dir/live_hosts" --screenshot-path "$output_dir/screenshots" --threads 4 >/dev/null 2>&1 || true
    fi
}

# ==============================================================================
# PHASE 3: Port Scanning & Network Service Auditing
# ==============================================================================
run_naabu() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    if [ ! -s "$output_dir/ips" ]; then
        log_info "No IPs found to scan. Skipping port scan."
        echo "{}" > "$output_dir/ports.json"
        touch "$output_dir/ports"
        echo "[]" > "$output_dir/network_services.json"
        return 0
    fi

    local ip_count=$(count_lines "$output_dir/ips")
    log_phase "Phase 3: Port Scanning & Service Enumeration (Naabu)"
    log_info "Scanning $ip_count IP addresses..."

    timeout 300 naabu -hL "$output_dir/ips" \
        -silent \
        -c "$THREADS" \
        -rate 1000 \
        -top-ports 1000 \
        -json \
        -o "$output_dir/naabu.json" > /dev/null 2>&1 || touch "$output_dir/naabu.json"

    # Also generate classic ip:port text file
    if [ -s "$output_dir/naabu.json" ]; then
        jq -r '"\(.ip):\(.port)"' "$output_dir/naabu.json" | sort -u > "$output_dir/ports"
    else
        touch "$output_dir/ports"
    fi

    # Group ports into JSON and extract network services
    if [ -s "$output_dir/ports" ]; then
        declare -A ip_ports
        local srv_list="[]"

        while IFS=: read -r ip port; do
            [ -z "$ip" ] || [ -z "$port" ] && continue
            ip_ports["$ip"]+="$port "
            
            # Infer basic service name from well-known ports
            local sname="unknown"
            case "$port" in
                21) sname="ftp" ;;
                22) sname="ssh" ;;
                23) sname="telnet" ;;
                25) sname="smtp" ;;
                53) sname="dns" ;;
                80|8080|8000|8888) sname="http" ;;
                443|8443|4443) sname="https" ;;
                445|139) sname="smb" ;;
                3306) sname="mysql" ;;
                3389) sname="rdp" ;;
                5432) sname="postgresql" ;;
                6379) sname="redis" ;;
                27017) sname="mongodb" ;;
            esac

            local s_item=$(jq -n --arg ip "$ip" --arg p "$port" --arg s "$sname" '{ip: $ip, port: ($p|tonumber), protocol: "tcp", service: $s}')
            srv_list=$(echo "$srv_list" | jq --argjson item "$s_item" '. += [$item]')
        done < "$output_dir/ports"

        echo "$srv_list" > "$output_dir/network_services.json"

        {
            echo "{"
            count=0
            total_ips=${#ip_ports[@]}
            for ip in "${!ip_ports[@]}"; do
                ports_array=(${ip_ports["$ip"]})
                ports_json=$(printf '"%s",' "${ports_array[@]}")
                ports_json="[${ports_json%,}]"
                count=$((count + 1))
                if [ "$count" -lt "$total_ips" ]; then
                    echo "\"$ip\": $ports_json,"
                else
                    echo "\"$ip\": $ports_json"
                fi
            done
            echo "}"
        } > "$output_dir/ports.json"

        log_info "Open ports grouped into ports.json and network_services.json"
    else
        echo "{}" > "$output_dir/ports.json"
        echo "[]" > "$output_dir/network_services.json"
    fi
}

# ==============================================================================
# PHASE 4: Deep Web Crawling, Parameter Mining & JS Secrets Analysis
# ==============================================================================
run_katana() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    log_phase "Phase 4: Web Crawling, URL Discovery & JS Secret Mining"

    if [ ! -s "$output_dir/live_hosts" ]; then
        log_info "No live hosts for crawling. Skipping Phase 4."
        return
    fi

    log_info "Crawling $(count_lines "$output_dir/live_hosts") endpoints in parallel (Katana + Gau)..."

    # 1. Katana Crawling & 2. Historical URLs in Parallel
    (
        timeout 300 katana -list "$output_dir/live_hosts" \
            -silent \
            -jc 20 \
            -kf all \
            -c "$THREADS" \
            -d 3 \
            -timeout 8 \
            -retries 1 \
            -disable-update-check \
            > "$output_dir/katana_crawl" 2>/dev/null || touch "$output_dir/katana_crawl"
    ) &
    local pid_katana=$!

    local pid_gau=""
    if command -v gau >/dev/null 2>&1; then
        (
            timeout 90 gau "$domain" --subs --threads 10 2>/dev/null | head -n 2000 > "$output_dir/gau_urls" || touch "$output_dir/gau_urls"
        ) &
        pid_gau=$!
    fi

    wait $pid_katana ${pid_gau:+$pid_gau} 2>/dev/null
    cat "$output_dir/katana_crawl" "$output_dir/gau_urls" 2>/dev/null > "$output_dir/katana_raw"
    rm -f "$output_dir/katana_crawl" "$output_dir/gau_urls" 2>/dev/null

    # 3. Clean & Deduplicate with uro if available
    if command -v uro >/dev/null 2>&1 && [ -s "$output_dir/katana_raw" ]; then
        uro -i "$output_dir/katana_raw" -o "$output_dir/katana_all" 2>/dev/null || cp "$output_dir/katana_raw" "$output_dir/katana_all"
    else
        sort -u "$output_dir/katana_raw" > "$output_dir/katana_all"
    fi

    # Extract JS files and parameter endpoints
    grep -Ei '\.js(\?.*)?$' "$output_dir/katana_all" | sort -u > "$output_dir/js_links"
    grep -Ei '\?.+=' "$output_dir/katana_all" | sort -u > "$output_dir/params"

    # 4. Manifest Discovery & Inline Script Extraction across Live Hosts
    if [ -s "$output_dir/live_hosts" ] && [ -f "$SCRIPT_DIR/js_secrets.py" ]; then
        log_info "Probing live hosts for Next.js/Webpack manifests & inline scripts..."
        python3 "$SCRIPT_DIR/js_secrets.py" --extract-live "$output_dir/live_hosts" "$output_dir" "$THREADS" 2>/dev/null || true
        
        # Re-deduplicate js_links and katana_all after manifest/inline extraction
        if [ -s "$output_dir/js_links" ]; then
            sort -u "$output_dir/js_links" -o "$output_dir/js_links"
        fi
        if [ -s "$output_dir/katana_all" ]; then
            if command -v uro >/dev/null 2>&1; then
                uro -i "$output_dir/katana_all" -o "$output_dir/katana_all.tmp" 2>/dev/null && mv "$output_dir/katana_all.tmp" "$output_dir/katana_all"
            else
                sort -u "$output_dir/katana_all" -o "$output_dir/katana_all"
            fi
        fi
    fi

    log_info "Crawling extracted $(count_lines "$output_dir/katana_all") URLs, $(count_lines "$output_dir/js_links") JS files, and $(count_lines "$output_dir/params") parameterized endpoints."

    # 5. Deep JS Secret & Endpoint Analysis (Multi-threaded)
    if [ -s "$output_dir/js_links" ] && [ -f "$SCRIPT_DIR/js_secrets.py" ]; then
        log_info "Scanning JavaScript bundles & inline scripts for leaked secrets & API keys (concurrency: $THREADS)..."
        local verify_flag=""
        if [ "$VERIFY_SECRETS" = "1" ] || [ "$VERIFY_SECRETS" = "true" ]; then
            verify_flag="--verify"
            log_info "Active secret verification enabled — confirming which matched credentials are live."
        fi
        python3 "$SCRIPT_DIR/js_secrets.py" "$output_dir/js_links" "$output_dir/js_findings.json" "$THREADS" $verify_flag 2>/dev/null || true
        
        if [ -s "$output_dir/js_findings.json" ]; then
            jq '.secrets // []' "$output_dir/js_findings.json" > "$output_dir/all_secrets.json"
            
            # Combine JS endpoints and crawled endpoints into unified all_endpoints.json
            local js_endpoints
            js_endpoints=$(jq '.endpoints // []' "$output_dir/js_findings.json" 2>/dev/null || echo "[]")
            if [ -s "$output_dir/katana_all" ]; then
                local crawl_endpoints
                crawl_endpoints=$(head -n 2000 "$output_dir/katana_all" | jq -R '{url: ., path: (split("?")[0] | sub("^https?://[^/]+"; "")), source: "crawler"}' 2>/dev/null | jq -s . 2>/dev/null || echo "[]")
                jq -n --argjson js "$js_endpoints" --argjson crawl "$crawl_endpoints" '$js + $crawl | unique_by(.url)' > "$output_dir/all_endpoints.json" 2>/dev/null || echo "$js_endpoints" > "$output_dir/all_endpoints.json"
            else
                echo "$js_endpoints" > "$output_dir/all_endpoints.json"
            fi
            
            local sec_count=$(jq '. | length' "$output_dir/all_secrets.json" 2>/dev/null || echo 0)
            if [ "$sec_count" -gt 0 ]; then
                log_info "🚨 Discovered $sec_count secrets in JS files & inline scripts!"
                send_telegram_notification "🔑 <b>High-Signal Secrets Found in JS Analysis</b> for <code>$domain</code>
• Total Secrets: <b>$sec_count</b>"
            fi

            # Feed discovered JS endpoints back into crawl list for deeper analysis & exposure scanning
            local ep_count=$(jq '. | length' "$output_dir/all_endpoints.json" 2>/dev/null || echo 0)
            if [ "$ep_count" -gt 0 ]; then
                log_info "Feeding $ep_count extracted JS endpoints back into crawl list..."
                jq -r '.[].url // empty' "$output_dir/all_endpoints.json" 2>/dev/null | grep -Ei '^https?://' >> "$output_dir/katana_all" || true
                
                # Re-deduplicate
                if command -v uro >/dev/null 2>&1; then
                    uro -i "$output_dir/katana_all" -o "$output_dir/katana_all.tmp" 2>/dev/null && mv "$output_dir/katana_all.tmp" "$output_dir/katana_all"
                else
                    sort -u "$output_dir/katana_all" -o "$output_dir/katana_all"
                fi
                
                # Re-extract parameterized endpoints
                grep -Ei '\?.+=' "$output_dir/katana_all" | sort -u > "$output_dir/params"
            fi

            # Sync JS findings and endpoints to SQLite DB
            update_js_results "$domain"
        fi
    fi
}

# ==============================================================================
# PHASE 5: Directory & Sensitive Content / Backup Exposure Discovery
# ==============================================================================
run_content_discovery() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    log_phase "Phase 5: Content, Directory & Sensitive Exposure Discovery"

    if [ ! -s "$output_dir/live_hosts" ]; then
        return
    fi

    mkdir -p "$output_dir/fuzz"

    local sensitive_paths="/.env,/.git/HEAD,/swagger.json,/api-docs,/graphql,/backup.sql,/config.php.bak"
    local live_count=$(count_lines "$output_dir/live_hosts")
    log_info "Scanning exposure across $live_count live host(s) in parallel with httpx (threads: $THREADS)..."

    local exposure_raw="$output_dir/fuzz/httpx_exposure.json"
    timeout 120 httpx -list "$output_dir/live_hosts" \
        -path "$sensitive_paths" \
        -mc 200 \
        -silent \
        -nc \
        -t "$THREADS" \
        -timeout 5 \
        -json \
        -disable-update-check \
        -o "$exposure_raw" >/dev/null 2>&1 || true

    local cur_findings="[]"
    if [ -s "$output_dir/exposure_findings.json" ]; then
        cur_findings=$(cat "$output_dir/exposure_findings.json")
    fi

    if [ -s "$exposure_raw" ]; then
        while read -r line; do
            [ -z "$line" ] && continue
            local exp_url=$(echo "$line" | jq -r '.url // empty')
            [ -z "$exp_url" ] && continue

            local path_matched=$(echo "$exp_url" | sed -E 's|^https?://[^/]+||')
            log_info "🚨 Found sensitive file exposure: $exp_url (HTTP 200)"

            local f_item=$(jq -n \
                --arg title "Exposed Sensitive File: $path_matched" \
                --arg url "$exp_url" \
                --arg tool "exposure_scanner" \
                --arg sev "high" \
                --arg vt "exposure" \
                --arg desc "Sensitive configuration or backup file accessible publicly" \
                '{title: $title, url: $url, tool: $tool, severity: $sev, vuln_type: $vt, description: $desc}')

            cur_findings=$(echo "$cur_findings" | jq --argjson item "$f_item" '. += [$item]')

            send_telegram_notification "⚠️ <b>Sensitive File Exposure Found!</b>
• URL: <code>$exp_url</code> (HTTP 200)"
        done < "$exposure_raw"
    fi

    echo "$cur_findings" > "$output_dir/exposure_findings.json"
}

# ==============================================================================
# PHASE 6: Vulnerability & DAST Assessment
# ==============================================================================
run_nuclei() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    if [ ! -s "$output_dir/live_hosts" ]; then
        log_info "No live hosts for vulnerability scanning. Skipping Nuclei."
        return
    fi

    log_phase "Phase 6: Vulnerability & DAST Scanning (Nuclei + Dalfox)"
    local host_count=$(count_lines "$output_dir/live_hosts")
    log_info "Running Nuclei against $host_count targets..."

    # 1. Nuclei scanning
    timeout 600 nuclei -list "$output_dir/live_hosts" \
        -silent \
        -disable-update-check \
        -c "$THREADS" \
        -bulk-size "$THREADS" \
        -tags cve,exposure,misconfiguration,takeover,default-login,oast \
        -severity critical,high,medium,low \
        -json-export "$output_dir/nuclei.json" > /dev/null 2>&1 || touch "$output_dir/nuclei.json"

    # Process Nuclei findings into standardized JSON
    local all_findings="[]"
    if [ -s "$output_dir/nuclei.json" ]; then
        while read -r nline; do
            [ -z "$nline" ] && continue
            local title=$(echo "$nline" | jq -r '.info.name // "Untitled Nuclei Finding"')
            local sev=$(echo "$nline" | jq -r '.info.severity // "info"')
            local url=$(echo "$nline" | jq -r '.["matched-at"] // .host // ""')
            local desc=$(echo "$nline" | jq -r '.info.description // ""')
            local cve=$(echo "$nline" | jq -r '.info.classification["cve-id"][0] // ""')
            local evidence=$(echo "$nline" | jq -r '.extracted-results[0] // ""')

            local item=$(jq -n \
                --arg title "$title" \
                --arg sev "$sev" \
                --arg url "$url" \
                --arg desc "$desc" \
                --arg cve "$cve" \
                --arg ev "$evidence" \
                --arg tool "nuclei" \
                --arg vt "vulnerability" \
                '{title: $title, severity: $sev, url: $url, description: $desc, cve: $cve, evidence: $ev, tool: $tool, vuln_type: $vt}')

            all_findings=$(echo "$all_findings" | jq --argjson i "$item" '. += [$i]')
        done < "$output_dir/nuclei.json"
    fi

    # Merge exposure findings if present
    if [ -s "$output_dir/exposure_findings.json" ]; then
        all_findings=$(jq -s '.[0] + .[1]' <(echo "$all_findings") "$output_dir/exposure_findings.json")
    fi

    echo "$all_findings" > "$output_dir/all_findings.json"
    local vuln_count=$(jq '. | length' "$output_dir/all_findings.json" 2>/dev/null || echo 0)
    log_info "Vulnerability scan completed. Found $vuln_count findings."
}

# ==============================================================================
# Master Workflows
# ==============================================================================
run_info_gathering() {
    local domain=$1
    local start_time=$(date +%s)
    log_phase "Starting Targeted Information Gathering Workflow"
    log_info "Target: $domain"
    local output_dir="$TARGETS_DIR/$domain"
    mkdir -p "$output_dir"

    run_subdomain_enum "$domain"
    
    local sub_count=$(count_lines "$output_dir/subdomains")
    send_telegram_notification "✅ <b>Phase 1: Subdomain Discovery Done</b> for <code>$domain</code> (<b>$sub_count</b> subdomains discovered)"

    run_httpx "$domain"
    insert_company_and_domains "$domain"
    update_httpx_results "$domain"

    local live_count=$(count_lines "$output_dir/live_hosts")
    send_telegram_notification "✅ <b>Phase 2: Live HTTP Probing Done</b> for <code>$domain</code> (<b>$live_count</b> active hosts saved)"

    # Execute Phase 3 and Phase 4 concurrently in parallel
    log_info "⚡ Running Phase 3 (Port Scanning) and Phase 4 (Deep Web Crawling & JS Analysis) in parallel..."
    (
        run_naabu "$domain"
        update_port_scan_results "$domain"
        update_network_services_results "$domain"
    ) &
    local pid_phase3=$!

    (
        run_katana "$domain"
        update_endpoints_results "$domain"
        update_secrets_results "$domain"
        update_js_results "$domain"
    ) &
    local pid_phase4=$!

    wait $pid_phase3 $pid_phase4 2>/dev/null

    local duration=$(( $(date +%s) - start_time ))
    log_phase "Information Gathering Workflow Completed in $duration seconds."
    send_telegram_notification "🏁 <b>Info-Gathering Completed</b> for <code>$domain</code> in <b>$duration</b>s."
}

run_web_recon() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    mkdir -p "$output_dir"

    run_subdomain_enum "$domain"
    run_httpx "$domain"
    insert_company_and_domains "$domain"
    update_httpx_results "$domain"
    run_katana "$domain"
    update_endpoints_results "$domain"
    update_secrets_results "$domain"
    update_js_results "$domain"
    run_content_discovery "$domain"
    run_nuclei "$domain"
    update_findings_results "$domain"
}

run_network_recon() {
    local target=$1
    local output_dir="$TARGETS_DIR/$target"
    mkdir -p "$output_dir"

    echo "$target" > "$output_dir/ips"
    run_naabu "$target"
    update_port_scan_results "$target"
    update_network_services_results "$target"
}

# ==============================================================================
# DAG Phase Runner — each node of the task dependency graph is one phase.
# Emits a single machine-readable result line the runner forwards to the
# backend, where trigger rules decide which child phases to enqueue.
# ==============================================================================
emit_result() {
    # $1 = compact JSON object describing this phase's outcome
    printf '##CHACK_RESULT## %s\n' "$1"
}

run_phase() {
    local phase=$1
    local domain=$2
    local output_dir="$TARGETS_DIR/$domain"
    mkdir -p "$output_dir"

    case "$phase" in
        subdomain_enum)
            run_subdomain_enum "$domain"
            emit_result "{\"job_type\":\"subdomain_enum\",\"subdomains\":$(count_lines "$output_dir/subdomains")}"
            ;;
        httpx|httpx_fingerprint)
            run_httpx "$domain"
            insert_company_and_domains "$domain"
            update_httpx_results "$domain"
            emit_result "{\"job_type\":\"$phase\",\"live_hosts\":$(count_lines "$output_dir/live_hosts")}"
            ;;
        naabu)
            run_naabu "$domain"
            update_port_scan_results "$domain"
            update_network_services_results "$domain"
            local ports_csv
            ports_csv=$(awk -F: 'NF>1{print $2}' "$output_dir/ports" 2>/dev/null | grep -E '^[0-9]+$' | sort -un | paste -sd, -)
            emit_result "{\"job_type\":\"naabu\",\"open_ports\":[${ports_csv}],\"ports_count\":$(count_lines "$output_dir/ports")}"
            ;;
        katana)
            run_katana "$domain"
            update_endpoints_results "$domain"
            update_secrets_results "$domain"
            update_js_results "$domain"
            local js_count
            js_count=$(jq 'length' "$output_dir/js_findings.json" 2>/dev/null || echo 0)
            emit_result "{\"job_type\":\"katana\",\"endpoints\":$(count_lines "$output_dir/katana_raw"),\"js_files\":${js_count:-0}}"
            ;;
        nuclei)
            run_nuclei "$domain"
            update_findings_results "$domain"
            local find_count
            find_count=$(jq 'length' "$output_dir/all_findings.json" 2>/dev/null || echo 0)
            emit_result "{\"job_type\":\"nuclei\",\"findings\":${find_count:-0}}"
            ;;
        content_discovery)
            run_content_discovery "$domain"
            emit_result "{\"job_type\":\"content_discovery\"}"
            ;;
        *)
            log_error "Unknown phase: $phase"
            return 1
            ;;
    esac
}

recon() {
    local domain=$1
    local start_time=$(date +%s)
    log_phase "Starting Full Reconnaissance & DAST Pipeline"
    log_info "Target: $domain"
    local output_dir="$TARGETS_DIR/$domain"
    mkdir -p "$output_dir"

    # Phase 1
    if ! run_subdomain_enum "$domain"; then
        log_error "Subdomain enumeration failed"
    fi
    
    local sub_count=$(count_lines "$output_dir/subdomains")
    send_telegram_notification "✅ <b>Phase 1: Subdomain Enumeration Completed</b> for <code>$domain</code>
• Total subdomains discovered: <b>$sub_count</b>"

    # Phase 2
    if ! run_httpx "$domain"; then
        log_error "HTTPX scan failed"
    fi
    insert_company_and_domains "$domain"
    update_httpx_results "$domain"

    local live_count=$(count_lines "$output_dir/live_hosts")
    send_telegram_notification "✅ <b>Phase 2: Live HTTP Resolution Completed</b> for <code>$domain</code>
• Active web endpoints saved: <b>$live_count</b>"

    # Execute Phase 3 (Port Scanning) and Phase 4 (Web Crawling & JS Analysis) in parallel
    log_info "⚡ Running Phase 3 (Port Scanning) and Phase 4 (Web Crawling & JS Secret Analysis) in parallel..."
    (
        if run_naabu "$domain"; then
            update_port_scan_results "$domain"
            update_network_services_results "$domain"
            local port_count=$(count_lines "$output_dir/ports")
            send_telegram_notification "✅ <b>Phase 3: Port Scan Completed</b> for <code>$domain</code>
• Open ports: <b>$port_count</b>"
        else
            log_error "Port scanning failed"
        fi
    ) &
    local pid_phase3=$!

    (
        if run_katana "$domain"; then
            update_endpoints_results "$domain"
            update_secrets_results "$domain"
            update_js_results "$domain"
        else
            log_error "Katana crawling failed"
        fi
    ) &
    local pid_phase4=$!

    wait $pid_phase3 $pid_phase4 2>/dev/null

    # Phase 5
    run_content_discovery "$domain"

    # Phase 6
    run_nuclei "$domain"
    update_findings_results "$domain"

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_phase "Recon Pipeline Completed"
    log_info "Total execution time: $duration seconds"
    log_info "Results saved in $TARGETS_DIR/$domain"

    send_telegram_notification "🏁 <b>Full Recon Completed</b> for <code>$domain</code>
• Duration: <b>$duration</b>s
• All findings, endpoints, and secrets synchronized."
}

# ==========================================
# Target Data Synchronization (Cloudflare D1 & SQLite)
# ==========================================

sync_target_data() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    if [ ! -d "$output_dir" ]; then
        log_warn "Target directory does not exist: $output_dir"
        return 1
    fi

    log_phase "Syncing target '$domain' to Cloudflare D1 & local SQLite..."
    insert_company_and_domains "$domain"
    update_httpx_results "$domain"
    update_port_scan_results "$domain"
    update_network_services_results "$domain"
    update_endpoints_results "$domain"
    update_secrets_results "$domain"
    update_js_results "$domain"
    update_findings_results "$domain"
    log_info "Synchronization completed for '$domain'."
}

sync_all_targets() {
    log_phase "Synchronizing all targets in $TARGETS_DIR..."
    local count=0
    for t_dir in "$TARGETS_DIR"/*; do
        if [ -d "$t_dir" ]; then
            local dom
            dom=$(basename "$t_dir")
            sync_target_data "$dom"
            ((count++))
        fi
    done
    log_info "Completed synchronization for $count target(s)."
}

# ==========================================
# Terminal User Interface (TUI) Components
# ==========================================

TUI_BOLD="\033[1m"
TUI_DIM="\033[2m"
TUI_ITALIC="\033[3m"
TUI_UNDERLINE="\033[4m"
TUI_RESET="\033[0m"

TUI_RED="\033[31m"
TUI_GREEN="\033[32m"
TUI_YELLOW="\033[33m"
TUI_BLUE="\033[34m"
TUI_MAGENTA="\033[35m"
TUI_CYAN="\033[36m"
TUI_WHITE="\033[37m"

TUI_BG_BLUE="\033[44m"
TUI_BG_DARK="\033[48;5;236m"

tui_pause() {
    echo ""
    echo -e -n "  ${TUI_DIM}Press ${TUI_BOLD}[Enter]${TUI_RESET}${TUI_DIM} to return to menu...${TUI_RESET}"
    read -r
}

tui_input() {
    local prompt="$1"
    local default_val="$2"
    local var_name="$3"
    local input_val=""
    if [ -n "$default_val" ]; then
        echo -e -n "  ${TUI_BOLD}${prompt}${TUI_RESET} [${TUI_CYAN}${default_val}${TUI_RESET}]: "
    else
        echo -e -n "  ${TUI_BOLD}${prompt}${TUI_RESET}: "
    fi
    read -r input_val
    if [ -z "$input_val" ]; then
        input_val="$default_val"
    fi
    eval "$var_name=\"\$input_val\""
}

read_menu_key() {
    local __ret_var="$1"
    local key=""
    local res=""
    local input_fd=""

    if [ ! -t 0 ] && [ -t 1 ] && [ -c /dev/tty ] && [ -r /dev/tty ]; then
        input_fd="/dev/tty"
    fi

    if [ -n "$input_fd" ]; then
        if ! IFS= read -rsn1 key < "$input_fd" 2>/dev/null; then
            res="EOF"
        fi
    else
        if ! IFS= read -rsn1 key 2>/dev/null; then
            res="EOF"
        fi
    fi

    if [ -z "$res" ]; then
        if [[ "$key" == $'\x1b' ]]; then
            local key2=""
            if [ -n "$input_fd" ]; then
                read -rsn2 -t 0.04 key2 < "$input_fd" 2>/dev/null
            else
                read -rsn2 -t 0.04 key2 2>/dev/null
            fi
            key+="$key2"

            if [[ "$key2" =~ ^\[[0-9] ]]; then
                local extra=""
                if [ -n "$input_fd" ]; then
                    read -rsn1 -t 0.01 extra < "$input_fd" 2>/dev/null
                else
                    read -rsn1 -t 0.01 extra 2>/dev/null
                fi
                key+="$extra"
            fi
        fi

        case "$key" in
            $'\x1b[A'|$'\x1bOA') res="UP" ;;
            $'\x1b[B'|$'\x1bOB') res="DOWN" ;;
            $'\x1b[C'|$'\x1bOC') res="RIGHT" ;;
            $'\x1b[D'|$'\x1bOD') res="LEFT" ;;
            ""|$'\x0a') res="ENTER" ;;
            $'\x20') res="SPACE" ;;
            $'\x7f'|$'\x08') res="BACKSPACE" ;;
            $'\x1b') res="ESC" ;;
            *) res="$key" ;;
        esac
    fi

    if [ -n "$__ret_var" ]; then
        printf -v "$__ret_var" "%s" "$res"
    else
        echo "$res"
    fi
    return 0
}

_DB_SUMMARY_CACHE=""
_DB_SUMMARY_CACHE_TIME=0

get_cached_db_summary() {
    local now
    now=$(date +%s)
    if [ -n "$_DB_SUMMARY_CACHE" ] && [ $((now - _DB_SUMMARY_CACHE_TIME)) -lt 4 ]; then
        printf "%s" "$_DB_SUMMARY_CACHE"
        return 0
    fi
    _DB_SUMMARY_CACHE=$(python3 "$SCRIPT_DIR/db_sqlite.py" summary 2>/dev/null)
    _DB_SUMMARY_CACHE_TIME=$now
    printf "%s" "$_DB_SUMMARY_CACHE"
}

tui_select_menu() {
    local header_func="$1"
    local default_sel="${2:-0}"
    shift 2
    local -n _keys=$1
    local -n _icons=$2
    local -n _titles=$3
    local -n _descs=$4
    local count=${#_titles[@]}
    local selected=$default_sel
    if [ $selected -ge $count ]; then selected=0; fi

    # Fallback to simple input if not a tty
    if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        $header_func
        for ((i=0; i<count; i++)); do
            printf "  [%2s] %b %-32s %s\n" "${_keys[i]}" "${_icons[i]}" "${_titles[i]}" "${_descs[i]}"
        done
        local fallback_choice=""
        tui_input "Select option" "${_keys[0]}" "fallback_choice"
        SELECTED_CHOICE="$fallback_choice"
        SELECTED_INDEX=0
        return 0
    fi

    tput civis 2>/dev/null
    trap 'tput cnorm 2>/dev/null' RETURN INT TERM

    local need_full_draw=1

    while true; do
        if [ $need_full_draw -eq 1 ]; then
            $header_func
            echo -e "  ${TUI_DIM}Use ${TUI_BOLD}[↑/↓]${TUI_RESET}${TUI_DIM} or ${TUI_BOLD}[j/k]${TUI_RESET}${TUI_DIM} to navigate, ${TUI_BOLD}[Enter]${TUI_RESET}${TUI_DIM} to select, ${TUI_BOLD}[0-9]${TUI_RESET}${TUI_DIM} for shortcuts, ${TUI_BOLD}[q]${TUI_RESET}${TUI_DIM} to exit.${TUI_RESET}"
            echo ""
            need_full_draw=0
        else
            # Reposition cursor back up across all menu items and trailing blank line
            printf "\033[%dA" "$((count + 1))"
        fi

        for ((i=0; i<count; i++)); do
            local k="${_keys[i]}"
            local ic="${_icons[i]}"
            local tit="${_titles[i]}"
            local dsc="${_descs[i]}"

            if [ $i -eq $selected ]; then
                printf "\r\033[2K  ${TUI_CYAN}${TUI_BOLD}❯ [%2s] %b %-30b ${TUI_RESET}${TUI_CYAN}%s${TUI_RESET}\n" "$k" "$ic" "${TUI_BOLD}${tit}${TUI_RESET}" "$dsc"
            else
                printf "\r\033[2K    ${TUI_DIM}[%2s]${TUI_RESET} %b %-30b ${TUI_DIM}%s${TUI_RESET}\n" "$k" "$ic" "${TUI_WHITE}${tit}${TUI_RESET}" "$dsc"
            fi
        done
        printf "\r\033[2K\n"

        local k_in=""
        read_menu_key k_in
        if [ "$k_in" = "EOF" ]; then
            SELECTED_CHOICE="0"
            SELECTED_INDEX=$((count - 1))
            tput cnorm 2>/dev/null
            return 0
        fi

        case "$k_in" in
            UP|k|K)
                ((selected--))
                if [ $selected -lt 0 ]; then selected=$((count - 1)); fi
                ;;
            DOWN|j|J)
                ((selected++))
                if [ $selected -ge $count ]; then selected=0; fi
                ;;
            ENTER|SPACE)
                tput cnorm 2>/dev/null
                SELECTED_CHOICE="${_keys[selected]}"
                SELECTED_INDEX=$selected
                return 0
                ;;
            q|Q|ESC)
                tput cnorm 2>/dev/null
                SELECTED_CHOICE="0"
                SELECTED_INDEX=$((count - 1))
                return 0
                ;;
            r|R|$'\x0c')
                need_full_draw=1
                ;;
            *)
                # Direct key match
                for ((i=0; i<count; i++)); do
                    if [ "${_keys[i]}" = "$k_in" ]; then
                        selected=$i
                        tput cnorm 2>/dev/null
                        SELECTED_CHOICE="${_keys[i]}"
                        SELECTED_INDEX=$i
                        return 0
                    fi
                done
                ;;
        esac
    done
}

tui_banner() {
    clear
    echo -e "${TUI_CYAN}${TUI_BOLD}"
    cat << "EOF"
  ██████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
 ██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝
 ██║     ███████║███████║██║     █████╔╝ 
 ██║     ██╔══██║██╔══██║██║     ██╔═██╗ 
 ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
EOF
    echo -e "${TUI_MAGENTA}${TUI_BOLD}  Reconnaissance & Vulnerability Assessment Platform${TUI_RESET}"
    echo -e "${TUI_BLUE}  ─────────────────────────────────────────────────────────────${TUI_RESET}"

    # Status Bar
    local be_status="${TUI_RED}Disconnected${TUI_RESET}"
    if [ -n "$BACKEND_URL" ]; then
        be_status="${TUI_GREEN}$BACKEND_URL${TUI_RESET}"
    fi
    local runner_disp="${TUI_YELLOW}${RUNNER_NAME:-Default}${TUI_RESET}"

    local db_stats
    db_stats=$(get_cached_db_summary)
    local dom_count="0"
    local comp_count="0"
    local job_count="0"
    if [ -n "$db_stats" ]; then
        read -r dom_count comp_count job_count < <(echo "$db_stats" | jq -r '[.domains // 0, .companies // 0, .jobs // 0] | @tsv' 2>/dev/null || echo "0 0 0")
    fi

    echo -e "  ${TUI_BOLD}Runner:${TUI_RESET} $runner_disp  ${TUI_BOLD}|  Backend:${TUI_RESET} $be_status"
    echo -e "  ${TUI_BOLD}Database:${TUI_RESET} ${TUI_CYAN}$comp_count${TUI_RESET} Targets · ${TUI_CYAN}$dom_count${TUI_RESET} Domains · ${TUI_CYAN}$job_count${TUI_RESET} Jobs"
    echo -e "${TUI_BLUE}  ─────────────────────────────────────────────────────────────${TUI_RESET}"
    echo ""
}

tui_section_header() {
    local title="$1"
    echo -e "  ${TUI_BOLD}${TUI_YELLOW}▶ ${title}${TUI_RESET}"
    echo -e "  ${TUI_DIM}─────────────────────────────────────────────────────────────${TUI_RESET}"
}

tui_tool_diagnostics() {
    tui_banner
    tui_section_header "Tool Diagnostics & Environment Status"
    echo ""

    # Go Compiler Check
    if command -v go >/dev/null 2>&1; then
        local go_ver
        go_ver=$(go version | awk '{print $3}')
        echo -e "  ${TUI_BOLD}Go Environment:${TUI_RESET}       ${TUI_GREEN}✔ Installed${TUI_RESET} (${TUI_CYAN}$go_ver${TUI_RESET})"
    else
        echo -e "  ${TUI_BOLD}Go Environment:${TUI_RESET}       ${TUI_RED}✖ Not Found (Go >= 1.23 required)${TUI_RESET}"
    fi

    # System Dependencies
    echo ""
    echo -e "  ${TUI_BOLD}System Dependencies:${TUI_RESET}"
    local system_tools=("jq" "curl" "whois" "python3" "nmap")
    for st in "${system_tools[@]}"; do
        if command -v "$st" >/dev/null 2>&1; then
            printf "    ${TUI_GREEN}✔${TUI_RESET} %-16s ${TUI_DIM}%s${TUI_RESET}\n" "$st" "$(which "$st")"
        else
            printf "    ${TUI_RED}✖${TUI_RESET} %-16s ${TUI_RED}Missing${TUI_RESET}\n" "$st"
        fi
    done

    # Required Go Tools
    echo ""
    echo -e "  ${TUI_BOLD}Required Recon Tools (Phases 1-6):${TUI_RESET}"
    local missing_req=0
    for gt in "${REQUIRED_GO_TOOLS[@]}"; do
        if command -v "$gt" >/dev/null 2>&1; then
            printf "    ${TUI_GREEN}✔${TUI_RESET} %-16s ${TUI_DIM}%s${TUI_RESET}\n" "$gt" "$(which "$gt")"
        else
            printf "    ${TUI_RED}✖${TUI_RESET} %-16s ${TUI_RED}Missing${TUI_RESET}\n" "$gt"
            ((missing_req++))
        fi
    done

    # Optional Tools
    echo ""
    echo -e "  ${TUI_BOLD}Optional Analysis Tools:${TUI_RESET}"
    for ot in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$ot" >/dev/null 2>&1; then
            printf "    ${TUI_GREEN}✔${TUI_RESET} %-16s ${TUI_DIM}%s${TUI_RESET}\n" "$ot" "$(which "$ot")"
        else
            printf "    ${TUI_YELLOW}○${TUI_RESET} %-16s ${TUI_DIM}Optional / Not Found${TUI_RESET}\n" "$ot"
        fi
    done

    echo ""
    if [ $missing_req -gt 0 ]; then
        echo -e "  ${TUI_YELLOW}⚠ $missing_req required tool(s) are missing.${TUI_RESET}"
        local do_install
        tui_input "Would you like to install missing tools now? (y/N)" "N" "do_install"
        if [[ "$do_install" =~ ^[Yy]$ ]]; then
            echo ""
            log_info "Starting automatic tool installation..."
            check_requirements
        fi
    else
        echo -e "  ${TUI_GREEN}✔ All core reconnaissance dependencies are installed and ready!${TUI_RESET}"
    fi

    tui_pause
}

tui_db_explorer() {
    local db_keys=("1" "2" "3" "4" "5" "6" "7" "8" "9" "0")
    local db_icons=("🏢" "📋" "🔑" "🛡️ " "🔌" "📜" "☁️ " "🔄" "🔍" "⬅️ ")
    local db_titles=(
        "List Targets & Companies"
        "Generate Domain Report"
        "View Discovered Secrets"
        "View Discovered Vulnerabilities"
        "View Open Ports & Services"
        "View Recent Scan Jobs & Logs"
        "Sync Targets to Cloudflare & SQLite"
        "Initialize / Reset SQLite Database"
        "Search & Analytics"
        "Back to Main Menu"
    )
    local db_descs=(
        "View all registered companies and domain counts"
        "Full executive summary (vulns, secrets, endpoints)"
        "List API keys and leaked secrets from JS bundles"
        "List Nuclei findings for a domain"
        "List network audit findings"
        "Inspect background runner jobs and stdout"
        "Sync on-disk targets to Cloudflare D1 & local SQLite"
        "Re-run schema.sql on local SQLite"
        "Search hosts, services, tech, secrets, findings, risk"
        ""
    )

    tui_db_header() {
        tui_banner
        tui_section_header "Database & Findings Explorer"
        echo ""

        local stats_json
        stats_json=$(get_cached_db_summary)

        if [ -n "$stats_json" ]; then
            local comp_cnt dom_cnt find_cnt sec_cnt srv_cnt end_cnt job_cnt
            read -r comp_cnt dom_cnt find_cnt sec_cnt srv_cnt end_cnt job_cnt < <(echo "$stats_json" | jq -r '[.companies // 0, .domains // 0, .findings // 0, .secrets // 0, .services // 0, .endpoints // 0, .jobs // 0] | @tsv' 2>/dev/null || echo "0 0 0 0 0 0 0")

            echo -e "  ${TUI_BOLD}Overview Metrics:${TUI_RESET}"
            echo -e "    🏢 Companies/Targets: ${TUI_CYAN}$comp_cnt${TUI_RESET}   🌐 Subdomains: ${TUI_CYAN}$dom_cnt${TUI_RESET}   🛡️  Findings: ${TUI_CYAN}$find_cnt${TUI_RESET}"
            echo -e "    🔑 Leaked Secrets:   ${TUI_CYAN}$sec_cnt${TUI_RESET}   🔌 Services:   ${TUI_CYAN}$srv_cnt${TUI_RESET}   🔗 Endpoints: ${TUI_CYAN}$end_cnt${TUI_RESET}"
            echo -e "    📋 Scan Jobs:        ${TUI_CYAN}$job_cnt${TUI_RESET}"
            echo ""
        fi
    }

    local last_db_sel=0
    while true; do
        tui_select_menu tui_db_header "$last_db_sel" db_keys db_icons db_titles db_descs
        local db_choice="$SELECTED_CHOICE"
        last_db_sel="$SELECTED_INDEX"

        case "$db_choice" in
            1)
                tui_banner
                tui_section_header "Registered Targets / Companies"
                echo ""
                python3 "$SCRIPT_DIR/db_sqlite.py" targets | jq -r '.[] | "  🏢 \(.name) (\(.slug))\n     Domains: \(.domain_count) | Created: \(.created_at)\n"' 2>/dev/null || echo "  No targets found."
                tui_pause
                ;;
            2)
                tui_banner
                tui_section_header "Domain Recon Report"
                local rep_domain
                tui_input "Enter domain or company slug" "" "rep_domain"
                if [ -n "$rep_domain" ]; then
                    echo ""
                    python3 "$SCRIPT_DIR/db_sqlite.py" report "$rep_domain" | jq '.'
                fi
                tui_pause
                ;;
            3)
                tui_banner
                tui_section_header "Leaked Secrets & API Keys"
                local sec_domain
                tui_input "Enter domain or company slug" "" "sec_domain"
                if [ -n "$sec_domain" ]; then
                    echo ""
                    python3 "$SCRIPT_DIR/db_sqlite.py" secrets "$sec_domain" | jq '.'
                fi
                tui_pause
                ;;
            4)
                tui_banner
                tui_section_header "Discovered Vulnerabilities"
                local vuln_domain
                tui_input "Enter domain or company slug" "" "vuln_domain"
                if [ -n "$vuln_domain" ]; then
                    echo ""
                    python3 "$SCRIPT_DIR/db_sqlite.py" findings "$vuln_domain" | jq '.'
                fi
                tui_pause
                ;;
            5)
                tui_banner
                tui_section_header "Network Services & Open Ports"
                local srv_domain
                tui_input "Enter domain or company slug" "" "srv_domain"
                if [ -n "$srv_domain" ]; then
                    echo ""
                    python3 "$SCRIPT_DIR/db_sqlite.py" services "$srv_domain" | jq '.'
                fi
                tui_pause
                ;;
            6)
                tui_banner
                tui_section_header "Recent Scan Jobs"
                echo ""
                python3 "$SCRIPT_DIR/db_sqlite.py" jobs | jq -r '.[:10][] | "  📋 [\(.status)] \(.domain // "No domain")\n     ID: \(.id)\n     Command: \(.command)\n     Created: \(.created_at)\n"' 2>/dev/null || echo "  No jobs recorded."
                echo ""
                local view_job_id
                tui_input "Enter Job ID to view full stdout log (or leave blank)" "" "view_job_id"
                if [ -n "$view_job_id" ]; then
                    echo ""
                    echo -e "  ${TUI_BOLD}--- Log for Job $view_job_id ---${TUI_RESET}"
                    python3 "$SCRIPT_DIR/db_sqlite.py" job_log "$view_job_id"
                fi
                tui_pause
                ;;
            7)
                tui_banner
                tui_section_header "Synchronize Targets to Cloudflare & SQLite"
                echo ""
                echo -e "  This will parse on-disk scan data from ${TUI_CYAN}$TARGETS_DIR${TUI_RESET} and sync to Cloudflare D1 & SQLite."
                echo ""
                local sync_mode
                tui_input "Sync all targets or a specific domain? (all/<domain>)" "all" "sync_mode"
                if [ "$sync_mode" = "all" ] || [ -z "$sync_mode" ]; then
                    sync_all_targets
                else
                    sync_target_data "$sync_mode"
                fi
                tui_pause
                ;;
            8)
                tui_banner
                tui_section_header "Initialize SQLite Database"
                local confirm_init
                tui_input "Initialize local SQLite database with schema? (y/N)" "N" "confirm_init"
                if [[ "$confirm_init" =~ ^[Yy]$ ]]; then
                    python3 "$SCRIPT_DIR/db_sqlite.py" init
                fi
                tui_pause
                ;;
            9)
                tui_banner
                tui_section_header "Search & Analytics"
                echo -e "  Search across hosts, services, tech stack, exposed credentials, and findings."
                echo -e "  Kinds: ${TUI_CYAN}all${TUI_RESET} (default) | domain | service | tech | secret | finding | risk | asn"
                echo -e "  For ${TUI_CYAN}risk${TUI_RESET}, enter a minimum score as the term (e.g. term=10, kind=risk)."
                echo ""
                local search_term search_kind
                tui_input "Search term" "" "search_term"
                if [ -n "$search_term" ]; then
                    tui_input "Kind (blank = all)" "all" "search_kind"
                    [ -z "$search_kind" ] && search_kind="all"
                    echo ""
                    python3 "$SCRIPT_DIR/db_sqlite.py" search "$search_term" "$search_kind" | jq '.'
                fi
                tui_pause
                ;;
            0)
                break
                ;;
            *)
                ;;
        esac
    done
}

tui_target_management() {
    local ent_keys=("1" "2" "3" "4" "0")
    local ent_icons=("🏢" "👤" "👥" "📋" "⬅️ ")
    local ent_titles=(
        "Add Company Target"
        "Add Person Target"
        "Add User / Operator"
        "List Registered Targets"
        "Back to Main Menu"
    )
    local ent_descs=(
        "Create new company container in GraphQL/SQLite"
        "Register individual contact or employee"
        "Register operator with Telegram ID"
        "View all companies and domains"
        ""
    )

    tui_target_header() {
        tui_banner
        tui_section_header "Target & Entity Management"
        echo ""
    }

    local last_ent_sel=0
    while true; do
        tui_select_menu tui_target_header "$last_ent_sel" ent_keys ent_icons ent_titles ent_descs
        local ent_choice="$SELECTED_CHOICE"
        last_ent_sel="$SELECTED_INDEX"

        case "$ent_choice" in
            1)
                tui_banner
                tui_section_header "Add Company Target"
                local comp_name comp_slug comp_desc
                tui_input "Company Name" "" "comp_name"
                if [ -z "$comp_name" ]; then
                    echo -e "  ${TUI_RED}Company name cannot be empty.${TUI_RESET}"
                    tui_pause
                    continue
                fi
                local auto_slug
                auto_slug=$(echo "$comp_name" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g')
                tui_input "Company Slug" "$auto_slug" "comp_slug"
                tui_input "Description" "Added via TUI" "comp_desc"
                echo ""
                db_add_company "$comp_name" "$comp_slug" "$comp_desc"
                tui_pause
                ;;
            2)
                tui_banner
                tui_section_header "Add Person Target"
                local p_first p_last p_comp
                tui_input "First Name" "" "p_first"
                tui_input "Last Name" "" "p_last"
                tui_input "Company ID (leave blank for Default Company)" "" "p_comp"
                if [ -z "$p_comp" ]; then
                    local comp_res
                    if comp_res=$(execute_graphql "query { companies { id } }"); then
                        p_comp=$(echo "$comp_res" | jq -r '.data.companies[0].id // empty')
                    fi
                    if [ -z "$p_comp" ]; then
                        p_comp=$(db_add_company "Default Company" "default-company" "Default company for orphan targets")
                    fi
                fi
                echo ""
                db_add_person "$p_comp" "$p_first" "$p_last" "" "[]" "{}"
                tui_pause
                ;;
            3)
                tui_banner
                tui_section_header "Add User / Operator"
                local u_name u_num u_first u_last
                tui_input "Username" "" "u_name"
                if [ -z "$u_name" ]; then
                    echo -e "  ${TUI_RED}Username cannot be empty.${TUI_RESET}"
                    tui_pause
                    continue
                fi
                tui_input "Telegram Number ID" "" "u_num"
                tui_input "First Name" "" "u_first"
                tui_input "Last Name" "" "u_last"
                echo ""
                db_add_user "$u_name" "$u_num" "$u_first" "$u_last"
                tui_pause
                ;;
            4)
                tui_banner
                tui_section_header "Registered Targets"
                echo ""
                python3 "$SCRIPT_DIR/db_sqlite.py" targets | jq -r '.[] | "  🏢 \(.name) (\(.slug))\n     Domains: \(.domain_count) | Created: \(.created_at)\n"' 2>/dev/null || echo "  No targets found."
                tui_pause
                ;;
            0)
                break
                ;;
            *)
                ;;
        esac
    done
}

tui_view_config() {
    tui_banner
    tui_section_header "Environment & Configuration (.env)"
    echo ""

    echo -e "  ${TUI_BOLD}Backend Configuration:${TUI_RESET}"
    echo -e "    Backend URL:        ${TUI_CYAN}${BACKEND_URL:-Not set}${TUI_RESET}"
    echo -e "    Runner Name:        ${TUI_CYAN}${RUNNER_NAME:-Default}${TUI_RESET}"
    echo -e "    Local DB File:      ${TUI_CYAN}${SCRIPT_DIR}/local.db${TUI_RESET}"
    echo ""
    echo -e "  ${TUI_BOLD}Telegram Notification Configuration:${TUI_RESET}"
    if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
        local masked_tok="${TELEGRAM_BOT_TOKEN:0:8}******${TELEGRAM_BOT_TOKEN: -4}"
        echo -e "    Bot Token:          ${TUI_GREEN}Configured${TUI_RESET} (${TUI_DIM}$masked_tok${TUI_RESET})"
    else
        echo -e "    Bot Token:          ${TUI_YELLOW}Not configured${TUI_RESET}"
    fi
    echo -e "    Admin IDs:          ${TUI_CYAN}${ADMIN_IDS:-Not set}${TUI_RESET}"
    echo ""

    # Test backend ping
    if [ -n "$BACKEND_URL" ]; then
        echo -e "  ${TUI_BOLD}Testing Backend Connection...${TUI_RESET}"
        local be_ping
        be_ping=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$BACKEND_URL" 2>/dev/null)
        if [ "$be_ping" = "200" ] || [ "$be_ping" = "404" ] || [ "$be_ping" = "302" ]; then
            echo -e "    Backend Status:     ${TUI_GREEN}✔ Online${TUI_RESET} (HTTP $be_ping)"
        else
            echo -e "    Backend Status:     ${TUI_RED}✖ Unreachable / Failed${TUI_RESET} (HTTP $be_ping)"
        fi
    fi

    tui_pause
}

tui_daemon_runner() {
    tui_banner
    tui_section_header "cHack Scan Runner Daemon"
    echo ""
    echo -e "  ${TUI_BOLD}Backend Queue:${TUI_RESET}      ${TUI_CYAN}$BACKEND_URL/api/runner/next-job${TUI_RESET}"
    echo -e "  ${TUI_BOLD}Runner Name:${TUI_RESET}        ${TUI_YELLOW}$RUNNER_NAME${TUI_RESET}"
    echo -e "  ${TUI_BOLD}Polling Interval:${TUI_RESET}   ${TUI_DIM}5 seconds${TUI_RESET}"
    echo ""
    echo -e "  ${TUI_MAGENTA}Daemon is now running and waiting for scan jobs from Cloudflare queue.${TUI_RESET}"
    echo -e "  ${TUI_DIM}Press [Ctrl+C] at any time to stop the daemon and return to the TUI.${TUI_RESET}"
    echo -e "  ${TUI_BLUE}─────────────────────────────────────────────────────────────${TUI_RESET}"
    echo ""

    python3 "$SCRIPT_DIR/db_sqlite.py" init >/dev/null 2>&1
    local keep_running=true
    runner_start_heartbeat
    trap 'keep_running=false; runner_stop_heartbeat; log_info "\nDaemon stopped by user."; return' INT

    while [ "$keep_running" = true ]; do
        runner_poll_for_jobs
        sleep 5
    done
    runner_stop_heartbeat
    trap - INT
}

launch_tui() {
    # Verify prerequisites before entering TUI
    check_requirements >/dev/null 2>&1

    local menu_keys=("1" "2" "3" "4" "5" "6" "7" "8" "9" "10" "11" "0")
    local menu_icons=("🎯" "🔍" "🌐" "⚡" "📁" "🛡️ " "👥" "📊" "🤖" "🔧" "⚙️ " "🚪")
    local menu_titles=(
        "Full Reconnaissance Pipeline"
        "Information Gathering"
        "Web Recon & Crawling"
        "Network & Port Audit"
        "Content & Directory Fuzzing"
        "Vulnerability & DAST Scan"
        "Target & Entity Management"
        "Database & Findings Explorer"
        "Start Scan Runner Daemon"
        "Tool Diagnostics & Setup"
        "View Configuration & Settings"
        "Exit cHack"
    )
    local menu_descs=(
        "Phases 1-6: Subdomains, Probing, Ports, Crawling, Fuzz, Nuclei"
        "Phases 1-4: Passive DNS, Subdomains, Live Probe, Archives"
        "Katana, Hakrawler, Waymore, JS Secret Analysis"
        "Naabu & Nmap Port/Service discovery on Target/CIDR"
        "Feroxbuster, Dirsearch, Exposed Backup Files"
        "Nuclei v3 automated template scanning"
        "Manage Companies, People, and Users in DB"
        "Browse targets, subdomains, vulns, leaked secrets, and jobs"
        "Poll central Cloudflare backend queue for tasks"
        "Check and install missing Go and system tools"
        "Inspect .env variables and backend connectivity"
        "Quit to shell"
    )

    tui_main_header() {
        tui_banner
        tui_section_header "Main Control Menu"
        echo ""
    }

    local last_main_sel=0
    while true; do
        tui_select_menu tui_main_header "$last_main_sel" menu_keys menu_icons menu_titles menu_descs
        local main_choice="$SELECTED_CHOICE"
        last_main_sel="$SELECTED_INDEX"

        case "$main_choice" in
            1)
                tui_banner
                tui_section_header "Full Reconnaissance Pipeline"
                echo ""
                local target_domain
                tui_input "Enter Target Domain (e.g. example.com)" "" "target_domain"
                if [ -n "$target_domain" ]; then
                    if ! [[ "$target_domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                        echo -e "  ${TUI_RED}Invalid domain format: $target_domain${TUI_RESET}"
                    else
                        local confirm_run
                        tui_input "Start Full Recon for $target_domain? (Y/n)" "Y" "confirm_run"
                        if [[ "$confirm_run" =~ ^[Yy]$ ]] || [ -z "$confirm_run" ]; then
                            echo ""
                            recon "$target_domain"
                        fi
                    fi
                fi
                tui_pause
                ;;
            2)
                tui_banner
                tui_section_header "Information Gathering (Phases 1-4)"
                echo ""
                local target_domain
                tui_input "Enter Target Domain" "" "target_domain"
                if [ -n "$target_domain" ]; then
                    echo ""
                    run_info_gathering "$target_domain"
                fi
                tui_pause
                ;;
            3)
                tui_banner
                tui_section_header "Web Recon & Crawling"
                echo ""
                local target_domain
                tui_input "Enter Target Domain / URL" "" "target_domain"
                if [ -n "$target_domain" ]; then
                    echo ""
                    run_web_recon "$target_domain"
                fi
                tui_pause
                ;;
            4)
                tui_banner
                tui_section_header "Network & Port Audit"
                echo ""
                local net_target
                tui_input "Enter Target Domain, IP or CIDR (e.g. 192.168.1.1/24)" "" "net_target"
                if [ -n "$net_target" ]; then
                    echo ""
                    run_network_recon "$net_target"
                fi
                tui_pause
                ;;
            5)
                tui_banner
                tui_section_header "Content & Directory Fuzzing"
                echo ""
                local fuzz_target
                tui_input "Enter Target Domain / URL" "" "fuzz_target"
                if [ -n "$fuzz_target" ]; then
                    echo ""
                    run_content_discovery "$fuzz_target"
                fi
                tui_pause
                ;;
            6)
                tui_banner
                tui_section_header "Nuclei Vulnerability Scan"
                echo ""
                local vuln_target
                tui_input "Enter Target Domain / Host" "" "vuln_target"
                if [ -n "$vuln_target" ]; then
                    echo ""
                    run_nuclei "$vuln_target"
                fi
                tui_pause
                ;;
            7)
                tui_target_management
                ;;
            8)
                tui_db_explorer
                ;;
            9)
                tui_daemon_runner
                ;;
            10)
                tui_tool_diagnostics
                ;;
            11)
                tui_view_config
                ;;
            0|q|Q|exit|quit)
                echo -e "\n  ${TUI_GREEN}Goodbye! Happy Hacking.${TUI_RESET}\n"
                exit 0
                ;;
            *)
                echo -e "  ${TUI_RED}Invalid option.${TUI_RESET}"
                sleep 1
                ;;
        esac
    done
}

show_usage() {
    echo "cHack Recon Platform (Imported from Reconner)"
    echo "Usage: $0 [options]"
    echo ""
    echo "Interactive Modes:"
    echo "  -i, --tui, --menu         Launch Interactive Terminal User Interface (TUI)"
    echo "  -D, --daemon              Start background scan runner daemon"
    echo ""
    echo "Direct Scan Workflows:"
    echo "  -d, --domain DOMAIN       Run full end-to-end recon & DAST scan"
    echo "  --info-gather DOMAIN      Run non-intrusive information gathering (Phases 1-4)"
    echo "  --web DOMAIN              Run web-focused reconnaissance and crawling"
    echo "  --network TARGET          Run network & port scan on IP / CIDR / domain"
    echo "  --fuzz DOMAIN             Run content & backup file discovery"
    echo "  --vuln DOMAIN             Run Nuclei & DAST vulnerability scanning"
    echo "  -t, --threads NUM         Set concurrency / worker threads (default: 50)"
    echo ""
    echo "Target & Entity Management:"
    echo "  --sync DOMAIN             Sync on-disk scan data to Cloudflare D1 & local SQLite"
    echo "  --sync-all                Sync all targets from disk to Cloudflare D1 & SQLite"
    echo "  -p, --person NAME         Add a person target (GraphQL API)"
    echo "  -c, --company NAME        Add a company target (GraphQL API)"
    echo "  -u, --user USERNAME       Add a new user (GraphQL API)"
    echo "  --number-id ID            Telegram number ID for the new user"
    echo "  --first-name NAME         First name for the new user"
    echo "  --last-name NAME          Last name for the new user"
    echo "  --sender-id ID            Telegram User ID of the command sender"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "If no options are provided in an interactive terminal, launches the TUI."
}

runner_send_log() {
    local job_id="$1"
    local log_data="$2"
    
    if [ -n "$BACKEND_URL" ]; then
        local payload
        payload=$(jq -n --arg id "$job_id" --arg log "$log_data" '{id: $id, log: $log}')
        curl -s -X POST "$BACKEND_URL/api/runner/log" \
            -H "Content-Type: application/json" \
            -d "$payload" >/dev/null 2>&1
    fi

    local log_b64
    log_b64=$(echo -n "$log_data" | base64 | tr -d '\n')
    python3 "$SCRIPT_DIR/db_sqlite.py" append_log "$job_id" "$log_b64" >/dev/null 2>&1
}

runner_update_status() {
    local job_id="$1"
    local status="$2"
    local result="$3"  # optional compact JSON emitted by the phase

    if [ -n "$BACKEND_URL" ]; then
        local payload
        if [ -n "$result" ]; then
            # --argjson so the result is sent as a JSON object, not a string;
            # fall back to a plain status payload if it isn't valid JSON.
            payload=$(jq -n --arg id "$job_id" --arg status "$status" --argjson result "$result" \
                '{id: $id, status: $status, result: $result}' 2>/dev/null) \
                || payload=$(jq -n --arg id "$job_id" --arg status "$status" '{id: $id, status: $status}')
        else
            payload=$(jq -n --arg id "$job_id" --arg status "$status" '{id: $id, status: $status}')
        fi
        curl -s -X POST "$BACKEND_URL/api/runner/status" \
            -H "Content-Type: application/json" \
            -d "$payload" >/dev/null 2>&1
    fi

    python3 "$SCRIPT_DIR/db_sqlite.py" update_status "$job_id" "$status" "$result" >/dev/null 2>&1
}

# Background keepalive: while the daemon is up (including during a long-running
# job that blocks the poll loop), ping the backend so this runner stays marked
# online and its in-flight job is not reclaimed and re-dispatched elsewhere.
HEARTBEAT_PID=""
runner_start_heartbeat() {
    [ -z "$BACKEND_URL" ] && return
    (
        while true; do
            curl -s "${BACKEND_URL}/api/runner/heartbeat?runner=${RUNNER_NAME}" >/dev/null 2>&1
            sleep 30
        done
    ) &
    HEARTBEAT_PID=$!
}
runner_stop_heartbeat() {
    if [ -n "$HEARTBEAT_PID" ]; then
        kill "$HEARTBEAT_PID" >/dev/null 2>&1
        wait "$HEARTBEAT_PID" 2>/dev/null
        HEARTBEAT_PID=""
    fi
}

runner_poll_for_jobs() {
    local url="${BACKEND_URL}/api/runner/next-job?runner=${RUNNER_NAME}"
    local res
    res=$(curl -s "$url")
    if [ -z "$res" ]; then
        return
    fi

    local job_id
    job_id=$(echo "$res" | jq -r '.job.id // empty')
    if [ -z "$job_id" ]; then
        return
    fi

    local command_str
    command_str=$(echo "$res" | jq -r '.job.command')
    local domain
    domain=$(echo "$res" | jq -r '.job.domain')

    log_info "🚀 [Job $job_id] Starting task for domain: $domain"
    log_info "   Command args: $command_str"

    local temp_job_file
    temp_job_file=$(mktemp "/tmp/temp_job_XXXXXX.json" 2>/dev/null || mktemp)
    echo "$res" | jq '.job' > "$temp_job_file"
    python3 "$SCRIPT_DIR/db_sqlite.py" save_job "$temp_job_file" >/dev/null 2>&1

    python3 "$SCRIPT_DIR/db_sqlite.py" update_status "$job_id" "running" >/dev/null 2>&1

    local out_file
    out_file=$(mktemp "/tmp/chack_out_XXXXXX" 2>/dev/null || mktemp)

    local log_line
    eval "\"$SCRIPT_DIR/cHack.sh\" $command_str" 2>&1 | while IFS= read -r log_line || [ -n "$log_line" ]; do
        echo "$log_line"
        printf '%s\n' "$log_line" >> "$out_file"
        runner_send_log "$job_id" "$log_line"$'\n'
    done

    local exit_code=${PIPESTATUS[0]}
    log_info "🏁 [Job $job_id] Process exited with code: $exit_code"

    # Extract the phase result line (last one wins) for DAG trigger evaluation.
    local result_json=""
    result_json=$(grep -a '##CHACK_RESULT##' "$out_file" 2>/dev/null | tail -n1 | sed 's/.*##CHACK_RESULT##[[:space:]]*//')
    rm -f "$out_file"

    local final_status="completed"
    if [ $exit_code -ne 0 ]; then
        final_status="failed"
    fi

    runner_update_status "$job_id" "$final_status" "$result_json"
}

main() {
    local DOMAIN=""
    local INFO_GATHER=""
    local WEB_TARGET=""
    local NET_TARGET=""
    local FUZZ_TARGET=""
    local VULN_TARGET=""
    local PHASE=""
    local PHASE_TARGET=""
    local PERSON=""
    local COMPANY=""
    local USERNAME=""
    local NUMBER_ID=""
    local FIRST_NAME=""
    local LAST_NAME=""
    local FORCE_TUI=false
    local FORCE_DAEMON=false
    local SYNC_TARGET=""
    local SYNC_ALL=false
    SENDER_ID=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -i|--tui|--interactive|--menu)
                FORCE_TUI=true
                shift
                ;;
            -D|--daemon)
                FORCE_DAEMON=true
                shift
                ;;
            -d|--domain)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                DOMAIN="$2"
                shift 2
                ;;
            -t|--threads)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                THREADS="$2"
                shift 2
                ;;
            --info-gather)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                INFO_GATHER="$2"
                shift 2
                ;;
            --sync)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                SYNC_TARGET="$2"
                shift 2
                ;;
            --sync-all)
                SYNC_ALL=true
                shift
                ;;
            --web)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                WEB_TARGET="$2"
                shift 2
                ;;
            --network)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                NET_TARGET="$2"
                shift 2
                ;;
            --fuzz)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                FUZZ_TARGET="$2"
                shift 2
                ;;
            --vuln)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                VULN_TARGET="$2"
                shift 2
                ;;
            --phase)
                if [ $# -lt 3 ]; then log_error "Option --phase requires <type> <domain>."; exit 1; fi
                PHASE="$2"
                PHASE_TARGET="$3"
                shift 3
                ;;
            -p|--person)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                PERSON="$2"
                shift 2
                ;;
            -c|--company)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                COMPANY="$2"
                shift 2
                ;;
            -u|--user)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                USERNAME="$2"
                shift 2
                ;;
            --number-id)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                NUMBER_ID="$2"
                shift 2
                ;;
            --first-name)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                FIRST_NAME="$2"
                shift 2
                ;;
            --last-name)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                LAST_NAME="$2"
                shift 2
                ;;
            --sender-id)
                if [ $# -lt 2 ]; then log_error "Option $1 requires an argument."; exit 1; fi
                SENDER_ID="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                if [ -z "$DOMAIN" ] && [ -z "$PERSON" ] && [ -z "$COMPANY" ] && [ -z "$USERNAME" ] && [[ ! "$1" =~ ^- ]]; then
                    DOMAIN="$1"
                    shift
                else
                    log_error "Unknown option: $1"
                    show_usage
                    exit 1
                fi
                ;;
        esac
    done

    # Run tool prerequisite checks
    if ! check_requirements; then
        log_error "Requirement checks failed. Exiting."
        exit 1
    fi

    # Target Sync Workflows
    if [ -n "$SYNC_TARGET" ]; then
        sync_target_data "$SYNC_TARGET"
        exit 0
    fi
    if [ "$SYNC_ALL" = true ]; then
        sync_all_targets
        exit 0
    fi

    # Explicit TUI Request
    if [ "$FORCE_TUI" = true ]; then
        launch_tui
        exit 0
    fi

    # Single DAG phase (dispatched by the backend dependency graph)
    if [ -n "$PHASE" ]; then
        run_phase "$PHASE" "$PHASE_TARGET"
        exit $?
    fi

    # Targeted Info Gathering
    if [ -n "$INFO_GATHER" ]; then
        run_info_gathering "$INFO_GATHER"
        exit 0
    fi

    # Web Recon
    if [ -n "$WEB_TARGET" ]; then
        run_web_recon "$WEB_TARGET"
        exit 0
    fi

    # Network Recon
    if [ -n "$NET_TARGET" ]; then
        run_network_recon "$NET_TARGET"
        exit 0
    fi

    # Content Fuzzing
    if [ -n "$FUZZ_TARGET" ]; then
        run_content_discovery "$FUZZ_TARGET"
        exit 0
    fi

    # Vulnerability Scan
    if [ -n "$VULN_TARGET" ]; then
        run_nuclei "$VULN_TARGET"
        exit 0
    fi

    # Full Recon
    if [ -n "$DOMAIN" ]; then
        if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log_error "Invalid domain format: $DOMAIN"
            exit 1
        fi
        recon "$DOMAIN"
        exit 0
    fi

    # Entity Creation
    if [ -n "$PERSON" ]; then
        log_info "Adding person to DB: $PERSON"
        local company_id=""
        local comp_q="query { companies { id } }"
        local comp_res
        if comp_res=$(execute_graphql "$comp_q"); then
            company_id=$(echo "$comp_res" | jq -r '.data.companies[0].id // empty')
        fi
        if [ -z "$company_id" ]; then
            company_id=$(db_add_company "Default Company" "default-company" "Default company for orphan targets")
        fi

        local first_name=$(echo "$PERSON" | cut -d ' ' -f 1)
        local last_name=$(echo "$PERSON" | cut -d ' ' -f 2-)
        if [ "$first_name" = "$last_name" ]; then last_name=""; fi
        db_add_person "$company_id" "$first_name" "$last_name" "" "[]" "{}"
        exit 0
    fi

    if [ -n "$COMPANY" ]; then
        log_info "Adding company to DB: $COMPANY"
        local slug=$(echo "$COMPANY" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g')
        db_add_company "$COMPANY" "$slug" "Added via CLI"
        exit 0
    fi

    if [ -n "$USERNAME" ]; then
        log_info "Adding user to DB: $USERNAME"
        db_add_user "$USERNAME" "$NUMBER_ID" "$FIRST_NAME" "$LAST_NAME"
        exit 0
    fi

    # If running interactively with no specific action specified, launch TUI
    if [ "$FORCE_DAEMON" != true ] && [ -t 0 ]; then
        launch_tui
        exit 0
    fi

    # Daemon Mode
    log_info "Starting cHack Daemon Runner (Polling $BACKEND_URL)..."
    log_info "Runner Name: $RUNNER_NAME"

    python3 "$SCRIPT_DIR/db_sqlite.py" init >/dev/null 2>&1
    runner_start_heartbeat
    trap 'runner_stop_heartbeat; log_info "\nExiting..."; exit 0' INT

    while true; do
        runner_poll_for_jobs
        sleep 5
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
