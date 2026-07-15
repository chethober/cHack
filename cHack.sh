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

log_info() {
    local timestamp=$(date '+%H:%M:%S')
    echo -e "\033[0;32m[INFO][$timestamp]\033[0m $1" >&2
    echo "[INFO][$timestamp] $1" >> "$LOG_FILE"
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

execute_sql() {
    log_error "execute_sql is deprecated (direct Postgres access removed). Database migrated to Cloudflare D1. Use GraphQL."
    return 1
}

execute_graphql() {
    local query="$1"
    local variables="$2"
    if [ -z "$variables" ]; then
        variables="{}"
    fi

    # Fallback to BACKEND_URL/graphql if GRAPHQL_ENDPOINT is local but BACKEND_URL is remote
    if [[ "$GRAPHQL_ENDPOINT" == *"localhost"* || "$GRAPHQL_ENDPOINT" == *"127.0.0.1"* ]] && [[ "$BACKEND_URL" == *"workers.dev"* || ( "$BACKEND_URL" == *"http"* && "$BACKEND_URL" != *"localhost"* && "$BACKEND_URL" != *"127.0.0.1"* ) ]]; then
        GRAPHQL_ENDPOINT="${BACKEND_URL%/}/graphql"
    fi

    if [ -z "$GRAPHQL_ENDPOINT" ]; then
        log_error "GRAPHQL_ENDPOINT is not configured in .env"
        return 1
    fi

    # Construct the JSON payload using jq to ensure correct escaping
    local payload
    if ! payload=$(jq -n --arg query "$query" --arg vars "$variables" '{query: $query, variables: ($vars | fromjson)}' 2>&1); then
        log_error "Failed to construct GraphQL payload: $payload"
        return 1
    fi

    local response
    local success=false

    # Try remote request first
    if response=$(curl -s --connect-timeout 10 -m 15 -X POST "$GRAPHQL_ENDPOINT" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>&1); then
        # Check if there are GraphQL errors in the response
        if ! echo "$response" | jq -e '.errors' >/dev/null 2>&1; then
            success=true
        fi
    fi

    if [ "$success" = true ]; then
        # Save to local SQLite database asynchronously using db_sqlite.py
        local temp_gql_in
        local temp_gql_res
        if temp_gql_in=$(mktemp 2>/dev/null) && temp_gql_res=$(mktemp 2>/dev/null); then
            echo "$payload" > "$temp_gql_in"
            echo "$response" > "$temp_gql_res"
            python3 "$SCRIPT_DIR/db_sqlite.py" graphql "$temp_gql_in" "$temp_gql_res" >/dev/null 2>&1 &
        fi
    else
        log_error "GraphQL HTTP Request failed or returned errors. Resolving locally via SQLite..."
        local temp_gql_in
        if temp_gql_in=$(mktemp 2>/dev/null); then
            echo "$payload" > "$temp_gql_in"
            if response=$(python3 "$SCRIPT_DIR/db_sqlite.py" query "$temp_gql_in" 2>/dev/null); then
                success=true
            else
                log_error "GraphQL local SQLite resolution failed."
                response=""
            fi
        fi
    fi

    if [ "$success" = false ]; then
        return 1
    fi

    echo "$response"
}

db_add_user() {
    local username="$1"
    local number_id="${2:-""}"
    local first_name="${3:-""}"
    local last_name="${4:-""}"

    log_info "GraphQL: Adding user '$username'..."

    local query="mutation CreateUser(\$username: String!, \$number_id: BigInt, \$first_name: String, \$last_name: String) {
        createUser(username: \$username, number_id: \$number_id, first_name: \$first_name, last_name: \$last_name) {
            id
            username
        }
    }"

    # Construct variables JSON
    local variables
    variables=$(jq -n \
        --arg username "$username" \
        --arg number_id "$number_id" \
        --arg first_name "$first_name" \
        --arg last_name "$last_name" \
        '{username: $username, number_id: (if $number_id == "" then null else $number_id | tonumber end), first_name: (if $first_name == "" then null else $first_name end), last_name: (if $last_name == "" then null else $last_name end)}')

    local res
    if res=$(execute_graphql "$query" "$variables"); then
        local user_id
        user_id=$(echo "$res" | jq -r '.data.createUser.id')
        log_info "User added successfully (ID: $user_id)"
        echo "$user_id"
        return 0
    else
        log_error "Failed to add user via GraphQL"
        return 1
    fi
}

db_add_company() {
    local name="$1"
    local slug="$2"
    local description="${3:-""}"

    local owner_user_id=""
    if [ -n "$SENDER_ID" ]; then
        local user_q="query GetUserByNumberId(\$numId: BigInt!) { user(number_id: \$numId) { id } }"
        local user_v
        user_v=$(jq -n --argjson numId "$SENDER_ID" '{numId: $numId}')
        local user_res
        if user_res=$(execute_graphql "$user_q" "$user_v"); then
            owner_user_id=$(echo "$user_res" | jq -r '.data.user.id // empty')
        fi
    fi

    if [ -z "$owner_user_id" ]; then
        # Fetch bot user UUID
        local user_q="query GetUserByUsername(\$username: String!) { user(username: \$username) { id } }"
        local user_v
        user_v=$(jq -n '{username: "chackbot"}')
        local user_res
        if user_res=$(execute_graphql "$user_q" "$user_v"); then
            owner_user_id=$(echo "$user_res" | jq -r '.data.user.id // empty')
        fi

        if [ -z "$owner_user_id" ]; then
            # Create bot user if not exists
            local bot_number_id
            if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
                bot_number_id=$(echo "$TELEGRAM_BOT_TOKEN" | cut -d':' -f1)
            fi
            if ! [[ "$bot_number_id" =~ ^[0-9]+$ ]]; then
                bot_number_id="8326260912"
            fi
            db_add_user "chackbot" "$bot_number_id" "Chack" "Bot" >/dev/null

            user_res=$(execute_graphql "$user_q" "$user_v")
            owner_user_id=$(echo "$user_res" | jq -r '.data.user.id // empty')
        fi
    fi

    log_info "GraphQL: Adding company '$name'..."

    local query="mutation CreateCompany(\$input: CompanyInput!) {
        createCompany(input: \$input) {
            id
            name
        }
    }"

    # Construct input object
    local variables
    variables=$(jq -n \
        --arg name "$name" \
        --arg slug "$slug" \
        --arg desc "$description" \
        --arg owner "$owner_user_id" \
        '{input: {name: $name, slug: (if $slug == "" then null else $slug end), description: (if $desc == "" then null else $desc end), owner_user_id: (if $owner == "" then null else $owner end)}}')

    local res
    if res=$(execute_graphql "$query" "$variables"); then
        local company_id
        company_id=$(echo "$res" | jq -r '.data.createCompany.id')
        log_info "Company added successfully (ID: $company_id)"
        echo "$company_id"
        return 0
    else
        log_error "Failed to add company via GraphQL"
        return 1
    fi
}

db_add_person() {
    local company_id="$1"
    local f_name="$2"
    local l_name="${3:-""}"
    local email="${4:-""}"
    local phones_json="${5:-"[]"}"
    local data_json="${6:-"{}"}"

    log_info "GraphQL: Adding person '$f_name $l_name'..."

    local query="mutation CreatePeople(\$input: PeopleInput!) {
        createPeople(input: \$input) {
            id
            given_name
            family_name
        }
    }"

    # Construct emails array
    local emails_json="[]"
    if [ -n "$email" ]; then
        emails_json=$(jq -n --arg email "$email" '[$email]')
    fi

    # Construct input object
    local variables
    variables=$(jq -n \
        --arg cid "$company_id" \
        --arg fname "$f_name" \
        --arg lname "$l_name" \
        --argjson emails "$emails_json" \
        --argjson phones "$phones_json" \
        --argjson data "$data_json" \
        '{input: {company_id: $cid, given_name: $fname, family_name: (if $lname == "" then null else $lname end), emails: $emails, phones: $phones, data: $data}}')

    local res
    if res=$(execute_graphql "$query" "$variables"); then
        local person_id
        person_id=$(echo "$res" | jq -r '.data.createPeople.id')
        log_info "Person added successfully (ID: $person_id)"
        echo "$person_id"
        return 0
    else
        log_error "Failed to add person via GraphQL"
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
    variables=$(jq -n --arg slug "$slug" '{slug: $slug}')

    local res
    if res=$(execute_graphql "$query" "$variables"); then
        local company_id
        company_id=$(echo "$res" | jq -r '.data.companyBySlug.id // empty')
        echo "$company_id"
        return 0
    else
        return 1
    fi
}

db_add_domain() {
    local company_id="$1"
    local host="$2"

    local query="mutation CreateDomain(\$input: DomainInput!) {
        createDomain(input: \$input) {
            id
        }
    }"
    local variables
    variables=$(jq -n --arg cid "$company_id" --arg host "$host" '{input: {company_id: $cid, host: $host}}')

    local res
    if res=$(execute_graphql "$query" "$variables"); then
        local domain_id
        domain_id=$(echo "$res" | jq -r '.data.createDomain.id')
        echo "$domain_id"
        return 0
    else
        return 1
    fi
}



get_domains_to_scan() {
    local query="query { domainsToScan { slug } }"
    local res
    if res=$(execute_graphql "$query"); then
        echo "$res" | jq -r '.data.domainsToScan[].slug // empty'
    fi
}

insert_company_and_domains() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local company_id
    local name=$(whois $domain | grep "Registrant Organization" | cut -d ':' -f 2 | sed 's/^ *//')

    if [ -z "$name" ]; then
        name="$domain"
    fi

    # First, try to get the company ID via GraphQL
    company_id=$(db_get_company_by_slug "$domain")

    # If company not found, try to create it via GraphQL
    if [ -z "$company_id" ]; then
        company_id=$(db_add_company "$name" "$domain" "Discovered during domain recon")
        if [ -z "$company_id" ]; then
            log_error "Failed to create or find company for $domain. Skipping domain insertion."
            return
        fi
        log_info "Created new company (ID: $company_id) for domain: $domain"
    else
        log_info "Found existing company ID: $company_id for domain: $domain"
    fi

    # Try to find or insert the main domain
    # Since we don't have a direct domain query, we query companies and check if domain exists.
    # For robust scripting, we just call the createDomain GQL mutation.
    # The GQL backend resolver handles uniqueness or we can query domains in company if desired.
    # Let's perform createDomain. If it already exists, the resolver may throw/return null, or create it.
    local domain_id
    domain_id=$(db_add_domain "$company_id" "$domain")
    if [ -n "$domain_id" ]; then
        log_info "* Inserted main domain: $domain (ID: $domain_id)"
    else
        log_info "Main domain $domain already exists or failed to insert."
    fi

    # Insert subdomains if subdomains file exists
    if [ -f "$output_dir/subdomains" ]; then
        log_info "Processing subdomains from $output_dir/subdomains"
        while read -r subdomain; do
            # Skip empty lines and comments
            if [ -z "$subdomain" ] || [[ "$subdomain" == "#"* ]]; then
                continue
            fi

            # Clean up the subdomain
            subdomain=$(echo "$subdomain" | tr -d '\r' | tr -d '\n' | xargs)

            if [ -z "$subdomain" ]; then
                continue
            fi

            local subdomain_id
            subdomain_id=$(db_add_domain "$company_id" "$subdomain")
            if [ -n "$subdomain_id" ]; then
                log_info "* Inserted subdomain: $subdomain (ID: $subdomain_id)"
            else
                log_info "Subdomain $subdomain already exists or failed to insert."
            fi
        done < "$output_dir/subdomains"
    fi

    # Update company phase (phase 1)
    # We update the company using the updateCompany mutation
    local query="mutation UpdateCompany(\$id: ID!, \$input: CompanyInput!) {
        updateCompany(id: \$id, input: \$input) {
            id
        }
    }"
    local variables
    variables=$(jq -n \
        --arg id "$company_id" \
        --arg name "$name" \
        --arg slug "$domain" \
        '{id: $id, input: {name: $name, slug: $slug, data: {phase: "1"}}}')

    execute_graphql "$query" "$variables" >/dev/null

    log_info "Successfully processed company $domain (ID: $company_id) and its domains"
}

update_httpx_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    if [ ! -s "$output_dir/httpx.json" ]; then
        log_error "httpx.json is empty. Skipping results processing."
        return
    fi

    log_info "GraphQL: Uploading httpx results..."

    # Construct a single JSON array of all results
    local results_json
    results_json=$(jq -s '.' "$output_dir/httpx.json")

    local query="mutation UpdateHttpxResults(\$domain: String!, \$results: [JSON!]!) {
        updateHttpxResults(domain: \$domain, results: \$results)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson res "$results_json" '{domain: $dom, results: $res}')

    if execute_graphql "$query" "$variables" >/dev/null; then
        log_info "Updated httpx results in database via GraphQL"
    else
        log_error "Failed to update httpx results via GraphQL"
    fi
}

update_port_scan_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    if [ ! -s "$output_dir/ports.json" ]; then
        log_error "ports.json is empty. Skipping port scan results."
        return
    fi

    # Process ports.json
    local ports_json
    ports_json=$(jq -c . "$output_dir/ports.json")

    # Get IPs if available
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

    if execute_graphql "$query" "$variables" >/dev/null; then
        log_info "Updated port scan results in database via GraphQL"
    else
        log_error "Failed to update port scan results via GraphQL"
    fi
}

update_katana_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local has_results=false

    # Phase update is handled in updateKatanaResults GraphQL mutation on backend Worker

    # Check if we have any katana results
    for subdomain_dir in "$output_dir/"*/; do
        if [ -d "$subdomain_dir" ] && { [ -f "$subdomain_dir/files" ] || [ -f "$subdomain_dir/urls" ] || [ -f "$subdomain_dir/params" ]; }; then
            has_results=true
            break
        fi
    done

    if [ "$has_results" = false ]; then
        log_info "No katana results found for $domain"
        return 0
    fi

    # Construct array of results
    local results_json="[]"

    # Process each subdomain
    for subdomain_dir in "$output_dir/"*/; do
        if [ -d "$subdomain_dir" ]; then
            local subdomain=$(basename "$subdomain_dir")
            local files="$(cat "$subdomain_dir/files" 2>/dev/null || echo '[]')"
            local urls="$(cat "$subdomain_dir/urls" 2>/dev/null || echo '[]')"
            local params="$(cat "$subdomain_dir/params" 2>/dev/null || echo '[]')"

            # Skip if no data
            if [ "$files" = "[]" ] && [ "$urls" = "[]" ] && [ "$params" = "[]" ]; then
                continue
            fi

            local item_json
            item_json=$(jq -n \
                --arg host "$subdomain" \
                --argjson files "$files" \
                --argjson urls "$urls" \
                --argjson params "$params" \
                '{host: $host, files: $files, urls: $urls, params: $params}')

            results_json=$(echo "$results_json" | jq --argjson item "$item_json" '. += [$item]')
        fi
    done

    log_info "GraphQL: Uploading Katana results..."

    local query="mutation UpdateKatanaResults(\$domain: String!, \$results: [JSON!]!) {
        updateKatanaResults(domain: \$domain, results: \$results)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson res "$results_json" '{domain: $dom, results: $res}')

    if execute_graphql "$query" "$variables" >/dev/null; then
        log_info "Updated katana results in database via GraphQL"
    else
        log_error "Failed to update katana results via GraphQL"
    fi
}

update_nuclei_results() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    # Check if nuclei results file exists
    if [ ! -f "$output_dir/nuclei.json" ]; then
        log_info "No nuclei results found for $domain"
        return 0
    fi

    local results_json="{}"

    # Process nuclei results
    if [ -f "$output_dir/live_hosts" ]; then
        while read -r url; do
            subdomain=$(echo "$url" | sed 's|https://||;s|http://||;s|/.*$||')
            subdomain_dir="$output_dir/$subdomain"

            if [ -f "$subdomain_dir/vulns" ]; then
                local vulns
                vulns=$(cat "$subdomain_dir/vulns")
                # Parse as JSON array if it's formatted as array, or keep as array of objects
                local val_json="[]"
                if [ -n "$vulns" ]; then
                    val_json=$(echo "$vulns" | jq -s '.' 2>/dev/null || jq -n --arg text "$vulns" '[$text]')
                fi

                results_json=$(echo "$results_json" | jq --arg url "$url" --argjson val "$val_json" '. + {($url): $val}')
            fi
        done < "$output_dir/live_hosts"
    fi

    log_info "GraphQL: Uploading Nuclei results..."

    local query="mutation UpdateNucleiResults(\$domain: String!, \$results: JSON!) {
        updateNucleiResults(domain: \$domain, results: \$results)
    }"
    local variables
    variables=$(jq -n --arg dom "$domain" --argjson res "$results_json" '{domain: $dom, results: $res}')

    if execute_graphql "$query" "$variables" >/dev/null; then
        log_info "Updated nuclei results in database via GraphQL"
    else
        log_error "Failed to update nuclei results via GraphQL"
    fi
}

process_domain() {
    local domain=$1

    # Create output directory
    local output_dir="$TARGETS_DIR/$domain"
    mkdir -p "$output_dir"

    # Update company updated_at timestamp to indicate scan started
    local company_id
    company_id=$(db_get_company_by_slug "$domain")
    if [ -n "$company_id" ]; then
        local query="mutation UpdateScanStart(\$id: ID!, \$input: CompanyInput!) {
            updateCompany(id: \$id, input: \$input) { id }
        }"
        local variables
        variables=$(jq -n --arg id "$company_id" '{id: $id, input: {name: "", data: {}} }') # payload to bump updated_at
        execute_graphql "$query" "$variables" >/dev/null
    fi

    # Run all phases
    run_subdomain_enum "$domain"
    run_httpx "$domain"
    run_naabu "$domain"
    run_katana "$domain"
    run_nuclei "$domain"

    log_info "All phases completed for $domain"
}

run_subdomain_enum() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    mkdir -p "$output_dir"

    log_phase "Starting Subdomain Enumeration"
    log_info "Target domain: $domain"
    log_info "Output directory: $output_dir"

    log_info "Running subfinder..."
    timeout 180 subfinder -d "$domain" -silent -disable-update-check > "$output_dir/subfinder"

    log_info "Running assetfinder..."
    timeout 120 assetfinder --subs-only "$domain" > "$output_dir/assetfinder"

    # Combine and deduplicate results
    log_info "Combining and deduplicating results..."
    cat "$output_dir/subfinder" "$output_dir/assetfinder" | sort -u | grep . > "$output_dir/subdomains"

    log_info "Subdomain enumeration completed. Total unique subdomains: $(wc -l < "$output_dir/subdomains")"
}

run_httpx() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    log_phase "Starting HTTPX Scan"

    if [ ! -s "$output_dir/subdomains" ]; then
        log_info "No subdomains to scan. Skipping HTTPX scan."
        echo "[]" > "$output_dir/httpx.json"
        touch "$output_dir/live_hosts"
        touch "$output_dir/ips"
        return
    fi

    log_info "Scanning $(wc -l < "$output_dir/subdomains") subdomains"

    timeout 300 ~/go/bin/httpx -list "$output_dir/subdomains" \
        -silent \
        -nc \
        -sc \
        -title \
        -ip \
        -server \
        -json \
        -irh \
        -td \
        -t 50 \
        -timeout 4 \
        -retries 1 \
        -disable-update-check \
        -o "$output_dir/httpx.json" > /dev/null 2>&1

    if [ ! -f "$output_dir/httpx.json" ]; then
        log_error "httpx failed to create an output file. Skipping results processing."
        return
    fi

    # Extract live hosts
    jq -r '.url' "$output_dir/httpx.json" > "$output_dir/live_hosts"

    # Extract IPs
    jq -r 'select(.host != null) | .host' "$output_dir/httpx.json" | sort -u > "$output_dir/ips"

    log_info "HTTPX scan completed. Found $(wc -l < "$output_dir/live_hosts") live hosts"
}

run_naabu() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    if [ ! -s "$output_dir/ips" ]; then
        log_error "No IPs to scan. Skipping port scan."
        echo "{}" > "$output_dir/ports.json"
        return
    fi

    log_phase "Starting Port Scan"
    log_info "Scanning $(wc -l < "$output_dir/ips") IPs..."

    timeout 300 naabu -hL "$output_dir/ips" \
        -silent \
        -ports top-1000 \
        > "$output_dir/ports"

    # Process ports into JSON format only if ports file exists and is not empty
    if [ -s "$output_dir/ports" ]; then
        log_info "Processing open ports..."

        declare -A ip_ports

        while IFS=: read -r ip port; do
            ip_ports["$ip"]+="$port "
        done < "$output_dir/ports"

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

        log_info "Grouped open ports into ports.json"
    else
        echo "{}" > "$output_dir/ports.json"
        log_error "No open ports found"
    fi
}

run_katana() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"

    log_phase "Starting URL Discovery"
    log_info "Processing $(wc -l < "$output_dir/live_hosts") live hosts"

    # Run katana once for all subs
    timeout 300 katana -list "$output_dir/live_hosts" \
        -silent \
        -jc 20 \
        -kf all \
        -c 50 \
        -d 3 \
        -timeout 10 \
        -retries 2 \
        -disable-update-check \
        > "$output_dir/katana_all"

    # Process each subdomain's URLs
    while read -r url; do
        subdomain=$(echo "$url" | sed 's|https://||;s|http://||;s|/.*$||')
        subdomain_dir="$output_dir/$subdomain"
        mkdir -p "$subdomain_dir"

        grep "$subdomain" "$output_dir/katana_all" > "$subdomain_dir/katana"

        grep -E '\.(js|json|php|aspx?|jsp|html?|txt|xml)(\?|$)' "$subdomain_dir/katana" > "$subdomain_dir/files"
        grep -E '\?.+=' "$subdomain_dir/katana" > "$subdomain_dir/params"
        grep -vE '(\?.+=|\.(js|json|php|aspx?|jsp|html?|txt|xml)(\?|$))' "$subdomain_dir/katana" > "$subdomain_dir/urls"

        log_info "Found $(wc -l < "$subdomain_dir/katana") URLs for $subdomain"
    done < "$output_dir/live_hosts"

    log_info "Katana URL discovery done"
}

run_nuclei() {
    local domain=$1
    local output_dir="$TARGETS_DIR/$domain"
    local total_hosts=$(wc -l < "$output_dir/live_hosts")
    local current_host=0

    log_phase "Starting Vulnerability Scan"
    log_info "Scanning $total_hosts live hosts"

    # Run nuclei on each live host
    while read -r url; do
        current_host=$((current_host + 1))
        # Extract subdomain from URL (remove protocol and path)
        subdomain=$(echo "$url" | sed 's|https://||;s|http://||;s|/.*$||')
        subdomain_dir="$output_dir/$subdomain"

        log_info "[$current_host/$total_hosts] Running nuclei for $subdomain"

        # Run nuclei
        nuclei -silent -disable-update-check -u "$subdomain" > "$subdomain_dir/vulns"

        if [ -s "$subdomain_dir/vulns" ]; then
            log_info "[$current_host/$total_hosts] Found $(wc -l < "$subdomain_dir/vulns") vulnerabilities for $subdomain"
        else
            log_info "[$current_host/$total_hosts] No vulnerabilities found for $subdomain"
        fi

    done < "$output_dir/live_hosts"

    log_info "Vulnerability scan completed for all hosts"
}

recon() {
    local domain=$1
    local start_time=$(date +%s)
    log_phase "Starting Recon"
    log_info "Target: $domain"
    log_info "Output directory: $TARGETS_DIR/$domain"
    mkdir -p "$TARGETS_DIR/$domain"

    if ! run_subdomain_enum "$domain"; then
        log_error "Subdomain enumeration failed"
        return 1
    fi
    insert_company_and_domains "$domain"
    
    local sub_count=0
    if [ -f "$output_dir/subdomains" ]; then
        sub_count=$(wc -l < "$output_dir/subdomains" | xargs)
    fi
    send_telegram_notification "✅ <b>Phase 1 Completed: Subdomain Enumeration</b> for <code>$domain</code>
• Total subdomains found: <b>$sub_count</b>"

    if ! run_httpx "$domain"; then
        log_error "HTTPX scan failed"
        return 1
    fi
    update_httpx_results "$domain"

    local live_count=0
    if [ -f "$output_dir/live_hosts" ]; then
        live_count=$(wc -l < "$output_dir/live_hosts" | xargs)
    fi
    send_telegram_notification "✅ <b>Phase 2 Completed: HTTPX Scan</b> for <code>$domain</code>
• Live hosts found: <b>$live_count</b>"

    if ! run_naabu "$domain"; then
        log_error "Port scanning failed"
        return 1
    fi
    update_port_scan_results "$domain"

    local port_count=0
    if [ -f "$output_dir/ports" ]; then
        port_count=$(wc -l < "$output_dir/ports" | xargs)
    fi
    send_telegram_notification "✅ <b>Phase 3 Completed: Port Scan</b> for <code>$domain</code>
• Open port entries: <b>$port_count</b>"

    if ! run_katana "$domain"; then
        log_error "Katana crawling failed"
        return 1
    fi
    #update_katana_results "$domain"

    local url_count=0
    if [ -f "$output_dir/katana_all" ]; then
        url_count=$(wc -l < "$output_dir/katana_all" | xargs)
    fi
    send_telegram_notification "✅ <b>Phase 4 Completed: URL Discovery (Katana)</b> for <code>$domain</code>
• Discovered URLs: <b>$url_count</b>"

    #if ! run_nuclei "$domain"; then
    #    log_error "Nuclei scanning failed"
    #    return 1
    #fi
    #update_nuclei_results "$domain"

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    log_phase "Recon Completed"
    log_info "Total time taken: $duration seconds"
    log_info "Results saved in $TARGETS_DIR/$domain"

    send_telegram_notification "🏁 <b>Recon Completed</b> for <code>$domain</code>
• Duration: <b>$duration</b> seconds.
• Results saved in targets directory."
}

show_usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -d, --domain DOMAIN    Run recon for the specified domain"
    echo "  -p, --person NAME      Add a person target (creates in DB via GraphQL API)"
    echo "  -c, --company NAME     Add a company target (creates in DB via GraphQL API)"
    echo "  -u, --user USERNAME    Add a new user (creates in DB via GraphQL API)"
    echo "  --number-id ID         Telegram number ID for the new user"
    echo "  --first-name NAME      First name for the new user"
    echo "  --last-name NAME       Last name for the new user"
    echo "  --sender-id ID         Telegram User ID of the command sender"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "If no options are provided, starts the job runner daemon polling the central queue."
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

    if [ -n "$BACKEND_URL" ]; then
        local payload
        payload=$(jq -n --arg id "$job_id" --arg status "$status" '{id: $id, status: $status}')
        curl -s -X POST "$BACKEND_URL/api/runner/status" \
            -H "Content-Type: application/json" \
            -d "$payload" >/dev/null 2>&1
    fi

    python3 "$SCRIPT_DIR/db_sqlite.py" update_status "$job_id" "$status" >/dev/null 2>&1
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

    log_info "🚀 [Job $job_id] Starting scan for domain: $domain"
    log_info "   Command args: $command_str"

    local temp_job_file
    temp_job_file=$(mktemp "/tmp/temp_job_XXXXXX.json" 2>/dev/null || mktemp)
    echo "$res" | jq '.job' > "$temp_job_file"
    python3 "$SCRIPT_DIR/db_sqlite.py" save_job "$temp_job_file" >/dev/null 2>&1

    python3 "$SCRIPT_DIR/db_sqlite.py" update_status "$job_id" "running" >/dev/null 2>&1

    local log_line
    eval "\"$SCRIPT_DIR/cHack.sh\" $command_str" 2>&1 | while IFS= read -r log_line || [ -n "$log_line" ]; do
        echo "$log_line"
        runner_send_log "$job_id" "$log_line"$'\n'
    done

    local exit_code=${PIPESTATUS[0]}
    log_info "🏁 [Job $job_id] Process exited with code: $exit_code"

    local final_status="completed"
    if [ $exit_code -ne 0 ]; then
        final_status="failed"
    fi

    runner_update_status "$job_id" "$final_status"
}

main() {
    local DOMAIN=""
    local PERSON=""
    local COMPANY=""
    local USERNAME=""
    local NUMBER_ID=""
    local FIRST_NAME=""
    local LAST_NAME=""
    SENDER_ID=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                DOMAIN="$2"
                shift 2
                ;;
            -p|--person)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                PERSON="$2"
                shift 2
                ;;
            -c|--company)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                COMPANY="$2"
                shift 2
                ;;
            -u|--user)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                USERNAME="$2"
                shift 2
                ;;
            --number-id)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                NUMBER_ID="$2"
                shift 2
                ;;
            --first-name)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                FIRST_NAME="$2"
                shift 2
                ;;
            --last-name)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                LAST_NAME="$2"
                shift 2
                ;;
            --sender-id)
                if [ $# -lt 2 ]; then
                    log_error "Option $1 requires an argument."
                    exit 1
                fi
                SENDER_ID="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                # Backward compatibility: if no options are set and it doesn't look like an option, treat it as a domain
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

    if [ -n "$DOMAIN" ]; then
        # Validate domain format
        if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log_error "Invalid domain format: $DOMAIN"
            exit 1
        fi
        recon "$DOMAIN"
        exit 0
    fi

    if [ -n "$PERSON" ]; then
        log_info "Adding person to DB: $PERSON"

        # Find or create a company to associate this person with.
        local company_id=""
        local comp_q="query { companies { id } }"
        local comp_res
        if comp_res=$(execute_graphql "$comp_q"); then
            company_id=$(echo "$comp_res" | jq -r '.data.companies[0].id // empty')
        fi

        if [ -z "$company_id" ]; then
            company_id=$(db_add_company "Default Company" "default-company" "Default company for orphan targets")
        fi

        if [ -z "$company_id" ]; then
            log_error "Cannot add person: No company available."
            exit 1
        fi

        local first_name=""
        local last_name=""
        local phones_json="[]"
        local data_json="{}"

        if [[ "$PERSON" =~ ^\+ ]]; then
            # Phone number target
            first_name="$PERSON"
            phones_json=$(jq -n --arg phone "$PERSON" '[$phone]')
        elif [[ "$PERSON" =~ ^@ ]]; then
            # Username target
            first_name="${PERSON#@}"
            data_json=$(jq -n --arg username "$PERSON" '{"username": $username}')
        else
            # Name target
            first_name=$(echo "$PERSON" | cut -d ' ' -f 1)
            last_name=$(echo "$PERSON" | cut -d ' ' -f 2-)
            if [ "$first_name" = "$last_name" ]; then
                last_name=""
            fi
        fi

        db_add_person "$company_id" "$first_name" "$last_name" "" "$phones_json" "$data_json"
        exit 0
    fi

    if [ -n "$COMPANY" ]; then
        log_info "Adding company to DB: $COMPANY"
        local slug
        slug=$(echo "$COMPANY" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g')
        db_add_company "$COMPANY" "$slug" "Added via CLI"
        exit 0
    fi

    if [ -n "$USERNAME" ]; then
        log_info "Adding user to DB: $USERNAME"
        db_add_user "$USERNAME" "$NUMBER_ID" "$FIRST_NAME" "$LAST_NAME"
        exit 0
    fi

    # Daemon mode (default if no inputs)
    log_info "Starting cHack Bash Daemon Runner (Ctrl+C to Exit)..."
    log_info "Backend URL: $BACKEND_URL"
    log_info "Runner Name: $RUNNER_NAME"

    # Ensure local database is initialized
    python3 "$SCRIPT_DIR/db_sqlite.py" init >/dev/null 2>&1

    # Set up trap to handle Ctrl+C
    trap 'log_info "\nExiting..."; exit 0' INT

    while true; do
        runner_poll_for_jobs
        sleep 5
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
