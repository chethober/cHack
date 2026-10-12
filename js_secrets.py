#!/usr/bin/env python3
"""
High-signal JS Analysis & Secret Scanner for cHack.
Enhanced with noise reduction, entropy verification, vendor filtering,
and placeholder suppression to minimize false positives.
"""
import sys
import os
import re
import json
import math
import ssl
import time
import socket
import base64
import bisect
import urllib.request
import urllib.error
import concurrent.futures
from collections import Counter
from urllib.parse import urlparse, urljoin

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Unverified SSL context to ensure resilient analysis of staging/internal assets
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# Known CDN and third-party tracking domains that generate massive false positives
VENDOR_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "facebook.net",
    "connect.facebook.net", "cloudflare.com", "intercom.io", "sentry.io",
    "clarity.ms", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "recaptcha.net", "hcaptcha.com", "stripe.com", "paypal.com",
    "segment.io", "hotjar.com", "newrelic.com", "datadoghq-browser-agent.com",
    "ajax.googleapis.com", "fonts.googleapis.com", "twimg.com"
}

# Known library filenames that contain static mock data or test tokens
VENDOR_FILE_REGEX = re.compile(
    r"(?:jquery|lodash|underscore|core-js|polyfill|react-dom|vue|angular|bootstrap|moment|axios|slick-carousel|chart\.js|fontawesome)"
    r"([.-][0-9a-z.-]+)?(\.min)?\.js$",
    re.IGNORECASE
)

# Common placeholder / dummy keywords found in client-side code
PLACEHOLDER_KEYWORDS = [
    "example", "sample", "dummy", "placeholder", "your_key", "your_token",
    "insert_", "replace_", "my_secret", "change_me", "test_key", "xxxx",
    "123456", "mock_", "fake_", "demo_key", "todo", "<token>", "{token}",
    "undefined", "null", "none"
]

# Static assets and MIME extensions to exclude from extracted API endpoints
EXCLUDED_ENDPOINT_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
    ".mp3", ".wav", ".pdf", ".zip", ".tar", ".gz"
)

# Entropy is only meaningful for generic / captured-group tokens. Rules with a strong
# fixed prefix (ghp_, AKIA, sk-ant-, …) are already proven by their format, so their
# min_entropy is 0.0 — entropy gating there adds no precision and can wrongly discard
# real, low-entropy keys.
PATTERNS = [
    # Source control & packages
    ("github_pat", "critical", r"\bghp_[0-9A-Za-z]{36}\b", 0.0),
    ("github_oauth", "critical", r"\bgho_[0-9A-Za-z]{36}\b", 0.0),
    ("github_app_token", "critical", r"\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b", 0.0),
    ("github_refresh", "high", r"\bghr_[0-9A-Za-z]{36}\b", 0.0),
    ("github_fine_grained", "critical", r"\bgithub_pat_[0-9A-Za-z_]{82}\b", 0.0),
    ("gitlab_pat", "critical", r"\bglpat-[0-9A-Za-z_\-]{20}\b", 0.0),
    ("npm_token", "high", r"\bnpm_[0-9A-Za-z]{36}\b", 0.0),
    ("pypi_token", "critical", r"\bpypi-AgEIcHlwaS[0-9A-Za-z_\-]{50,}\b", 0.0),
    ("rubygems", "high", r"\brubygems_[0-9a-f]{48}\b", 0.0),
    ("docker_hub_pat", "high", r"\bdckr_pat_[0-9A-Za-z_\-]{27,}\b", 0.0),

    # Cloud providers & Storage
    ("aws_access_key", "critical", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b", 0.0),
    ("aws_secret_key", "critical", r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)[\s:=\"']+([A-Za-z0-9/+=]{40})[\s\"']", 3.2),
    ("google_api_key", "high", r"\bAIza[0-9A-Za-z\-_]{35}\b", 0.0),
    ("firebase_url", "medium", r"https://[a-z0-9\-]+(?:\.firebaseio\.com|\.firebaseapp\.com)", 0.0),
    ("supabase_key", "critical", r"(?i)supabase[a-z0-9_\- ]{0,20}[:=]\s*[\"']?([A-Za-z0-9_\-\.]{80,})[\"']?", 3.2),
    ("digitalocean_pat", "critical", r"\bdop_v1_[0-9a-f]{64}\b", 0.0),
    ("digitalocean_oauth", "critical", r"\bdoo_v1_[0-9a-f]{64}\b", 0.0),
    ("heroku_api_key", "high", r"(?i)heroku[a-z0-9_\- ]{0,20}[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", 2.5),
    ("azure_storage_key", "critical", r"(?i)AccountKey=([0-9A-Za-z+/]{86}==)", 3.8),
    ("cloudflare_api_token", "high", r"(?i)cloudflare[a-z0-9_\- ]{0,20}[:=]\s*[\"']?([A-Za-z0-9_\-]{40})", 3.2),
    ("s3_bucket", "medium", r"\b(?:[a-z0-9\.\-]+\.s3(?:-[a-z0-9\-]+)?\.amazonaws\.com|s3://[a-z0-9\.\-]+)\b", 0.0),
    ("gcs_bucket", "medium", r"\b(?:storage\.googleapis\.com/[a-z0-9\.\-_]+|[a-z0-9\.\-_]+\.storage\.googleapis\.com)\b", 0.0),

    # Payments (Only true secret/restricted keys, not frontend publishable keys)
    ("stripe_secret", "critical", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b", 0.0),
    ("square_access", "critical", r"\b(?:sq0atp|sq0csp|EAAA)[0-9A-Za-z_\-]{22,60}\b", 0.0),
    ("paypal_braintree", "high", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b", 0.0),
    ("shopify_token", "critical", r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b", 0.0),

    # Messaging & Communications
    ("slack_token", "high", r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b", 0.0),
    ("slack_webhook", "high", r"https://hooks\.slack\.com/services/T[0-9A-Za-z_\-]{8,}/B[0-9A-Za-z_\-]{8,}/[0-9A-Za-z_\-]{24,}", 0.0),
    ("discord_webhook", "medium", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_\-]{60,}", 0.0),
    ("discord_bot_token", "high", r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b", 0.0),
    ("telegram_bot_token", "high", r"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b", 0.0),
    # SK+32hex alone collides with any hex blob — require a nearby `twilio` anchor.
    ("twilio_api_key", "high", r"(?i)twilio[a-z0-9_\- ]{0,30}[:=]\s*[\"']?(SK[0-9a-fA-F]{32})", 0.0),
    ("twilio_auth_token", "critical", r"(?i)twilio[a-z0-9_\- ]{0,20}[:=]\s*[\"']?([0-9a-fA-F]{32})[\"']?", 3.0),
    ("sendgrid", "critical", r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b", 0.0),
    # `key-`+32hex is far too generic on its own — require a nearby `mailgun` anchor.
    ("mailgun", "high", r"(?i)mailgun[a-z0-9_\- ]{0,30}[:=]\s*[\"']?(key-[0-9a-f]{32})", 0.0),

    # AI / SaaS
    ("openai_key", "critical", r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}T3BlbkFJ[0-9A-Za-z_\-]{20,}\b", 0.0),
    ("anthropic_key", "critical", r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b", 0.0),
    ("huggingface", "high", r"\bhf_[0-9A-Za-z]{34}\b", 0.0),
    ("datadog_api", "high", r"(?i)datadog[a-z0-9_\- ]{0,20}[:=]\s*[\"']?([0-9a-f]{32})", 2.8),
    ("newrelic", "high", r"\bNRAK-[0-9A-Z]{27}\b", 0.0),
    ("postman_key", "high", r"\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b", 0.0),
    ("linear_key", "high", r"\blin_api_[0-9A-Za-z]{40}\b", 0.0),

    # High Confidence Generic & Databases
    ("database_uri", "critical", r"\b(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp)://[a-zA-Z0-9_\-\.]+:[^@\s\"'\`]+@[a-zA-Z0-9_\-\.:]+/[a-zA-Z0-9_\-\.]+", 2.0),
    ("jwt", "high", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", 3.5),
    ("private_key_block", "critical", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", 0.0),
    ("private_key_escaped", "critical", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----\\n", 0.0),
    ("basic_auth_url", "high", r"(?i)\b(?:https?|ftp)://[a-z0-9._%\-]+:[^\s:@\"'`/]{6,}@[a-z0-9.\-]+", 2.5),
    # Session/bearer tokens in client code are rarely persistent secrets — low signal.
    ("generic_bearer", "low", r"(?i)authorization[\"'`\s]*[:=][\"'`\s]*bearer\s+([A-Za-z0-9_\-\.=]{24,})", 3.2)
]

# Rules whose matches are public by design (shipped to the browser on purpose).
# Their mere presence is not a vulnerability — only an unrestricted/privileged one is,
# which active verification decides. Default tier: informational.
PUBLIC_BY_DESIGN = {
    "google_api_key", "firebase_url", "s3_bucket", "gcs_bucket",
}

COMPILED_PATTERNS = [(name, sev, re.compile(pat), min_entropy) for name, sev, pat, min_entropy in PATTERNS]
ENDPOINT_REGEX = re.compile(
    r"""(?:['"`])(/(?:api|v[0-9]+|rest|graphql|auth|admin|user|internal|login|logout|dashboard|checkout|webhook|upload|export|settings|debug|account|cart|billing)/[a-zA-Z0-9_\-/?&=.%#]*)(?:['"`])"""
)
API_HOST_REGEX = re.compile(
    r"""https?://(?:[a-zA-Z0-9_\-]+\.)*(?:api|dev|stage|staging|test|internal|backend|admin)\.[a-zA-Z0-9_\-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_\-/?&=.%#]*)?"""
)


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder(secret: str) -> bool:
    """Checks if a secret is a placeholder, example, or dummy key."""
    s_lower = secret.lower()

    # Contains placeholder keyword
    for kw in PLACEHOLDER_KEYWORDS:
        if kw in s_lower:
            return True

    # Check for long runs of a single character (e.g., '000000', 'xxxxxx', 'ffffff')
    if re.search(r'(.)\1{5,}', s_lower):
        return True

    # Strip common prefix before checking distinct character count
    body = re.sub(r'^(?:gh[porsu]_|sk_[a-z]+_|glpat-|xox[baprs]-|dop_v1_|ai_za|ya29\.)', '', s_lower)
    if len(body) > 6 and len(set(body)) < 4:
        return True

    return False


def is_vendor_target(target: str) -> bool:
    """Identifies third-party CDNs and known open-source vendor scripts."""
    parsed = urlparse(target)
    hostname = (parsed.hostname or "").lower()

    # Check third-party tracking/CDN domains
    for vdomain in VENDOR_DOMAINS:
        if hostname == vdomain or hostname.endswith("." + vdomain):
            return True

    # Check vendor library filenames
    path = parsed.path or target
    filename = os.path.basename(path)
    if VENDOR_FILE_REGEX.search(filename):
        return True

    return False


def fetch_url(url: str, timeout: int = 10, max_size: int = 8 * 1024 * 1024):
    """Fetches JavaScript/JSON/HTML file with size, timeout guards, and resilient SSL & proxy handling."""
    if HAS_REQUESTS:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': '*/*'
            }
            # For loopback addresses, bypass any proxy
            proxies = None
            if '127.0.0.1' in url or 'localhost' in url:
                proxies = {'http': '', 'https': ''}

            with requests.get(url, headers=headers, timeout=timeout, verify=False, stream=True, proxies=proxies) as resp:
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '').lower()
                    if any(ct in content_type for ct in ('javascript', 'json', 'text', 'html')) or url.split('?')[0].endswith(('.js', '.map', '.html', '.htm')):
                        data = resp.raw.read(max_size + 1)
                        if len(data) <= max_size:
                            return data.decode('utf-8', errors='ignore')
        except Exception:
            pass
        return None

    # Fallback to urllib.request
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': '*/*'
            }
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=SSL_CTX))
        with opener.open(req, timeout=timeout) as resp:
            content_type = resp.headers.get('Content-Type', '').lower()
            if any(ct in content_type for ct in ('javascript', 'json', 'text', 'html')) or url.split('?')[0].endswith(('.js', '.map', '.html', '.htm')):
                data = resp.read(max_size + 1)
                if len(data) <= max_size:
                    return data.decode('utf-8', errors='ignore')
    except Exception:
        pass
    return None


def scan_text(content: str, source_url: str):
    """Scans content for secrets and endpoints using heuristics, entropy checks, and context capture."""
    secrets = []
    endpoints = []

    # Pre-compute newline offsets for fast line number determination
    newline_offsets = [0] + [m.start() + 1 for m in re.finditer(r'\n', content)]

    def get_line_number(char_idx: int) -> int:
        return bisect.bisect_right(newline_offsets, char_idx)

    # 1. Match Secrets with Heuristic Filtering
    for name, severity, pattern, min_entropy in COMPILED_PATTERNS:
        for match in pattern.finditer(content):
            # If pattern has a capturing group (e.g. extracted key without wrapper syntax)
            token = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            token = token.strip().strip('"\'`')

            # Filter dummy placeholders
            if is_placeholder(token):
                continue

            # Check Shannon entropy for random-token patterns
            if min_entropy > 0.0:
                ent = shannon_entropy(token)
                if ent < min_entropy:
                    continue

            # Extract surrounding context (~60 chars before and ~60 chars after)
            start_pos = match.start()
            end_pos = match.end()
            line_num = get_line_number(start_pos)

            ctx_start = max(0, start_pos - 60)
            ctx_end = min(len(content), end_pos + 60)
            raw_ctx = content[ctx_start:ctx_end].replace('\r', ' ').replace('\n', ' ')
            context_snippet = re.sub(r'\s+', ' ', raw_ctx).strip()

            secrets.append({
                "rule_name": name,
                "secret_type": name.split('_')[0],
                "match_snippet": token[:120],
                "context": context_snippet[:200],
                "line_number": line_num,
                "file_url": source_url,
                "severity": severity,
                "confidence": "high" if min_entropy > 3.0 else "medium"
            })

    # 2. Match and Clean Relative API Endpoints
    parsed_source = urlparse(source_url) if (source_url.startswith("http://") or source_url.startswith("https://")) else None

    for match in ENDPOINT_REGEX.finditer(content):
        ep = match.group(1).strip()
        ep_clean = ep.split('?')[0].lower()

        # Skip short fragments or media/font assets
        if len(ep) <= 3 or ep_clean.endswith(EXCLUDED_ENDPOINT_EXTENSIONS):
            continue

        # Resolve relative route against base URL if scanning a web host
        resolved_url = urljoin(source_url, ep) if parsed_source else ep

        endpoints.append({
            "url": resolved_url,
            "path": ep,
            "source": "js_analysis"
        })

    # 3. Match Absolute API and Staging Host URLs
    for match in API_HOST_REGEX.finditer(content):
        full_url = match.group(0).strip().rstrip('\'"`),;')
        full_clean = full_url.split('?')[0].lower()
        if full_clean.endswith(EXCLUDED_ENDPOINT_EXTENSIONS):
            continue
        parsed_ep = urlparse(full_url)
        endpoints.append({
            "url": full_url,
            "path": parsed_ep.path or "/",
            "source": "js_analysis_host"
        })

    return secrets, endpoints


def process_sourcemap(target: str, js_content: str):
    """Probes for exposed JavaScript sourcemap (remote and base64 inline) and analyzes original sources."""
    if not (target.startswith('http://') or target.startswith('https://')):
        return [], []

    map_url = None
    map_data = None

    # Check explicit sourceMappingURL directive in JS content
    sm_match = re.search(r'/[/*]#\s*sourceMappingURL=([^\s\'"]+)', js_content)
    if sm_match:
        ref = sm_match.group(1).strip()
        if ref.startswith('data:'):
            # Parse inline base64 sourcemap
            try:
                b64_part = ref.split(',', 1)[1] if ',' in ref else ''
                map_data = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
                map_url = f"{target}#inline-sourcemap"
            except Exception:
                map_data = None
        else:
            map_url = urljoin(target, ref)

    # Fallback to standard convention <url>.map
    if not map_data and not map_url:
        clean_target = target.split('?')[0]
        if clean_target.endswith('.js'):
            map_url = clean_target + '.map'

    if not map_data and map_url and not map_url.startswith('data:'):
        map_data = fetch_url(map_url, timeout=6, max_size=10 * 1024 * 1024)

    if not map_data or not map_data.strip().startswith('{'):
        return [], []

    try:
        parsed_map = json.loads(map_data)
        sources = parsed_map.get('sources', [])
        contents = parsed_map.get('sourcesContent', [])

        secrets = [{
            "rule_name": "exposed_sourcemap",
            "secret_type": "sourcemap",
            "match_snippet": f"Exposed source map with {len(sources)} files: {map_url}",
            "context": f"Found {len(sources)} source files mapped",
            "line_number": 1,
            "file_url": map_url,
            "severity": "medium",
            "confidence": "high"
        }]
        endpoints = []

        # Extract routes/paths from sources even if sourcesContent is absent
        for src_path in sources[:100]:
            if src_path and isinstance(src_path, str):
                cleaned_path = src_path.lstrip('./').lstrip('/')
                if any(cleaned_path.startswith(pfx) for pfx in ("pages/", "routes/", "api/", "src/pages/", "src/routes/", "src/api/")):
                    endpoints.append({
                        "url": urljoin(target, "/" + cleaned_path),
                        "path": "/" + cleaned_path,
                        "source": "sourcemap_source_tree"
                    })

        # Analyze extracted original source files
        if contents and isinstance(contents, list):
            for idx, src_text in enumerate(contents[:100]):  # Cap at 100 files for performance
                if src_text and isinstance(src_text, str):
                    s_name = sources[idx] if idx < len(sources) else f"source_{idx}"
                    src_label = f"{map_url} -> {s_name}"
                    sub_sec, sub_ep = scan_text(src_text, src_label)
                    secrets.extend(sub_sec)
                    endpoints.extend(sub_ep)

        return secrets, endpoints
    except Exception:
        return [], []


def process_file_or_url(target: str):
    target = target.strip()
    if not target:
        return [], []

    # Filter known third-party / vendor scripts before fetching
    if is_vendor_target(target):
        return [], []

    content = None
    if target.startswith('http://') or target.startswith('https://'):
        content = fetch_url(target)
    elif os.path.exists(target):
        try:
            with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            pass

    if content:
        secrets, endpoints = scan_text(content, target)

        # Probe for exposed sourcemap
        map_secrets, map_endpoints = process_sourcemap(target, content)
        if map_secrets:
            secrets.extend(map_secrets)
        if map_endpoints:
            endpoints.extend(map_endpoints)

        return secrets, endpoints

    return [], []


def extract_live_host(host_url: str, output_dir: str, inline_dir: str):
    """Probes a single live host for HTML, extracts inline scripts, script tag sources, and Next.js/Webpack manifests."""
    host_url = host_url.strip()
    if not host_url.startswith(('http://', 'https://')):
        host_url = f"https://{host_url}"

    parsed = urlparse(host_url)
    host_slug = re.sub(r'[^a-zA-Z0-9_\-]', '_', parsed.netloc)

    html = fetch_url(host_url, timeout=8, max_size=4 * 1024 * 1024)
    if not html:
        return [], [], []

    discovered_js = []
    discovered_routes = []
    inline_files = []

    # 1. Extract <script src="...">
    script_src_pattern = re.compile(r'<script(?:\s+[^>]*?)?\s+src=[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
    for match in script_src_pattern.finditer(html):
        src = match.group(1).strip()
        if src.startswith(('data:', 'javascript:')):
            continue
        full_js_url = urljoin(host_url, src)
        if not is_vendor_target(full_js_url):
            discovered_js.append(full_js_url)

    # 2. Extract inline <script> blocks
    script_block_pattern = re.compile(r'<script(?:\s+[^>]*?)?>([\s\S]*?)</script>', re.IGNORECASE)
    script_idx = 0
    build_id = None

    for match in script_block_pattern.finditer(html):
        content = match.group(1).strip()
        if len(content) < 15:
            continue

        # Check for Next.js buildId in __NEXT_DATA__
        if '__NEXT_DATA__' in match.group(0) or '"buildId"' in content:
            bid_match = re.search(r'"buildId"\s*:\s*"([A-Za-z0-9_\-]+)"', content)
            if bid_match:
                build_id = bid_match.group(1)

        # Save inline script to file for deep scanning
        script_idx += 1
        inline_filename = f"inline_{host_slug}_{script_idx}.js"
        inline_filepath = os.path.join(inline_dir, inline_filename)
        try:
            with open(inline_filepath, 'w', encoding='utf-8') as f:
                f.write(f"// Host: {host_url}\n{content}\n")
            inline_files.append(inline_filepath)
            discovered_js.append(inline_filepath)
        except Exception:
            pass

    # 3. Check for Next.js buildId in script src tags if not found in __NEXT_DATA__
    if not build_id:
        bid_match = re.search(r'/_next/static/([A-Za-z0-9_\-]+)/_buildManifest\.js', html)
        if bid_match:
            build_id = bid_match.group(1)

    # 4. Probe Next.js _buildManifest.js and _ssgManifest.js
    if build_id:
        manifest_url = urljoin(host_url, f"/_next/static/{build_id}/_buildManifest.js")
        manifest_content = fetch_url(manifest_url, timeout=6, max_size=2 * 1024 * 1024)
        if manifest_content:
            discovered_js.append(manifest_url)
            # Next.js sortedPages: ["/", "/admin", ...]
            pages_match = re.search(r'sortedPages\s*:\s*(\[[^\]]+\])', manifest_content)
            if pages_match:
                try:
                    pages = json.loads(pages_match.group(1).replace("'", '"'))
                    for p in pages:
                        if isinstance(p, str) and p.startswith('/'):
                            discovered_routes.append(urljoin(host_url, p))
                except Exception:
                    pass

            # Extract chunk files: "static/chunks/pages/..."
            chunk_matches = re.findall(r'["\'](static/chunks/[^"\']+\.js)["\']', manifest_content)
            for chunk in chunk_matches:
                chunk_url = urljoin(host_url, f"/_next/{chunk}")
                discovered_js.append(chunk_url)

        # Also probe _ssgManifest.js
        ssg_url = urljoin(host_url, f"/_next/static/{build_id}/_ssgManifest.js")
        ssg_content = fetch_url(ssg_url, timeout=5, max_size=1 * 1024 * 1024)
        if ssg_content:
            discovered_js.append(ssg_url)
            ssg_routes = re.findall(r'["\'](/[a-zA-Z0-9_\-/?&=.%#]*)["\']', ssg_content)
            for r in ssg_routes:
                if len(r) > 1 and not r.endswith(('.js', '.css', '.json')):
                    discovered_routes.append(urljoin(host_url, r))

    return discovered_js, discovered_routes, inline_files


def extract_live_hosts(live_hosts_file: str, output_dir: str, max_workers: int = 20):
    """Extracts inline scripts, script tags, and Next.js manifests across all live hosts."""
    if not os.path.exists(live_hosts_file):
        return

    with open(live_hosts_file, 'r', encoding='utf-8', errors='ignore') as f:
        hosts = [line.strip() for line in f if line.strip()]

    if not hosts:
        return

    inline_dir = os.path.join(output_dir, "inline_scripts")
    os.makedirs(inline_dir, exist_ok=True)

    all_discovered_js = []
    all_discovered_routes = []
    total_inline = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(extract_live_host, h, output_dir, inline_dir): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            try:
                js_links, routes, inline_files = future.result()
                all_discovered_js.extend(js_links)
                all_discovered_routes.extend(routes)
                total_inline += len(inline_files)
            except Exception:
                pass

    # Append discovered JS files to output_dir/js_links
    js_links_path = os.path.join(output_dir, "js_links")
    existing_js = set()
    if os.path.exists(js_links_path):
        with open(js_links_path, 'r', encoding='utf-8', errors='ignore') as f:
            existing_js = {line.strip() for line in f if line.strip()}

    merged_js = existing_js.union(set(all_discovered_js))
    with open(js_links_path, 'w', encoding='utf-8') as f:
        for item in sorted(merged_js):
            f.write(f"{item}\n")

    # Append discovered routes to output_dir/katana_all
    katana_all_path = os.path.join(output_dir, "katana_all")
    existing_routes = set()
    if os.path.exists(katana_all_path):
        with open(katana_all_path, 'r', encoding='utf-8', errors='ignore') as f:
            existing_routes = {line.strip() for line in f if line.strip()}

    merged_routes = existing_routes.union(set(all_discovered_routes))
    with open(katana_all_path, 'w', encoding='utf-8') as f:
        for item in sorted(merged_routes):
            f.write(f"{item}\n")

    # Save manifest endpoints separately
    manifest_routes_path = os.path.join(output_dir, "manifest_endpoints.txt")
    with open(manifest_routes_path, 'w', encoding='utf-8') as f:
        for item in sorted(set(all_discovered_routes)):
            f.write(f"{item}\n")

    print(f"Discovered {total_inline} inline scripts, {len(all_discovered_routes)} manifest routes, and {len(merged_js)} total JS targets across live hosts.")


# ---------------------------------------------------------------------------
# Classification & active verification
#
# A regex match is a *candidate*, not a finding. Classification sorts candidates
# into three tiers so the output ranks real risk over noise:
#   - confirmed-live : a validator proved the credential is live (a real bug)
#   - candidate      : matched, not (or cannot be) verified
#   - informational  : public-by-design, or a benign/expired token
# Active verification (--verify) sends captured tokens to each provider's
# read-only "whoami" endpoint. It is OPT-IN: only run it against targets you
# are authorized to test.
# ---------------------------------------------------------------------------

VERIFY_TIMEOUT = 8


def _b64url_decode(segment: str) -> bytes:
    """Decodes a base64url segment, tolerating missing padding."""
    segment = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment)


def analyze_jwt(token: str):
    """Classifies a JWT by decoding its payload.

    Returns (tier, severity, reason). Most JWTs in client code are short-lived
    session tokens or public 'anon' keys — only a privileged, unexpired token is
    worth flagging as a real risk.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return "candidate", "high", "malformed jwt"
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", "ignore"))
    except Exception:
        return "informational", "low", "undecodable jwt payload"

    now = int(time.time())
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < now:
        return "informational", "low", "expired jwt"

    # Supabase/PostgREST-style privileged role, or explicit admin claims.
    role = str(payload.get("role", "")).lower()
    privileged_claims = {"service_role", "admin", "superuser", "root"}
    claim_values = {str(v).lower() for v in payload.values() if isinstance(v, (str, int))}
    if role in privileged_claims or privileged_claims & claim_values:
        return "candidate", "critical", f"privileged jwt (role={role or 'n/a'})"

    return "informational", "low", "non-privileged jwt"


def _http_request(method: str, url: str, headers=None, data=None, timeout=VERIFY_TIMEOUT):
    """Minimal HTTP helper returning (status_code, body_text) or (None, None).

    Uses requests when available, else urllib. TLS verification is disabled to
    mirror the rest of the scanner's resilience against staging/internal certs.
    """
    headers = headers or {}
    if HAS_REQUESTS:
        try:
            resp = requests.request(
                method, url, headers=headers, data=data,
                timeout=timeout, verify=False, allow_redirects=False,
            )
            return resp.status_code, resp.text[:2048]
        except Exception:
            return None, None
    try:
        body = data.encode() if isinstance(data, str) else data
        req = urllib.request.Request(url, headers=headers, data=body, method=method)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=SSL_CTX),
        )
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(2048).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, None


def _verify_github(token):
    status, _ = _http_request("GET", "https://api.github.com/user",
                              {"Authorization": f"Bearer {token}", "User-Agent": "cHack"})
    if status == 200:
        return True
    if status in (401, 403):
        return False
    return None


def _verify_gitlab(token):
    status, _ = _http_request("GET", "https://gitlab.com/api/v4/user",
                              {"PRIVATE-TOKEN": token})
    return True if status == 200 else (False if status == 401 else None)


def _verify_npm(token):
    status, _ = _http_request("GET", "https://registry.npmjs.org/-/whoami",
                              {"Authorization": f"Bearer {token}"})
    return True if status == 200 else (False if status in (401, 403) else None)


def _verify_stripe(token):
    # Stripe uses HTTP basic auth with the key as the username.
    cred = base64.b64encode(f"{token}:".encode()).decode()
    status, _ = _http_request("GET", "https://api.stripe.com/v1/account",
                              {"Authorization": f"Basic {cred}"})
    return True if status == 200 else (False if status == 401 else None)


def _verify_slack(token):
    status, body = _http_request("POST", "https://slack.com/api/auth.test",
                                 {"Authorization": f"Bearer {token}"})
    if status == 200 and body:
        try:
            return bool(json.loads(body).get("ok"))
        except Exception:
            return None
    return None


def _verify_sendgrid(token):
    status, _ = _http_request("GET", "https://api.sendgrid.com/v3/scopes",
                              {"Authorization": f"Bearer {token}"})
    return True if status == 200 else (False if status == 401 else None)


def _verify_openai(token):
    status, _ = _http_request("GET", "https://api.openai.com/v1/models",
                              {"Authorization": f"Bearer {token}"})
    return True if status == 200 else (False if status == 401 else None)


def _verify_anthropic(token):
    status, _ = _http_request("GET", "https://api.anthropic.com/v1/models",
                              {"x-api-key": token, "anthropic-version": "2023-06-01"})
    return True if status == 200 else (False if status in (401, 403) else None)


def _verify_huggingface(token):
    status, _ = _http_request("GET", "https://huggingface.co/api/whoami-v2",
                              {"Authorization": f"Bearer {token}"})
    return True if status == 200 else (False if status == 401 else None)


def _verify_digitalocean(token):
    status, _ = _http_request("GET", "https://api.digitalocean.com/v2/account",
                              {"Authorization": f"Bearer {token}"})
    return True if status == 200 else (False if status == 401 else None)


def _verify_telegram(token):
    status, body = _http_request("GET", f"https://api.telegram.org/bot{token}/getMe")
    if status == 200 and body:
        try:
            return bool(json.loads(body).get("ok"))
        except Exception:
            return None
    return False if status in (401, 404) else None


def _verify_database_uri(token):
    """Confirms the database host is reachable (port open). Never authenticates."""
    parsed = urlparse(token)
    if not parsed.hostname:
        return None
    default_ports = {"postgres": 5432, "postgresql": 5432, "mysql": 3306,
                     "mongodb": 27017, "redis": 6379, "amqp": 5672}
    port = parsed.port or default_ports.get(parsed.scheme)
    if not port:
        return None
    try:
        with socket.create_connection((parsed.hostname, port), timeout=VERIFY_TIMEOUT):
            return True
    except Exception:
        return False


VALIDATORS = {
    "github_pat": _verify_github,
    "github_oauth": _verify_github,
    "github_app_token": _verify_github,
    "github_refresh": _verify_github,
    "github_fine_grained": _verify_github,
    "gitlab_pat": _verify_gitlab,
    "npm_token": _verify_npm,
    "stripe_secret": _verify_stripe,
    "slack_token": _verify_slack,
    "sendgrid": _verify_sendgrid,
    "openai_key": _verify_openai,
    "anthropic_key": _verify_anthropic,
    "huggingface": _verify_huggingface,
    "digitalocean_pat": _verify_digitalocean,
    "digitalocean_oauth": _verify_digitalocean,
    "telegram_bot_token": _verify_telegram,
    "database_uri": _verify_database_uri,
}


def classify_secret(secret: dict):
    """Assigns a base tier (before active verification) and refines JWT findings."""
    rule = secret["rule_name"]
    if rule == "jwt":
        tier, severity, reason = analyze_jwt(secret["match_snippet"])
        secret["severity"] = severity
        secret["classification_note"] = reason
        return tier
    if rule in PUBLIC_BY_DESIGN:
        secret["classification_note"] = "public by design; flag only if unrestricted"
        return "informational"
    return "candidate"


def verify_secrets(secrets, max_workers=20):
    """Actively verifies candidate secrets against provider APIs (opt-in).

    Promotes live credentials to 'confirmed-live' and drops ones proven dead.
    Candidates with no validator, or an inconclusive result, are kept as-is.
    """
    verifiable = [s for s in secrets
                  if s.get("tier") == "candidate" and s["rule_name"] in VALIDATORS]

    def _run(secret):
        try:
            return secret, VALIDATORS[secret["rule_name"]](secret["match_snippet"])
        except Exception:
            return secret, None

    if verifiable:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for secret, live in executor.map(_run, verifiable):
                if live is True:
                    secret["tier"] = "confirmed-live"
                    secret["confidence"] = "confirmed"
                elif live is False:
                    secret["tier"] = "dead"  # dropped below
    return [s for s in secrets if s.get("tier") != "dead"]


_TIER_ORDER = {"confirmed-live": 0, "candidate": 1, "informational": 2}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def main():
    # Extract optional flags up front so positional parsing stays unchanged.
    # --verify can also be enabled via the JS_VERIFY env var (used by cHack.sh).
    verify = os.environ.get("JS_VERIFY", "").lower() in ("1", "true", "yes")
    only_verified = False
    flag_argv = []
    for arg in sys.argv:
        if arg == "--verify":
            verify = True
        elif arg == "--only-verified":
            verify = True
            only_verified = True
        else:
            flag_argv.append(arg)
    sys.argv = flag_argv

    if len(sys.argv) < 2:
        print("Usage: js_secrets.py <urls_or_files_list> [output_json] [threads] [--verify] [--only-verified]")
        print("       js_secrets.py --extract-live <live_hosts_file> <output_dir> [threads]")
        sys.exit(1)

    if sys.argv[1] == '--extract-live':
        if len(sys.argv) < 4:
            print("Usage: js_secrets.py --extract-live <live_hosts_file> <output_dir> [threads]")
            sys.exit(1)
        live_hosts_file = sys.argv[2]
        output_dir = sys.argv[3]
        workers = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4].isdigit() else 20
        extract_live_hosts(live_hosts_file, output_dir, max_workers=workers)
        sys.exit(0)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "js_findings.json"

    if not os.path.exists(input_file):
        print(f"Error: input file {input_file} does not exist.")
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        targets = [line.strip() for line in f if line.strip()]

    all_secrets = []
    all_endpoints = []
    seen_secrets = set()
    seen_endpoints = set()

    threads_env = os.environ.get("JS_THREADS") or os.environ.get("THREADS")
    max_workers = int(threads_env) if threads_env and threads_env.isdigit() else 50
    if len(sys.argv) > 3 and sys.argv[3].isdigit():
        max_workers = int(sys.argv[3])

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_file_or_url, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            try:
                secrets, endpoints = future.result()
                for s in secrets:
                    key = (s['rule_name'], s['match_snippet'])
                    if key not in seen_secrets:
                        seen_secrets.add(key)
                        all_secrets.append(s)
                for ep in endpoints:
                    if ep['url'] not in seen_endpoints:
                        seen_endpoints.add(ep['url'])
                        all_endpoints.append(ep)
            except Exception:
                pass

    # Classify each candidate into a tier (confirmed-live / candidate / informational).
    for s in all_secrets:
        s["tier"] = classify_secret(s)

    # Optionally verify candidates against provider APIs, dropping dead credentials.
    if verify:
        all_secrets = verify_secrets(all_secrets, max_workers=min(max_workers, 20))

    if only_verified:
        all_secrets = [s for s in all_secrets if s.get("tier") == "confirmed-live"]

    # Rank: confirmed bugs first, then candidates, then informational — each by severity.
    all_secrets.sort(key=lambda s: (
        _TIER_ORDER.get(s.get("tier"), 1),
        _SEVERITY_ORDER.get(s.get("severity"), 4),
    ))

    tier_counts = Counter(s.get("tier", "candidate") for s in all_secrets)

    result = {
        "secrets": all_secrets,
        "endpoints": all_endpoints,
        "summary": {
            "total": len(all_secrets),
            "confirmed_live": tier_counts.get("confirmed-live", 0),
            "candidate": tier_counts.get("candidate", 0),
            "informational": tier_counts.get("informational", 0),
            "verified": verify,
        },
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    if verify:
        print(f"Discovered {len(all_secrets)} secrets "
              f"({tier_counts.get('confirmed-live', 0)} confirmed-live, "
              f"{tier_counts.get('candidate', 0)} candidate, "
              f"{tier_counts.get('informational', 0)} informational) "
              f"and {len(all_endpoints)} endpoints. Saved to {output_file}")
    else:
        print(f"Discovered {len(all_secrets)} candidate secrets "
              f"({tier_counts.get('informational', 0)} informational) "
              f"and {len(all_endpoints)} endpoints. Saved to {output_file} "
              f"(run with --verify to confirm which are live)")


if __name__ == '__main__':
    main()
