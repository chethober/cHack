#!/usr/bin/env python3
"""
High-signal JS Analysis & Secret Scanner for cHack.
Imported and adapted from Reconner's secret_patterns.go and js_scanner.go.
"""
import sys
import os
import re
import json
import urllib.request
import concurrent.futures
from urllib.parse import urlparse

PATTERNS = [
    # Source control & packages
    ("github_pat", "critical", r"\bghp_[0-9A-Za-z]{36}\b"),
    ("github_oauth", "critical", r"\bgho_[0-9A-Za-z]{36}\b"),
    ("github_app_token", "critical", r"\b(?:ghu|ghs)_[0-9A-Za-z]{36}\b"),
    ("github_refresh", "high", r"\bghr_[0-9A-Za-z]{36}\b"),
    ("github_fine_grained", "critical", r"\bgithub_pat_[0-9A-Za-z_]{82}\b"),
    ("gitlab_pat", "critical", r"\bglpat-[0-9A-Za-z_\-]{20}\b"),
    ("npm_token", "high", r"\bnpm_[0-9A-Za-z]{36}\b"),
    ("pypi_token", "critical", r"\bpypi-AgEIcHlwaS[0-9A-Za-z_\-]{50,}\b"),
    ("rubygems", "high", r"\brubygems_[0-9a-f]{48}\b"),
    ("docker_hub_pat", "high", r"\bdckr_pat_[0-9A-Za-z_\-]{27,}\b"),

    # Cloud providers
    ("aws_access_key", "critical", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ("gcp_api_key", "high", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("gcp_service_account", "critical", r'"type":\s*"service_account"'),
    ("gcp_oauth", "high", r"\bya29\.[0-9A-Za-z_\-]{50,}\b"),
    ("digitalocean_pat", "critical", r"\bdop_v1_[0-9a-f]{64}\b"),
    ("digitalocean_oauth", "critical", r"\bdoo_v1_[0-9a-f]{64}\b"),
    ("heroku_api_key", "high", r"(?i)heroku[a-z0-9_\- ]{0,20}[:=]\s*[\"']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("azure_storage_key", "critical", r"(?i)AccountKey=[0-9A-Za-z+/]{86}=="),
    ("cloudflare_api_token", "high", r"(?i)cloudflare[a-z0-9_\- ]{0,20}[:=]\s*[\"']?[A-Za-z0-9_\-]{40}"),

    # Payments
    ("stripe_secret", "critical", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b"),
    ("stripe_restricted", "high", r"\bsk_test_[0-9a-zA-Z]{24,99}\b"),
    ("square_access", "critical", r"\b(?:sq0atp|sq0csp|EAAA)[0-9A-Za-z_\-]{22,60}\b"),
    ("paypal_braintree", "high", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    ("shopify_token", "critical", r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"),

    # Messaging
    ("slack_token", "high", r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b"),
    ("slack_webhook", "high", r"https://hooks\.slack\.com/services/T[0-9A-Za-z_\-]{8,}/B[0-9A-Za-z_\-]{8,}/[0-9A-Za-z_\-]{24,}"),
    ("discord_webhook", "medium", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_\-]{60,}"),
    ("discord_bot_token", "high", r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b"),
    ("telegram_bot_token", "high", r"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b"),
    ("twilio_account_sid", "high", r"\bAC[0-9a-fA-F]{32}\b"),
    ("twilio_api_key", "high", r"\bSK[0-9a-fA-F]{32}\b"),
    ("sendgrid", "critical", r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
    ("mailgun", "high", r"\bkey-[0-9a-f]{32}\b"),
    ("mailchimp", "high", r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"),

    # AI / SaaS
    ("openai_key", "critical", r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}T3BlbkFJ[0-9A-Za-z_\-]{20,}\b"),
    ("anthropic_key", "critical", r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b"),
    ("huggingface", "high", r"\bhf_[0-9A-Za-z]{34}\b"),
    ("datadog_api", "high", r"(?i)datadog[a-z0-9_\- ]{0,20}[:=]\s*[\"']?[0-9a-f]{32}"),
    ("newrelic", "high", r"\bNRAK-[0-9A-Z]{27}\b"),
    ("postman_key", "high", r"\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b"),
    ("databricks", "high", r"\bdapi[0-9a-f]{32}\b"),
    ("linear_key", "high", r"\blin_api_[0-9A-Za-z]{40}\b"),

    # Generic High Confidence
    ("jwt", "high", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("private_key_block", "critical", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("basic_auth_url", "high", r"(?i)\b(?:https?|ftp)://[a-z0-9._%\-]+:[^\s:@\"'`/]{3,}@[a-z0-9.\-]+"),
    ("generic_bearer", "medium", r"(?i)authorization[\"'`\s]*[:=][\"'`\s]*bearer\s+[A-Za-z0-9_\-\.=]{20,}")
]

COMPILED_PATTERNS = [(name, sev, re.compile(pat)) for name, sev, pat in PATTERNS]
ENDPOINT_REGEX = re.compile(r"""(?:['"])(/(?:api|v[0-9]+|rest|graphql|auth|admin|user|internal)/[a-zA-Z0-9_\-/?&=.%#]*)(?:['"])""")

def fetch_url(url, timeout=10):
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (cHack Reconner Scanner 2.0)'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get('Content-Type', '')
            if 'javascript' in content_type or 'json' in content_type or 'text' in content_type or url.endswith('.js'):
                return resp.read().decode('utf-8', errors='ignore')
    except Exception:
        pass
    return None

def scan_text(content, source_url):
    secrets = []
    endpoints = []

    # Match secrets
    for name, severity, pattern in COMPILED_PATTERNS:
        for match in pattern.finditer(content):
            snippet = match.group(0)
            secrets.append({
                "rule_name": name,
                "secret_type": name.split('_')[0],
                "match_snippet": snippet[:100],
                "file_url": source_url,
                "severity": severity
            })

    # Match endpoints
    for match in ENDPOINT_REGEX.finditer(content):
        ep = match.group(1)
        if len(ep) > 3 and not ep.endswith('.png') and not ep.endswith('.jpg'):
            endpoints.append({
                "url": ep,
                "source": "js_analysis"
            })

    return secrets, endpoints

def process_file_or_url(target):
    target = target.strip()
    if not target:
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
        return scan_text(content, target)
    return [], []

def main():
    if len(sys.argv) < 2:
        print("Usage: js_secrets.py <urls_or_files_list> [output_json]")
        sys.exit(1)

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
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
            except Exception as e:
                pass

    result = {
        "secrets": all_secrets,
        "endpoints": all_endpoints
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    print(f"Discovered {len(all_secrets)} secrets and {len(all_endpoints)} endpoints. Saved to {output_file}")

if __name__ == '__main__':
    main()
