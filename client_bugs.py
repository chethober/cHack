#!/usr/bin/env python3
"""
Client-side bug hunter for cHack.

Two complementary engines, both authorized-use only:

  static  — passive source-code analysis of crawled/inline JavaScript for
            DOM-XSS source->sink flows, insecure postMessage listeners,
            prototype-pollution sinks, and dangerous dynamic-code execution.

  active  — live HTTP probing of discovered hosts/params for CORS
            misconfiguration, clickjacking / missing security headers, and
            reflected open-redirect behaviour.

Findings are emitted in cHack's standard finding schema so they merge straight
into all_findings.json:

    {title, severity, url, description, cve, evidence, tool, vuln_type}

Usage:
    client_bugs.py static <js_links_file> <output_json> [max_workers]
    client_bugs.py active <live_hosts_file> <params_file> <output_json> [max_workers]
    client_bugs.py all    <target_output_dir> [max_workers]
"""
import os
import re
import sys
import json
import uuid
import concurrent.futures
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl, urlencode, urljoin

# ---------------------------------------------------------------------------
# Reuse js_secrets' resilient fetcher + vendor filtering when available so we
# stay consistent with the rest of the pipeline (same UA, SSL handling, noise
# suppression). Fall back to local implementations if the import fails.
# ---------------------------------------------------------------------------
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from js_secrets import fetch_url, is_vendor_target, HAS_REQUESTS  # noqa: E402
except Exception:  # pragma: no cover - defensive fallback
    HAS_REQUESTS = False
    _VENDOR = ("google-analytics.com", "googletagmanager.com", "cloudflare.com",
               "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "jquery",
               "bootstrap", "react-dom", "polyfill")

    def is_vendor_target(t):
        tl = (t or "").lower()
        return any(v in tl for v in _VENDOR)

    def fetch_url(url, timeout=10, max_size=8 * 1024 * 1024):
        import ssl
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read(max_size).decode("utf-8", errors="ignore")
        except Exception:
            return None

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    requests = None

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# ===========================================================================
# STATIC ENGINE — DOM-based client-side analysis
# ===========================================================================

# Taint sources: attacker-controllable values in the browser.
SOURCE_RE = re.compile(
    r"location\.(?:hash|search|href|pathname)"
    r"|document\.(?:URL|documentURI|baseURI|referrer|cookie)"
    r"|window\.name"
    r"|\blocation\b(?!\s*=)"
    r"|URLSearchParams"
    r"|\.searchParams\b"
    r"|postMessage"
    r"|event\.data|e\.data|msg\.data",
    re.IGNORECASE,
)

# Dangerous sinks grouped by the kind of bug they create.
# Each: (rule_name, severity_when_tainted, severity_bare, compiled_regex)
HTML_SINKS = re.compile(
    r"\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(|document\.write(?:ln)?\s*\("
    r"|\$\([^)]*\)\.(?:html|append|prepend|after|before|replaceWith)\s*\("
    r"|dangerouslySetInnerHTML",
    re.IGNORECASE,
)
CODE_SINKS = re.compile(
    r"\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*[\"'`]|\bsetInterval\s*\(\s*[\"'`]"
    r"|\bdocument\.domain\s*=",
    re.IGNORECASE,
)
URL_SINKS = re.compile(
    r"location\s*=|location\.href\s*=|location\.assign\s*\(|location\.replace\s*\("
    r"|\.src\s*=|window\.open\s*\(",
    re.IGNORECASE,
)
# Prototype-pollution-prone recursive-merge / dynamic-key assignment.
PROTO_SINKS = re.compile(
    r"__proto__|constructor\s*\[\s*[\"']prototype[\"']\s*\]|\[\s*[\"']__proto__[\"']\s*\]"
    r"|Object\.assign\s*\([^,]*,\s*(?:JSON\.parse|location|params|query|data)",
    re.IGNORECASE,
)
# Wildcard postMessage target origin — leaks data to any window.
PM_WILDCARD_RE = re.compile(r"\.postMessage\s*\([^;]{0,400}?,\s*[\"']\*[\"']", re.IGNORECASE)
# message listener registration (either form).
PM_LISTENER_RE = re.compile(
    r"addEventListener\s*\(\s*[\"']message[\"']|(?:window|self)\.onmessage\s*=",
    re.IGNORECASE,
)
ORIGIN_CHECK_RE = re.compile(r"\.origin\b|\.source\b|originIsAllowed|trustedOrigins|allowedOrigins",
                             re.IGNORECASE)
# Framework HTML sinks that bypass the framework's auto-escaping.
FRAMEWORK_SINKS = re.compile(
    r"v-html\b|ng-bind-html\b|\[innerHTML\]|\btrustAsHtml\s*\(|\$sce\.trustAs|\$compile\s*\("
    r"|setAttribute\s*\(\s*[\"']on\w+[\"']",
    re.IGNORECASE,
)
# Sensitive values persisted to web storage (readable by any XSS).
STORAGE_RE = re.compile(
    r"(?:local|session)Storage\.setItem\s*\(\s*[\"'`][^\"'`]*"
    r"(?:token|jwt|secret|password|passwd|api[_-]?key|auth|session|credential|bearer)"
    r"[^\"'`]*[\"'`]",
    re.IGNORECASE,
)
# Insecure WebSocket transport.
WS_INSECURE_RE = re.compile(r"new\s+WebSocket\s*\(\s*[\"'`]\s*ws://", re.IGNORECASE)
# javascript: URI built from a dynamic/concatenated value.
JS_URI_RE = re.compile(r"[\"'`]\s*javascript:[^\"'`]*[\"'`]\s*\+|=\s*[\"'`]javascript:[\"'`]\s*\+",
                       re.IGNORECASE)

# Proximity window (chars) for correlating a source with a sink on big/minified files.
PROXIMITY = 160
MAX_PER_RULE = 25          # cap findings per rule per file to avoid flooding
MAX_SNIPPET = 220


def _finding(title, severity, url, description, evidence, vuln_type="xss"):
    return {
        "title": title,
        "severity": severity,
        "url": url or "",
        "description": description,
        "cve": "",
        "evidence": (evidence or "")[:MAX_SNIPPET],
        "tool": "client_bugs",
        "vuln_type": vuln_type,
    }


def _line_of(content, idx):
    return content.count("\n", 0, idx) + 1


def _snippet(content, idx, span=90):
    start = max(0, idx - span)
    end = min(len(content), idx + span)
    return content[start:end].replace("\n", " ").strip()


def _source_near(content, idx):
    lo = max(0, idx - PROXIMITY)
    hi = min(len(content), idx + PROXIMITY)
    return SOURCE_RE.search(content, lo, hi)


def _handler_body(content, start, max_len=800):
    """Return the balanced { ... } block of the handler starting at/after `start`.

    Falls back to a flat slice if no brace is found, so adjacent handlers don't
    bleed their origin checks into this one.
    """
    brace = content.find("{", start, start + 120)
    if brace == -1:
        return content[start:start + 200]
    depth, i, end = 0, brace, min(len(content), start + max_len)
    while i < end:
        c = content[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return content[brace:i + 1]
        i += 1
    return content[brace:end]


def analyze_js(content, source_url):
    """Scan one JS/HTML blob; return a list of findings."""
    findings = []
    if not content:
        return findings

    def scan(rule_regex, rule_name, vuln_type, tainted_sev, bare_sev, require_source):
        count = 0
        for m in rule_regex.finditer(content):
            if count >= MAX_PER_RULE:
                break
            near = _source_near(content, m.start())
            if require_source and not near:
                continue
            tainted = bool(near)
            sev = tainted_sev if tainted else bare_sev
            if sev is None:
                continue
            ln = _line_of(content, m.start())
            src_note = f" (user-controllable source `{near.group(0)}` nearby)" if tainted else ""
            findings.append(_finding(
                title=f"{rule_name}{' — likely DOM XSS' if tainted and vuln_type == 'xss' else ''}",
                severity=sev,
                url=source_url,
                description=(f"Sink `{m.group(0).strip()}` at line {ln}{src_note}. "
                             f"Review for untrusted data reaching this sink."),
                evidence=f"L{ln}: {_snippet(content, m.start())}",
                vuln_type=vuln_type,
            ))
            count += 1

    # HTML-writing sinks: only report when a taint source is nearby (noisy otherwise).
    scan(HTML_SINKS, "DOM HTML-injection sink", "xss", "high", None, require_source=True)
    # Dynamic code execution: high with source, medium bare (still risky).
    scan(CODE_SINKS, "Dynamic code execution sink", "xss", "high", "medium", require_source=False)
    # Navigation/src sinks: open-redirect / script-src injection when tainted.
    scan(URL_SINKS, "Client-side navigation sink", "open-redirect", "high", None, require_source=True)
    # Prototype pollution.
    scan(PROTO_SINKS, "Prototype-pollution-prone assignment", "prototype-pollution",
         "high", "medium", require_source=False)
    # Framework escaping bypass (v-html / ng-bind-html / trustAsHtml / $compile).
    scan(FRAMEWORK_SINKS, "Framework HTML-escaping bypass", "xss",
         "high", "medium", require_source=False)
    # javascript: URI built by concatenation (href/location).
    scan(JS_URI_RE, "Dynamically built javascript: URI", "xss",
         "high", "medium", require_source=False)

    # Sensitive data written to localStorage/sessionStorage (XSS-exfiltratable).
    for m in STORAGE_RE.finditer(content):
        ln = _line_of(content, m.start())
        findings.append(_finding(
            "Sensitive data stored in web storage", "medium", source_url,
            f"A token/credential-like value is written to web storage at line {ln}. "
            f"localStorage/sessionStorage is readable by any XSS on the origin; prefer "
            f"HttpOnly cookies for secrets.",
            f"L{ln}: {_snippet(content, m.start())}", vuln_type="sensitive-storage"))

    # Insecure WebSocket transport.
    for m in WS_INSECURE_RE.finditer(content):
        ln = _line_of(content, m.start())
        findings.append(_finding(
            "Insecure WebSocket (ws://)", "medium", source_url,
            f"A WebSocket is opened over plaintext ws:// at line {ln}; traffic is "
            f"interceptable/modifiable and blocked as mixed content on HTTPS pages.",
            f"L{ln}: {_snippet(content, m.start())}", vuln_type="insecure-transport"))

    # postMessage wildcard target origin.
    for m in PM_WILDCARD_RE.finditer(content):
        ln = _line_of(content, m.start())
        findings.append(_finding(
            "Insecure postMessage (wildcard target origin)", "medium", source_url,
            f"postMessage sends data with targetOrigin '*' at line {ln}; any framed/opener "
            f"window can read it. Pin an explicit origin.",
            f"L{ln}: {_snippet(content, m.start())}", vuln_type="postmessage"))

    # message listeners without an origin/source check.
    pm_hits = 0
    for m in PM_LISTENER_RE.finditer(content):
        if pm_hits >= MAX_PER_RULE:
            break
        body = _handler_body(content, m.start())
        if not ORIGIN_CHECK_RE.search(body):
            ln = _line_of(content, m.start())
            findings.append(_finding(
                "Insecure postMessage listener (missing origin check)", "medium", source_url,
                f"A 'message' event handler at line {ln} does not appear to validate "
                f"event.origin/source, allowing any site to post data to it.",
                f"L{ln}: {_snippet(content, m.start())}", vuln_type="postmessage"))
            pm_hits += 1
    return findings


def _read_target(target):
    """Return JS/HTML text for a URL or a local inline-script path."""
    if os.path.isfile(target):
        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return None
    if target.startswith(("http://", "https://")):
        return fetch_url(target)
    return None


def _static_one(target):
    target = target.strip()
    if not target or target.startswith("#"):
        return []
    if target.startswith(("http://", "https://")) and is_vendor_target(target):
        return []
    content = _read_target(target)
    label = target if target.startswith("http") else os.path.basename(target)
    return analyze_js(content, label)


def run_static(js_links_file, output_json, max_workers=20):
    if not os.path.isfile(js_links_file):
        _write(output_json, [])
        return
    with open(js_links_file, "r", encoding="utf-8", errors="ignore") as f:
        targets = [t for t in (ln.strip() for ln in f) if t]
    findings = []
    seen = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(_static_one, targets):
            for fnd in res:
                key = (fnd["title"], fnd["url"], fnd["evidence"][:60])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(fnd)
    _write(output_json, findings)
    print(f"[client_bugs:static] {len(findings)} client-side code findings -> {output_json}")


# ===========================================================================
# ACTIVE ENGINE — live HTTP probing
# ===========================================================================

REDIRECT_PARAMS = {
    "url", "u", "next", "redirect", "redirect_url", "redirect_uri", "redir",
    "return", "returnurl", "return_url", "returnto", "dest", "destination",
    "continue", "goto", "go", "target", "to", "out", "link", "callback", "rurl",
    "forward", "image_url", "checkout_url", "window", "view", "page",
}

SECURITY_HEADERS = {
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
}

CALLBACK_PARAMS = {"callback", "cb", "jsonp", "jsonpcallback", "jsoncallback",
                   "json_callback", "jscallback", "function", "func"}


def _normalize_host(h):
    h = h.strip()
    if not h:
        return None
    if not h.startswith(("http://", "https://")):
        h = "https://" + h
    return h


def _http(url, headers=None, allow_redirects=False, timeout=10, method="GET"):
    """Return (status, headers_lower_dict, text) or (None, {}, '')."""
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    if requests is not None:
        try:
            r = requests.request(method, url, headers=hdrs, timeout=timeout,
                                 verify=False, allow_redirects=allow_redirects)
            body = r.text if method != "HEAD" else ""
            return r.status_code, {k.lower(): v for k, v in r.headers.items()}, body
        except Exception:
            return None, {}, ""
    # urllib fallback
    import ssl
    import urllib.request
    import urllib.error
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        opener = urllib.request.build_opener(ctx and urllib.request.HTTPSHandler(context=ctx))
        if not allow_redirects:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect)
        req = urllib.request.Request(url, headers=hdrs, method=method)
        with opener.open(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(1 << 20).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}, ""
    except Exception:
        return None, {}, ""


def check_cors(host):
    findings = []
    evil = f"https://chack-canary-{uuid.uuid4().hex[:8]}.example.com"
    for test_origin, label in ((evil, "arbitrary reflected"), ("null", "null")):
        status, hdrs, _ = _http(host, headers={"Origin": test_origin})
        if status is None:
            return findings
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"
        reflected = acao == test_origin or (test_origin == "null" and acao == "null")
        if reflected:
            sev = "high" if acac else "medium"
            findings.append(_finding(
                f"CORS misconfiguration ({label} origin)", sev, host,
                f"Server reflects Origin '{test_origin}' into Access-Control-Allow-Origin"
                f"{' with Allow-Credentials: true' if acac else ''}. A malicious site can read "
                f"authenticated responses cross-origin.",
                f"Origin: {test_origin}  ->  ACAO: {acao}; ACAC: {acac}",
                vuln_type="cors"))
            break  # one CORS finding per host is enough
    else:
        # No reflection, but a static wildcard ACAO is still worth noting.
        _, hdrs, _ = _http(host, headers={"Origin": evil})
        if hdrs.get("access-control-allow-origin", "") == "*":
            findings.append(_finding(
                "CORS Access-Control-Allow-Origin: *", "info", host,
                "Responses are readable by any origin. Low risk while credentials are not "
                "allowed, but review for any endpoint returning sensitive data.",
                "Access-Control-Allow-Origin: *", vuln_type="cors"))
    return findings


def check_headers(host):
    findings = []
    status, hdrs, _ = _http(host)
    if status is None:
        return findings
    xfo = hdrs.get("x-frame-options", "").lower()
    csp = hdrs.get("content-security-policy", "")
    frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not frame_ancestors:
        findings.append(_finding(
            "Clickjacking: missing frame protections", "medium", host,
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is set; the page "
            "can be framed by any origin, enabling clickjacking.",
            "X-Frame-Options: <absent>; CSP frame-ancestors: <absent>",
            vuln_type="clickjacking"))
    if host.startswith("https://") and "strict-transport-security" not in hdrs:
        findings.append(_finding(
            "Missing HSTS header", "low", host,
            "No Strict-Transport-Security header; connections can be downgraded via SSL strip.",
            "Strict-Transport-Security: <absent>", vuln_type="security-headers"))
    if not csp:
        findings.append(_finding(
            "Missing Content-Security-Policy", "low", host,
            "No CSP header; reduces defense-in-depth against XSS and data injection.",
            "Content-Security-Policy: <absent>", vuln_type="security-headers"))
    elif re.search(r"unsafe-inline|unsafe-eval", csp, re.IGNORECASE):
        findings.append(_finding(
            "Weak Content-Security-Policy (unsafe-inline/eval)", "low", host,
            "CSP allows 'unsafe-inline' or 'unsafe-eval', largely negating its XSS protection.",
            f"CSP: {csp[:180]}", vuln_type="security-headers"))
    else:
        m = re.search(r"script-src[^;]*", csp, re.IGNORECASE)
        if m and re.search(r"(?:^|\s)\*(?:\s|$)|https?:(?:\s|$)", m.group(0)):
            findings.append(_finding(
                "Weak Content-Security-Policy (wildcard script-src)", "low", host,
                "script-src permits a wildcard/scheme source, allowing scripts from any host.",
                f"CSP script-src: {m.group(0)[:180]}", vuln_type="security-headers"))
    return findings


def check_open_redirect(param_url):
    """Replace redirect-like params with a canary and detect reflection in Location."""
    try:
        parts = urlsplit(param_url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
    except Exception:
        return []
    if not qs:
        return []
    targets = [k for k, _ in qs if k.lower() in REDIRECT_PARAMS]
    if not targets:
        return []
    canary_host = f"chack-canary-{uuid.uuid4().hex[:8]}.example.com"
    canary = f"https://{canary_host}/"
    findings = []
    for key in set(targets):
        new_qs = [(k, canary if k == key else v) for k, v in qs]
        test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_qs), parts.fragment))
        status, hdrs, body = _http(test_url, allow_redirects=False)
        if status is None:
            continue
        loc = hdrs.get("location", "")
        loc_l = loc.lower()
        hit = (300 <= (status or 0) < 400) and (
            loc_l.startswith(canary.lower())
            or loc_l.startswith(f"//{canary_host}")
            or canary_host in loc_l[:len(canary_host) + 12]
        )
        if hit:
            findings.append(_finding(
                "Open redirect", "high", test_url,
                f"Parameter '{key}' is reflected into the Location header, redirecting off-site "
                f"to an attacker-controlled destination (used for phishing / OAuth token theft).",
                f"HTTP {status}  Location: {loc[:160]}", vuln_type="open-redirect"))
        elif canary_host in (body or "")[:5000]:
            findings.append(_finding(
                "Potential client-side open redirect (reflected in body)", "medium", test_url,
                f"Canary from parameter '{key}' is reflected into the response body; verify it "
                f"is not used in a client-side location assignment / meta-refresh.",
                f"param={key}; canary reflected in body", vuln_type="open-redirect"))
    return findings


def check_jsonp(param_url):
    """Inject a canary callback name; flag endpoints that wrap JSON in it (JSONP)."""
    try:
        parts = urlsplit(param_url)
        qs = parse_qsl(parts.query, keep_blank_values=True)
    except Exception:
        return []
    cb_keys = [k for k, _ in qs if k.lower() in CALLBACK_PARAMS]
    if not cb_keys:
        return []
    canary = f"chackCb{uuid.uuid4().hex[:6]}"
    findings = []
    for key in set(cb_keys):
        new_qs = [(k, canary if k == key else v) for k, v in qs]
        test_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(new_qs), parts.fragment))
        status, hdrs, body = _http(test_url, allow_redirects=True)
        if status is None or not body:
            continue
        ctype = hdrs.get("content-type", "").lower()
        # Response executes the attacker-named callback with data payload.
        if re.search(r"(?:^|[^\w.])" + re.escape(canary) + r"\s*\(", body[:4000]) and \
           ("javascript" in ctype or "application/json" not in ctype):
            findings.append(_finding(
                "JSONP endpoint (callback reflected)", "medium", test_url,
                f"Parameter '{key}' controls a JSONP callback name that is reflected into an "
                f"executable response. Cross-origin pages can include this to steal the data "
                f"(and it can enable XSS if the callback is not validated).",
                f"callback={canary} -> body: {body[:120].strip()}", vuln_type="jsonp"))
    return findings


def check_mixed_and_tabnabbing(host):
    """Fetch host HTML; flag reverse-tabnabbing links and HTTPS mixed content."""
    if not host.startswith("https://"):
        return []
    status, _, body = _http(host, allow_redirects=True)
    if status is None or not body:
        return []
    findings = []
    # Reverse tabnabbing: target=_blank anchors without rel=noopener/noreferrer.
    tab = 0
    for m in re.finditer(r"<a\b[^>]*\btarget\s*=\s*[\"']?_blank[\"']?[^>]*>", body, re.IGNORECASE):
        if tab >= 5:
            break
        tag = m.group(0)
        if not re.search(r"rel\s*=\s*[\"'][^\"']*(?:noopener|noreferrer)", tag, re.IGNORECASE):
            findings.append(_finding(
                "Reverse tabnabbing (target=_blank without rel=noopener)", "low", host,
                "A target=_blank link lacks rel=noopener; the opened page can rewrite "
                "window.opener.location to a phishing page.",
                tag[:160], vuln_type="tabnabbing"))
            tab += 1
    # Mixed content: http:// subresources loaded by an HTTPS page.
    mix = re.search(r"(?:src|href)\s*=\s*[\"']http://[^\"']+\.(?:js|css)", body, re.IGNORECASE)
    if mix:
        findings.append(_finding(
            "Mixed content (HTTP resource on HTTPS page)", "low", host,
            "An HTTPS page references an http:// script/style resource; it is interceptable "
            "(and typically blocked by the browser).",
            mix.group(0)[:160], vuln_type="mixed-content"))
    return findings


def run_active(live_hosts_file, params_file, output_json, max_workers=20):
    hosts = []
    if os.path.isfile(live_hosts_file):
        with open(live_hosts_file, "r", encoding="utf-8", errors="ignore") as f:
            hosts = [h for h in (_normalize_host(x) for x in f) if h]
    hosts = list(dict.fromkeys(hosts))

    params = []
    if os.path.isfile(params_file):
        with open(params_file, "r", encoding="utf-8", errors="ignore") as f:
            params = [p.strip() for p in f if p.strip().startswith(("http://", "https://"))]
    all_params = list(dict.fromkeys(params))
    # Redirect-like params (open redirect) and callback params (JSONP), capped.
    redir_params = [p for p in all_params
                    if any(f"{k}=" in p.lower() or f"{k}%3d" in p.lower() for k in REDIRECT_PARAMS)][:150]
    jsonp_params = [p for p in all_params
                    if any(f"{k}=" in p.lower() or f"{k}%3d" in p.lower() for k in CALLBACK_PARAMS)][:150]

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        jobs = []
        for h in hosts:
            jobs.append(ex.submit(check_cors, h))
            jobs.append(ex.submit(check_headers, h))
            jobs.append(ex.submit(check_mixed_and_tabnabbing, h))
        for p in redir_params:
            jobs.append(ex.submit(check_open_redirect, p))
        for p in jsonp_params:
            jobs.append(ex.submit(check_jsonp, p))
        for fut in concurrent.futures.as_completed(jobs):
            try:
                findings.extend(fut.result())
            except Exception:
                pass

    # de-dup
    seen, out = set(), []
    for fnd in findings:
        key = (fnd["title"], fnd["url"])
        if key in seen:
            continue
        seen.add(key)
        out.append(fnd)
    _write(output_json, out)
    print(f"[client_bugs:active] {len(out)} live client-side findings "
          f"({len(hosts)} hosts, {len(redir_params)} redirect + {len(jsonp_params)} jsonp "
          f"candidate params) -> {output_json}")


# ===========================================================================
def _write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _merge(paths, output_json):
    merged, seen = [], set()
    for p in paths:
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                for fnd in json.load(f):
                    key = (fnd.get("title"), fnd.get("url"), fnd.get("evidence", "")[:60])
                    if key in seen:
                        continue
                    seen.add(key)
                    merged.append(fnd)
        except Exception:
            pass
    _write(output_json, merged)
    return merged


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    mode = sys.argv[1]

    if mode == "static":
        if len(sys.argv) < 4:
            print("Usage: client_bugs.py static <js_links_file> <output_json> [workers]")
            sys.exit(1)
        workers = int(sys.argv[4]) if len(sys.argv) > 4 else 20
        run_static(sys.argv[2], sys.argv[3], workers)

    elif mode == "active":
        if len(sys.argv) < 5:
            print("Usage: client_bugs.py active <live_hosts_file> <params_file> <output_json> [workers]")
            sys.exit(1)
        workers = int(sys.argv[5]) if len(sys.argv) > 5 else 20
        run_active(sys.argv[2], sys.argv[3], sys.argv[4], workers)

    elif mode == "all":
        if len(sys.argv) < 3:
            print("Usage: client_bugs.py all <target_output_dir> [workers]")
            sys.exit(1)
        out = sys.argv[2]
        workers = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        static_json = os.path.join(out, "client_static.json")
        active_json = os.path.join(out, "client_active.json")
        run_static(os.path.join(out, "js_links"), static_json, workers)
        run_active(os.path.join(out, "live_hosts"), os.path.join(out, "params"),
                   active_json, workers)
        merged = _merge([static_json, active_json], os.path.join(out, "client_findings.json"))
        print(f"[client_bugs:all] {len(merged)} total client-side findings "
              f"-> {os.path.join(out, 'client_findings.json')}")
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)


if __name__ == "__main__":
    main()
