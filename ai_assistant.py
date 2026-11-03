#!/usr/bin/env python3
"""
BYOK AI Assistant for cHack — authorized-use only.

Bring-your-own-key LLM layer that helps a human analyst triage cHack's own
stored scan data (findings, secrets, services, endpoints) faster. It never
runs scans or generates exploit payloads itself: it reads what the recon
pipeline already collected for an in-scope target, optionally grounds the
review in the analyst's own knowledge-base notes, and asks the configured
model to summarize / prioritize / point to the next manual-verification
step.

Configuration (env vars, normally set in .env and sourced by cHack.sh):

    AI_PROVIDER   anthropic (default) | openai | generic
    AI_API_KEY    your own API key for that provider (BYOK — never shipped
                  with cHack, never phoned home anywhere but the provider
                  you configure)
    AI_MODEL      model id (sensible per-provider default if unset)
    AI_BASE_URL   override endpoint (required for provider=generic, i.e.
                  any OpenAI-compatible endpoint: local model server,
                  self-hosted gateway, etc.)
    AI_KB_PATH    path to your own knowledge-base repo (e.g. a local clone
                  of your personal vuln-notes vault) used for grounding
                  skills that set requires_kb: true

Usage:
    python3 ai_assistant.py skills
    python3 ai_assistant.py review <domain_or_slug> [--skill NAME] [--kb] [--kb-payloads] [--save]
    python3 ai_assistant.py history <domain_or_slug> [--limit N]
"""
import argparse
import glob
import json
import os
import sys
import urllib.error
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.join(SCRIPT_DIR, "ai_skills")

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5-5",
    "openai": "gpt-5",
    "generic": "",
}

# Maps cHack's `vuln_type` finding values to a knowledge-base note filename
# (relative to AI_KB_PATH/Vulns/). Extend as your own KB's taxonomy grows.
VULN_TYPE_TO_KB_NOTE = {
    "xss": "XSS", "dom_xss": "XSS",
    "sqli": "SQLi", "sql_injection": "SQLi", "nosql": "NoSQL", "nosqli": "NoSQL",
    "cors": "CORS", "ssrf": "SSRF", "ssti": "SSTI", "xxe": "XXE",
    "csrf": "CSRF", "clickjacking": "Clickjacking",
    "idor": "AccessControl", "access_control": "AccessControl", "bac": "AccessControl",
    "auth": "Authentication", "authentication": "Authentication",
    "jwt": "JWT", "graphql": "GraphQL", "api": "API",
    "prototype_pollution": "PrototypePollution",
    "command_injection": "CommandInjection", "rce": "CommandInjection",
    "path_traversal": "PathTraversal", "lfi": "PathTraversal",
    "file_upload": "FileUpload",
    "request_smuggling": "RequestSmuggling",
    "cache_poisoning": "WebCachePoisoning", "cache_deception": "WebCacheDeception",
    "deserialization": "InsecureDeserialization",
    "websocket": "WebSockets", "websockets": "WebSockets",
    "race_condition": "RaceConditions", "race": "RaceConditions",
    "business_logic": "BusinessLogic",
    "secret": "InformationDisclosure", "exposure": "InformationDisclosure",
    "info_disclosure": "InformationDisclosure",
    "dos": "DoS", "webllm": "WebLLM", "llm": "WebLLM",
}

# KB note sections considered "methodology" (safe default context): overview,
# attack-vector explanation, impact, remediation, testing checklist. Payload
# dictionaries are excluded unless --kb-payloads is passed explicitly, since
# that content is denser/more sensitive to ship to a third-party API.
_SAFE_SECTION_PREFIXES = (
    "## 1.", "## 2.", "## 5.", "## 6.", "## 7.",
)
_PAYLOAD_SECTION_PREFIXES = ("## 4.", "## 8.")


def _load_env_file():
    """Best-effort .env loader so `python3 ai_assistant.py ...` works even
    when invoked directly (cHack.sh already sources .env for its own calls)."""
    env_path = os.path.join(SCRIPT_DIR, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def list_skills():
    skills = []
    for path in sorted(glob.glob(os.path.join(SKILLS_DIR, "*.skill.md"))):
        meta, _ = _parse_skill_file(path)
        skills.append(meta)
    return skills


def _parse_skill_file(path):
    with open(path) as f:
        raw = f.read()
    meta = {"name": os.path.basename(path).replace(".skill.md", ""),
            "title": "", "description": "", "requires_kb": False}
    body = raw
    if raw.startswith("---"):
        end = raw.find("\n---", 3)
        if end != -1:
            frontmatter = raw[3:end].strip()
            body = raw[end + 4:].lstrip("\n")
            for line in frontmatter.splitlines():
                if ":" not in line:
                    continue
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k == "requires_kb":
                    meta[k] = v.lower() in ("true", "yes", "1")
                else:
                    meta[k] = v
    return meta, body


def load_skill(name):
    path = os.path.join(SKILLS_DIR, f"{name}.skill.md")
    if not os.path.exists(path):
        available = ", ".join(s["name"] for s in list_skills())
        raise SystemExit(f"Unknown skill '{name}'. Available: {available}")
    return _parse_skill_file(path)


def build_context(domain_or_slug, max_findings=60, max_secrets=40, max_endpoints=30):
    """Pull the target's own stored report via db_sqlite and trim it to a
    size reasonable to hand to an LLM in one call."""
    sys.path.insert(0, SCRIPT_DIR)
    import db_sqlite  # local import: reuses cHack's existing report builder

    report = db_sqlite.generate_report(domain_or_slug)
    if report.get("target") is None:
        raise SystemExit(f"No stored target found for '{domain_or_slug}'. "
                          f"Run a scan / --sync first.")

    report["findings"] = report["findings"][:max_findings]
    report["secrets"] = report["secrets"][:max_secrets]
    report["endpoints"] = report["endpoints"][:max_endpoints]
    return report


def _kb_note_path(kb_path, note_name):
    for ext_dir in ("Vulns",):
        candidate = os.path.join(kb_path, ext_dir, f"{note_name}.md")
        if os.path.exists(candidate):
            return candidate
    return None


def _strip_frontmatter(md_text):
    if md_text.startswith("---"):
        end = md_text.find("\n---", 3)
        if end != -1:
            return md_text[end + 4:].lstrip("\n")
    return md_text


def _extract_safe_sections(md_text, include_payloads=False):
    lines = _strip_frontmatter(md_text).splitlines()
    out, keep = [], True  # keep the frontmatter/intro before the first "## "
    for line in lines:
        if line.startswith("## "):
            is_payload = line.startswith(_PAYLOAD_SECTION_PREFIXES)
            keep = include_payloads or not is_payload
            if not include_payloads and is_payload:
                continue
        if keep:
            out.append(line)
    return "\n".join(out).strip()


def kb_context_for_report(report, kb_path, include_payloads=False, max_chars=6000):
    """Pull the relevant knowledge-base note(s) for the vuln types present
    in a report, trimmed to methodology/checklist content by default."""
    if not kb_path or not os.path.isdir(kb_path):
        return "(no knowledge base configured — set AI_KB_PATH to your notes repo path)"

    vuln_types = {f.get("vuln_type", "").lower() for f in report.get("findings", [])}
    note_names = sorted({VULN_TYPE_TO_KB_NOTE[v] for v in vuln_types if v in VULN_TYPE_TO_KB_NOTE})

    if not note_names:
        return "(no matching knowledge-base notes for the vuln types in this report)"

    chunks = []
    for note in note_names:
        path = _kb_note_path(kb_path, note)
        if not path:
            continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            text = f.read()
        snippet = _extract_safe_sections(text, include_payloads=include_payloads)
        chunks.append(f"### {note}\n{snippet}")

    combined = "\n\n".join(chunks)
    if len(combined) > max_chars:
        combined = combined[:max_chars] + "\n...(truncated)"
    return combined or "(matching notes found but could not be read)"


def _call_anthropic(api_key, model, system, user, base_url=None):
    url = (base_url or "https://api.anthropic.com") + "/v1/messages"
    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode())
    return "".join(block.get("text", "") for block in data.get("content", []))


def _call_openai_compatible(api_key, model, system, user, base_url=None):
    url = (base_url or "https://api.openai.com/v1") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode())
    return data["choices"][0]["message"]["content"]


def call_llm(system_prompt, user_prompt):
    _load_env_file()
    provider = os.environ.get("AI_PROVIDER", "anthropic").lower()
    api_key = os.environ.get("AI_API_KEY", "")
    if not api_key:
        raise SystemExit(
            "AI_API_KEY is not set. This is BYOK: put your own provider API "
            "key in .env (AI_API_KEY=...) — cHack never ships or proxies a key."
        )
    model = os.environ.get("AI_MODEL") or DEFAULT_MODELS.get(provider, "")
    base_url = os.environ.get("AI_BASE_URL") or None

    try:
        if provider == "anthropic":
            return _call_anthropic(api_key, model, system_prompt, user_prompt, base_url)
        elif provider in ("openai", "generic"):
            if provider == "generic" and not base_url:
                raise SystemExit("AI_PROVIDER=generic requires AI_BASE_URL.")
            return _call_openai_compatible(api_key, model, system_prompt, user_prompt, base_url)
        else:
            raise SystemExit(f"Unknown AI_PROVIDER '{provider}' (use anthropic | openai | generic).")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")
        raise SystemExit(f"AI provider returned HTTP {e.code}: {body[:500]}")
    except urllib.error.URLError as e:
        raise SystemExit(f"Could not reach AI provider ({base_url or provider}): {e}")


def run_skill(domain_or_slug, skill_name, use_kb=False, kb_payloads=False):
    meta, prompt_template = load_skill(skill_name)
    report = build_context(domain_or_slug)

    kb_text = ""
    if meta.get("requires_kb") and use_kb:
        kb_path = os.environ.get("AI_KB_PATH", "")
        kb_text = kb_context_for_report(report, kb_path, include_payloads=kb_payloads)
    elif meta.get("requires_kb") and not use_kb:
        kb_text = "(knowledge-base context not requested — pass --kb to include it)"

    user_prompt = prompt_template.format(
        context=json.dumps(report, indent=2, default=str),
        kb_context=kb_text,
    )
    system_prompt = (
        "You are an authorized-use security triage assistant embedded in the "
        "cHack recon platform. Only ever analyze data the user's own tooling "
        "already collected on their own in-scope targets; never produce new "
        "exploit payloads or instructions to attack out-of-scope systems."
    )
    output = call_llm(system_prompt, user_prompt)
    return meta, report, output


def save_review(domain_or_slug, skill_name, output):
    sys.path.insert(0, SCRIPT_DIR)
    import db_sqlite
    model = os.environ.get("AI_MODEL") or DEFAULT_MODELS.get(
        os.environ.get("AI_PROVIDER", "anthropic").lower(), "")
    return db_sqlite.save_ai_review(domain_or_slug, skill_name, model, output)


def main():
    parser = argparse.ArgumentParser(description="cHack BYOK AI assistant")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("skills", help="List available AI skills")

    p_review = sub.add_parser("review", help="Run an AI skill against a stored target report")
    p_review.add_argument("target")
    p_review.add_argument("--skill", default="triage_findings")
    p_review.add_argument("--kb", action="store_true", help="Include knowledge-base context")
    p_review.add_argument("--kb-payloads", action="store_true",
                           help="Also include the KB's payload-dictionary sections (sent to the configured AI provider)")
    p_review.add_argument("--save", action="store_true", help="Store the output in local.db")

    p_hist = sub.add_parser("history", help="Show past AI reviews for a target")
    p_hist.add_argument("target")
    p_hist.add_argument("--limit", type=int, default=10)

    args = parser.parse_args()

    if args.cmd == "skills":
        for s in list_skills():
            kb = " [needs --kb]" if s.get("requires_kb") else ""
            print(f"{s['name']:<20} {s.get('description','')}{kb}")
        return

    if args.cmd == "review":
        meta, _report, output = run_skill(args.target, args.skill, args.kb, args.kb_payloads)
        print(f"\n=== {meta.get('title', args.skill)} — {args.target} ===\n")
        print(output)
        if args.save:
            save_review(args.target, args.skill, output)
            print("\n[saved to local.db — see `ai_assistant.py history`]")
        return

    if args.cmd == "history":
        sys.path.insert(0, SCRIPT_DIR)
        import db_sqlite
        for row in db_sqlite.get_ai_reviews(args.target, args.limit):
            print(f"[{row['created_at']}] {row['skill']} ({row['model']})")
            print(row["output"])
            print("-" * 60)


if __name__ == "__main__":
    main()
