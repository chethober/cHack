# AI Skills

Each `*.skill.md` file here is a prompt template used by `ai_assistant.py`
(the BYOK AI review layer — see `../README.md` → "BYOK AI Assistant").

## Format

```markdown
---
name: triage_findings
title: Findings Triage
description: One line shown by `ai_assistant.py skills`
requires_kb: true
---
<system prompt body — may use {context} and {kb_context} placeholders>
```

- `{context}` is replaced with the compact JSON report for the target
  (`db_sqlite.generate_report()` — findings, secrets, services, endpoints).
- `{kb_context}` is replaced with methodology notes pulled from your own
  knowledge-base repo (see `AI_KB_PATH` in `.env.example`), when
  `requires_kb: true` and the user passes `--kb`.

## Scope

These skills are triage/analysis aids for data your own pipeline already
collected on in-scope, authorized targets. They summarize, prioritize, and
point to the next manual-verification step — they never ask the model to
generate exploit payloads or attack code; that's what your KB's payload
sheets and your own judgment are for.

## Adding a skill

Drop a new `<name>.skill.md` file here following the format above. It's
picked up automatically — no code changes needed. List available skills
with:

```
python3 ai_assistant.py skills
```
