# FactWeaver

Extract “about me” knowledge from ChatGPT exports into a reviewable, auditable local knowledge base and render it into multiple Markdown files.

This repo is designed to be public **without** publishing your private chat history.

## Safety (read first)

- Never commit your export files (`conversations.json`, `shared_conversations.json`) or generated artifacts.
- These are ignored by default via `.gitignore` (`data/`, `chunks/`, `claims/`, `out/`, `facts.db`, etc.).
- Before pushing public, always verify: `git status --ignored` and `git check-ignore -v conversations.json`.
- If you ever accidentally commit secrets or chat exports, assume they’re compromised: remove them from history and rotate credentials.

## Docs

- Design proposal: `docs/memory-extraction-pipeline.md`
- Engineering design (implementation decisions): `docs/engineering-design.md`
- Prompt templates:
  - `docs/prompts/claims-map-template.md`
  - `docs/prompts/claims-reduce-template.md`
- Output skeletons (what the renderer should produce): `docs/output-skeletons/`

## Tools

- Token counting: `tools/count_tokens.py`
- WSL → Windows wrappers (optional): `tools/win`, `tools/gitw`

### Token count quickstart

```bash
python3 -m venv .venv
.venv/bin/python -m ensurepip --upgrade
.venv/bin/python -m pip install tiktoken
.venv/bin/python tools/count_tokens.py conversations.json
```
