# FactWeaver

FactWeaver is an **agent-in-the-loop** pipeline for distilling a large ChatGPT export into a local, auditable “memory” knowledge base (SQLite + Markdown views).

Key principle: **tools manage files; the agent decides meaning**. Fact extraction is not a heuristic script—it’s a deliberate per-chunk review step performed by an agent.

## Safety (read first)

- Never commit your export files (`conversations.json`, `shared_conversations.json`) or generated artifacts.
- These are ignored by default via `.gitignore` (`data/`, `chunks/`, `claims/`, `out/`, `facts.db`, etc.).
- Before pushing public, always verify: `git status --ignored` and `git check-ignore -v conversations.json`.
- If you ever accidentally commit secrets or chat exports, assume they’re compromised: remove them from history and rotate credentials.

Optional preflight:
- `python3 tools/dev/doctor.py --verbose`

## Docs

- Pipeline overview: `docs/memory-extraction-pipeline.md`
- Engineering design: `docs/engineering-design.md`
- Agent runbook: `manual/agent/README.md`
- Agent loop + guardrails: `docs/agent/`
- Prompt template (agent uses per chunk): `docs/prompts/claims-map-template.md`
- Output skeletons: `docs/output-skeletons/`

## Tools

Pipeline CLIs live under `tools/pipeline/`.

Typical run (agent-in-the-loop):

```bash
RUN="work/run_$(date -u +%Y%m%d_%H%M%SZ)"
python3 tools/pipeline/export_messages.py --input conversations.json --run-dir "$RUN"
python3 tools/pipeline/build_view.py --run-dir "$RUN"
python3 tools/pipeline/chunk_messages.py --run-dir "$RUN"
python3 tools/pipeline/pack_claim_prompts.py --run-dir "$RUN"

# Agent step:
# - read one chunk at a time
# - write JSONL claims to: $RUN/claims/claims_chunk_XXXX.jsonl (empty file is allowed)
# - then merge to facts.db to mark the chunk done

python3 tools/pipeline/validate_claims.py --run-dir "$RUN" --overwrite-report
python3 tools/pipeline/merge_claims.py --run-dir "$RUN" --overwrite-manifest
python3 tools/pipeline/render_md.py --run-dir "$RUN" --overwrite --overwrite-manifest
python3 tools/pipeline/status.py --run-dir "$RUN"
```

Notes:
- A chunk is considered **done** when it has been applied to `facts.db` (tracked in a progress table), even if it produced no useful memory.
- Rendered “final” views (`out/me/*.md`) contain **accepted** facts only. `out/review.md` is the queue for `needs_review`.
- Latest-only categories are enforced by the merge step: `identity.name`, `identity.handle`, `identity.role`, `identity.company` (older values become `superseded`).

### Token count quickstart

```bash
python3 -m venv .venv
.venv/bin/python -m ensurepip --upgrade
.venv/bin/python -m pip install tiktoken
.venv/bin/python tools/count_tokens.py conversations.json
```
