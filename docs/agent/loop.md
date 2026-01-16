# Agent Loop (Required)

This project is **agent-in-the-loop**: tools manage artifacts and persistence; the agent does semantic extraction.

## Definition of Done (per chunk)

A chunk is **done** only when it has been applied to `facts.db` and recorded in `chunk_progress` (even if no useful memory was found).

## Per-chunk loop

Given a run directory `work/<run-id>/`:

1) Find the next chunk to process:
- `python3 tools/pipeline/status.py --run-dir work/<run-id>`
- If it prints `next chunk: chunk_XXXX`, that is your target.

2) Read the chunk:
- `work/<run-id>/chunks/chunk_XXXX.jsonl` (preferred), or
- `work/<run-id>/prompts/claims_map/prompt_chunk_XXXX.md` (if generated).

3) Write claims (JSONL) to:
- `work/<run-id>/claims/claims_chunk_XXXX.jsonl`

Rules:
- JSONL only (one JSON object per line). No markdown fences, no arrays.
- Empty file is allowed and means “no useful memory in this chunk”.

4) Validate, then merge (this marks the chunk done in `facts.db`):
- `python3 tools/pipeline/validate_claims.py --run-dir work/<run-id> --overwrite-report`
- `python3 tools/pipeline/merge_claims.py --run-dir work/<run-id> --overwrite-manifest`

5) Render views any time:
- `python3 tools/pipeline/render_md.py --run-dir work/<run-id> --overwrite --overwrite-manifest`

## What to extract

Only durable “about the user” memory:
- identity (name/handle/role/company)
- interests (recurring patterns)
- preferences (tools/workflow)
- projects (ongoing work)
- constraints (do-nots)
- major events (high-signal only)
- short-term goals/plans (if stable enough)

Skip ephemeral content (e.g., the news itself). Store what it implies about the user (e.g., repeated interest).

