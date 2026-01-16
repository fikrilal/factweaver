# Agent-in-the-Loop Memory Extraction Pipeline (ChatGPT Export)

Purpose: distill a large ChatGPT export (`conversations.json`) into a **useful memory base** about the user (identity, interests, projects, constraints, major events), stored locally as:
- `facts.db` (canonical SQLite store)
- `out/me/*.md` (accepted facts only)
- `out/review.md` (`needs_review` queue)

Core principle: **tools handle mechanics; the agent handles meaning**. We do not rely on heuristic scripts to “extract facts”.

## 1) What “done” means

A chunk is **done** when:
- the agent has fully read and verified it, and
- the result (facts or “nothing useful found”) is recorded in `facts.db` via a progress table.

This prevents re-reading and makes runs resumable.

## 2) Artifact layout (local-only; gitignored)

All outputs live under `work/<run-id>/`:
- `messages.jsonl` (normalized transcript, verbatim)
- `messages_view.jsonl` (redacted + trimmed view for safe processing)
- `chunks/chunk_0001.jsonl` … + `chunks/manifest.json`
- `prompts/claims_map/` (per-chunk prompts for the agent; optional)
- `claims/claims_chunk_0001.jsonl` … (agent outputs; can be empty)
- `facts.db` (canonical store + progress table)
- `out/me/*.md` (accepted-only)
- `out/review.md` (needs review)

## 3) Pipeline (tool steps + agent loop)

1) Export messages:
- `python3 tools/pipeline/export_messages.py --input conversations.json --run-dir work/<run-id>`

2) Build the LLM-safe view (redaction + trimming):
- `python3 tools/pipeline/build_view.py --run-dir work/<run-id>`

3) Chunk by token budget:
- `python3 tools/pipeline/chunk_messages.py --run-dir work/<run-id> --max-tokens 180000`

4) (Optional) Generate per-chunk “agent prompts”:
- `python3 tools/pipeline/pack_claim_prompts.py --run-dir work/<run-id>`

5) Agent extraction loop (repeat until all chunks are done):
- pick the next not-done chunk (based on `facts.db` progress)
- read `chunks/chunk_XXXX.jsonl` (or `prompts/claims_map/prompt_chunk_XXXX.md`)
- write `claims/claims_chunk_XXXX.jsonl`:
  - emit only **useful memory**
  - default `status="accepted"`; use `status="needs_review"` if uncertain
  - empty file is allowed (explicitly means “no useful memory here”)
- run:
  - `python3 tools/pipeline/validate_claims.py --run-dir work/<run-id> --overwrite-report`
  - `python3 tools/pipeline/merge_claims.py --run-dir work/<run-id> --overwrite-manifest`

6) Render views (as often as you like):
- `python3 tools/pipeline/render_md.py --run-dir work/<run-id> --overwrite --overwrite-manifest`

## 4) Claim contract (agent output)

The agent writes JSONL where each line is one claim object (see `docs/prompts/claims-map-template.md`).

Key rules:
- Facts are **about the user**, not about ephemeral content.
  - Example: “Asked about AI news repeatedly” ⇒ “Interested in AI world” (keep this), but do not store the news itself.
- “Interests” can be inferred from behavior if there is evidence.
  - Interest threshold: **3+ occurrences ever**. Before threshold, keep `status="needs_review"` or defer.
- Major events only; skip minor day-to-day mood statements unless they recur as a stable pattern.
- Conflicts: keep **only the latest** version for “single-valued” attributes (agent should prefer newer evidence).

## 5) Review workflow

- `out/me/*.md` contains **accepted** facts only.
- `out/review.md` contains `needs_review` facts and any auto-flags that deserve attention.
- Human review (optional): use curation tooling to accept/reject items and keep an audit trail in `facts.db`.

## 6) Safety and privacy

- Never commit exports or artifacts. Everything under `work/` is local-only.
- Redaction happens in `messages_view.jsonl`; evidence quotes in outputs must stay short and redact secrets.
