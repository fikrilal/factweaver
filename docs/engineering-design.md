# FactWeaver Engineering Design (Agent-First)

Status: Draft  
Scope: local ChatGPT exports → chunked transcript → **agent-distilled** memory claims → `facts.db` → deterministic Markdown views

This document defines the *mechanical* system boundaries. Semantic extraction is performed by an agent; tools exist to make that reliable, resumable, and auditable.

## 1) Responsibility boundary

Agent responsibilities (semantic):
- Read one `chunks/chunk_*.jsonl` at a time.
- Decide what is “useful memory” (identity, interests, projects, constraints, major events, plans).
- Emit claim JSONL to `claims/claims_chunk_*.jsonl`.
- Default to `status="accepted"`; use `status="needs_review"` when uncertain.

Tool responsibilities (deterministic):
- Normalize/export (`messages.jsonl`), redact/trim (`messages_view.jsonl`), chunk (`chunks/`).
- Validate claim JSONL schema + safety.
- Merge/dedupe into a canonical SQLite DB (`facts.db`).
- Track per-chunk progress in `facts.db` so the agent never re-reads completed chunks.
- Render Markdown views from `facts.db`.

## 2) Run directory layout (local-only)

All artifacts for a run live under `work/<run-id>/` and are gitignored:
- Transcript: `messages.jsonl`, `messages_view.jsonl`
- Chunks: `chunks/chunk_0001.jsonl` … and `chunks/manifest.json`
- Agent outputs: `claims/claims_chunk_0001.jsonl` …
- Canonical store: `facts.db`
- Rendered views: `out/me/*.md`, `out/review.md`

## 3) Claim schema (contract)

Each line in `claims/claims_chunk_XXXX.jsonl` is a JSON object with:
- `category`: string (taxonomy)
- `fact`: string (atomic, declarative; “about the user”)
- `stability`: `"stable"` | `"transient"`
- `status`: `"accepted"` | `"needs_review"` (agent decision; default accepted)
- `confidence`: number `[0,1]`
- `time`: `{ "as_of_ts": number }` (newest evidence timestamp)
- `evidence`: array of `{ role, quote, conv_id, message_id, ts }` (short, verbatim; redact secrets)
- `derived_from`: `"user"` | `"mixed"` | `"assistant"`
  - `"mixed"` is allowed for inference (e.g., inferred interest) as long as evidence is present.

## 4) Taxonomy (recommended)

Use specific categories so “single-valued” items can be kept latest-only:
- `identity.name`, `identity.handle`
- `preferences.workflow.*` (e.g., `preferences.workflow.commit_policy`)
- `preferences.tools.*` (e.g., `preferences.tools.git`, `preferences.tools.editor`)
- `preferences.interests.*` (e.g., `preferences.interests.ai_news`)
- `projects.*` (repo, system, pipeline, stack)
- `constraints.*` (hard requirements / do-not)
- `events.major.*` (major life/work events)
- `goals.transient` (short-term plans)

Rule: ignore ephemeral content (e.g., “today’s news”). Store *what it implies about the user* (e.g., repeated interest).

Interest rule:
- an inferred interest should have evidence for **3+ occurrences ever** before being accepted; otherwise keep `needs_review` or defer.

## 5) Canonical DB (`facts.db`)

SQLite is the canonical store. It must support:
- incremental merge/dedupe
- evidence joins
- agent decisions (`accepted` vs `needs_review`)
- per-chunk progress

Minimum tables (simplified):
- `facts` (fact text + category + status + timestamps)
- `evidence` (quotes keyed to `fact_id`)
- `claims_raw` (audit log of agent claim lines)
- `chunk_progress` (chunk_id + chunk_sha + done_at + claims_count + note)

Latest-only policy:
- for “single-valued” categories, keep only the newest accepted fact (by evidence timestamp); older accepted facts should be demoted (e.g., marked rejected/superseded) rather than kept as competing truths.

## 6) Rendering

Rendering produces:
- `out/me/*.md`: accepted-only, grouped by category prefix.
- `out/review.md`: `needs_review` items and any auto-flags.

Rendering must be deterministic (stable ordering) for diff-friendly review.

## 7) Operational safety

- No exports or artifacts are committed (enforced by `.gitignore` + `tools/dev/doctor.py`).
- `messages_view.jsonl` performs redaction/trimming; outputs must not contain secrets.
- Validation must fail on secret-like strings in quotes/facts.

## 8) CLI surface

Core pipeline entrypoints:
- `tools/pipeline/export_messages.py`
- `tools/pipeline/build_view.py`
- `tools/pipeline/chunk_messages.py`
- `tools/pipeline/pack_claim_prompts.py` (agent helper)
- `tools/pipeline/validate_claims.py`
- `tools/pipeline/merge_claims.py`
- `tools/pipeline/render_md.py`
- `tools/pipeline/status.py` (agent-friendly progress summary)
