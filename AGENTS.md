# Repository Guidelines

FactWeaver is an **agent-in-the-loop** pipeline: tools manage artifacts; the agent performs semantic extraction.

## Project Structure

- `docs/`: pipeline + engineering design docs, prompt templates, output skeletons.
- `tools/pipeline/`: deterministic CLIs (export, view, chunk, validate, merge, render, status).
- `tools/dev/`: safety/diagnostics (e.g., `doctor.py`).
- Local-only artifacts (gitignored): `conversations.json`, `shared_conversations.json`, `work/`, `facts.db`, `chunks/`, `claims/`, `out/`.

## Development Commands

Typical run (agent-first):
- `python3 tools/pipeline/export_messages.py --input conversations.json --run-dir work/<run-id>`
- `python3 tools/pipeline/build_view.py --run-dir work/<run-id>`
- `python3 tools/pipeline/chunk_messages.py --run-dir work/<run-id>`
- `python3 tools/pipeline/pack_claim_prompts.py --run-dir work/<run-id>`
- Agent reads `chunks/chunk_*.jsonl` and writes `claims/claims_chunk_*.jsonl` (empty file allowed).
- `python3 tools/pipeline/validate_claims.py --run-dir work/<run-id> --overwrite-report`
- `python3 tools/pipeline/merge_claims.py --run-dir work/<run-id>`
- `python3 tools/pipeline/render_md.py --run-dir work/<run-id> --overwrite`
- `python3 tools/pipeline/status.py --run-dir work/<run-id>`

Safety preflight:
- `python3 tools/dev/doctor.py --verbose`

## Coding Style

- Python: 4-space indentation, PEP 8 naming.
- Prefer type hints and small, composable functions. Keep I/O explicit (no hidden globals).
- Keep outputs deterministic (stable ordering + stable hashing for manifests/IDs).

## Testing

- No test suite yet. If adding tests, use `pytest` under `tests/` (`test_*.py`).
- Prioritize tests for: JSONL parsing, redaction, chunk boundaries, merge/dedupe, and progress tracking.

## Commits & PRs

- Do not commit exports or run artifacts. Verify before pushing:
  - `git status --ignored`
  - `git check-ignore -v conversations.json`
- PRs should describe: what changed, how to run locally, and any updates to `.gitignore`.

## Security & Privacy

- Assume all exports contain sensitive material. Redact in `messages_view.jsonl` and keep evidence quotes short.
- If secrets ever land in git history, treat them as compromised and rotate/remove from history.
