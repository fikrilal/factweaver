# Repository Guidelines

## Project Structure & Module Organization

- `docs/`: architecture/design docs, prompt templates, and Markdown output skeletons.
- `tools/`: small scripts and wrappers (kept dependency-light).
  - `tools/count_tokens.py`: token counter for large exports.
  - `tools/win`, `tools/gitw`: WSL → Windows command wrappers (useful when the repo lives under `/mnt/c/...`).
- Local-only artifacts (gitignored): `conversations.json`, `shared_conversations.json`, `messages*.jsonl`, `chunks/`, `claims/`, `out/`, `facts.db`, `work/`.

## Build, Test, and Development Commands

- Token counting (requires `tiktoken`):
  - `python3 -m venv .venv && .venv/bin/python -m pip install -U pip tiktoken`
  - `.venv/bin/python tools/count_tokens.py conversations.json`
- Windows toolchain from WSL:
  - `bash tools/win <command> [args...]` (runs in Windows PowerShell from repo root)
  - `bash tools/gitw status` / `bash tools/gitw push`

## Coding Style & Naming Conventions

- Python: 4-space indentation, PEP 8 naming (`snake_case` for files/functions, `PascalCase` for classes).
- Prefer type hints and small, composable functions. Avoid “magic” defaults; make I/O paths explicit.
- Determinism matters: stable ordering and stable hashing for manifests/IDs.

## Testing Guidelines

- No test suite is established yet. If you add one, use `pytest` and place tests under `tests/` with `test_*.py`.
- Add tests for parsing/normalization, redaction, chunking boundaries, and SQLite merge/dedupe behavior.

## Commit & Pull Request Guidelines

- Commit messages in history are short and imperative (e.g., “Initial commit”); follow that style.
- Before opening a PR, verify no personal data is staged:
  - `git status --ignored`
  - `git check-ignore -v conversations.json`
- PRs should include: what changed, how to run it locally, and any new artifact paths added to `.gitignore`.

## Security & Privacy Notes

- Never commit raw exports or generated artifacts. If secrets are ever committed, treat them as compromised and rotate/remove from history.
