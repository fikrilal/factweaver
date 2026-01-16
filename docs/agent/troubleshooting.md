# Troubleshooting

## `validate_claims.py` fails

Common causes:
- `format.code_fence`: you included ``` fences. Remove them (JSONL only).
- `schema.*`: missing required fields (`status`, `derived_from`, `time.as_of_ts`, etc.).
- `schema.value.required`: interests require `value`.
- `interest.threshold`: an accepted interest has < 3 distinct user occurrences in evidence.
- `safety.*`: secret-like content detected; replace the sensitive substring with `[REDACTED]`.

Fix the claim file, then re-run:
- `python3 tools/pipeline/validate_claims.py --run-dir work/<run-id> --overwrite-report`

## `merge_claims.py` fails

- If it complains about secrets, you must redact in the claim file and re-run validation.
- If `--require-validation` is on (default), make sure `claims/validation_report.json` exists and has no errors.

Re-run:
- `python3 tools/pipeline/merge_claims.py --run-dir work/<run-id> --overwrite-manifest`

## Chunk shows as “stale”

`status.py` may report `stale>0` when chunk content changed after being marked done.

Recommended recovery:
- Re-process that chunk: regenerate its claims file, then validate + merge again.

## Too many low-signal facts

Tighten extraction:
- Prefer “stable” attributes and recurring patterns.
- Move uncertain items to `needs_review` (don’t guess).
- Drop ephemeral content; keep only what it implies about the user.

