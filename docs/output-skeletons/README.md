# Example Output Skeletons

These files are example “rendered views” the pipeline should generate into:
- `out/me/*.md` (accepted-only)
- `out/review.md` (`needs_review` queue)

They’re intentionally structured for fast human review:
- deterministic sections
- evidence inline (short quotes + IDs)
- clear separation of stable vs transient
- a dedicated `review.md` for `needs_review` items and auto-flags

Files:
- `docs/output-skeletons/identity.md`
- `docs/output-skeletons/preferences.md`
- `docs/output-skeletons/projects.md`
- `docs/output-skeletons/goals.md`
- `docs/output-skeletons/constraints.md`
- `docs/output-skeletons/review.md`
