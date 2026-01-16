# Taxonomy (Recommended Categories)

Use specific categories so facts group cleanly in `out/me/*.md` and “latest-only” logic can keep single-valued fields current.

## Identity (latest-only)

Use these exact categories for current identity fields:
- `identity.name` (latest-only)
- `identity.handle` (latest-only)
- `identity.role` (latest-only)
- `identity.company` (latest-only)

## Preferences

Use prefixes under `preferences.*`:
- `preferences.tools.*` (editor, shell, OS workflow, etc.)
- `preferences.workflow.*` (branching, commit style, review habits, etc.)
- `preferences.communication.*` (how the user prefers responses)
- `preferences.interests` (see below)

## Interests (option B)

- Category: `preferences.interests`
- Structured label: `value` (e.g., `"AI news"`, `"LLM agents"`, `"data engineering"`)

Guidance:
- Only keep interests that recur (threshold: 3+ occurrences ever for `accepted`).
- Store the *interest*, not the ephemeral content that triggered it.

## Projects

Use `projects.*` for ongoing work, repo efforts, and long-lived initiatives:
- `projects.factweaver.*`
- `projects.<other_project>.*`

## Constraints / do-nots

Use `constraints.*` for hard rules the agent must follow:
- `constraints.privacy.*`
- `constraints.workflow.*`

## Major events

Use `events.major.*` for high-signal life/work events only.

## Transient goals

Use `goals.transient` for short-term objectives that may change quickly.

