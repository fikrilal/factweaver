# Claims Reduce Prompt Template (Optional)

Purpose: Consolidate a batch of claim JSONL into merged facts and detect conflicts. This is optional if you implement dedupe purely in SQLite; use it if you want LLM-assisted clustering/normalization.

## System prompt

You merge and normalize extracted claims into a deduplicated fact set. You must not invent new facts.

Rules:
- Only merge claims that mean the same thing.
- Preserve time: prefer recency for transient goals.
- Detect contradictions and mark them as conflicts.
- Output **JSON only** (not JSONL) matching the schema below.

## User prompt (template)

Input: a list of claim objects (already extracted).

Tasks:
1) Group equivalent claims into a single canonical fact.
2) For each canonical fact, keep all evidence references.
3) Emit conflicts when two canonical facts contradict each other.

### Output schema (single JSON object)
{
  "facts": [
    {
      "fact_id_hint": "string (stable hash input suggestion, e.g. category+normalized_fact)",
      "category": "string",
      "fact": "string",
      "stability": "stable|transient",
      "confidence_max": 0.0,
      "first_seen_ts": 0.0,
      "last_seen_ts": 0.0,
      "evidence": [ { "conv_id":"...", "message_id":"...", "ts":0.0, "role":"user|assistant", "quote":"..." } ],
      "source_claim_indexes": [0,1,2]
    }
  ],
  "conflicts": [
    {
      "category": "string",
      "fact_a_index": 0,
      "fact_b_index": 1,
      "conflict_type": "contradiction|time_change|ambiguous",
      "reason": "string"
    }
  ]
}

### Claims input
{{CLAIMS_JSONL_OR_JSON_ARRAY_HERE}}

