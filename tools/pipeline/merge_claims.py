#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any, Iterable


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()

def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _normalize_fact_text(text: str) -> str:
    # Conservative normalization: collapse whitespace and casefold for stable hashing.
    collapsed = re.sub(r"\s+", " ", text.strip())
    return collapsed.casefold()


def _atomic_write_text(path: Path, text: str, *, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(str(path))

    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9-]{10,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b")),
    (
        "authorization_bearer",
        re.compile(
            r"(?i)\bAuthorization\s*:\s*Bearer\s+(?!\[REDACTED\])[A-Za-z0-9\-._~+/]+=*"
        ),
    ),
]

SECRET_KV_PATTERN = re.compile(
    r"(?i)\b(api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|passwd|pwd)\b(\s*[:=]\s*)([^\s'\"\\]+)"
)


def _looks_high_entropy(value: str) -> bool:
    if value == "[REDACTED]":
        return False
    if len(value) < 20:
        return False
    if re.fullmatch(r"[A-Za-z0-9+/_\-=]{20,}", value):
        return True
    return False


def _scan_for_secrets(text: str) -> list[str]:
    hits: list[str] = []
    for code, pat in SECRET_PATTERNS:
        if pat.search(text):
            hits.append(code)

    for m in SECRET_KV_PATTERN.finditer(text):
        value = m.group(3)
        if value == "[REDACTED]" or "[REDACTED]" in value:
            continue
        if _looks_high_entropy(value):
            hits.append("secret_kv_high_entropy")
            break

    return hits


@dataclass
class MergeStats:
    claim_lines: int = 0
    claim_objects: int = 0
    claims_raw_inserted: int = 0
    facts_inserted: int = 0
    facts_updated: int = 0
    evidence_inserted: int = 0
    fact_claim_links: int = 0
    review_flags_inserted: int = 0


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS claims_raw (
  claim_id TEXT PRIMARY KEY,
  source_path TEXT NOT NULL,
  source_line INTEGER NOT NULL,
  chunk_id TEXT,
  claim_json TEXT NOT NULL,
  imported_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS facts (
  fact_id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  fact_text TEXT NOT NULL,
  normalized_fact_text TEXT NOT NULL,
  stability TEXT NOT NULL,
  first_seen_ts REAL,
  last_seen_ts REAL,
  confidence_max REAL NOT NULL,
  status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_facts_category ON facts(category);
CREATE INDEX IF NOT EXISTS idx_facts_status ON facts(status);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  fact_id TEXT NOT NULL,
  conv_id TEXT NOT NULL,
  message_id TEXT NOT NULL,
  ts REAL,
  role TEXT NOT NULL,
  quote TEXT NOT NULL,
  quote_hash TEXT NOT NULL,
  FOREIGN KEY(fact_id) REFERENCES facts(fact_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_fact ON evidence(fact_id);

CREATE TABLE IF NOT EXISTS fact_claims (
  fact_id TEXT NOT NULL,
  claim_id TEXT NOT NULL,
  PRIMARY KEY(fact_id, claim_id),
  FOREIGN KEY(fact_id) REFERENCES facts(fact_id) ON DELETE CASCADE,
  FOREIGN KEY(claim_id) REFERENCES claims_raw(claim_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS review_flags (
  flag_id TEXT PRIMARY KEY,
  fact_id TEXT NOT NULL,
  flag_type TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at REAL NOT NULL,
  FOREIGN KEY(fact_id) REFERENCES facts(fact_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_review_flags_fact ON review_flags(fact_id);

CREATE TABLE IF NOT EXISTS chunk_progress (
  chunk_id TEXT PRIMARY KEY,
  chunk_sha256 TEXT NOT NULL,
  claims_path TEXT NOT NULL,
  claims_sha256 TEXT NOT NULL,
  claims_objects INTEGER NOT NULL,
  done_at REAL NOT NULL,
  note TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chunk_progress_done_at ON chunk_progress(done_at);
"""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
        ("schema_version", "1"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
        ("created_at", _now_utc_iso()),
    )


def _load_validation_report(report_path: Path) -> dict[str, Any]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("validation report must be a JSON object")
    return data


def _validation_has_errors(report: dict[str, Any]) -> bool:
    summaries = report.get("summaries")
    if isinstance(summaries, list):
        for s in summaries:
            if isinstance(s, dict) and isinstance(s.get("errors"), int) and s["errors"] > 0:
                return True
    issues = report.get("issues")
    if isinstance(issues, list):
        for i in issues:
            if isinstance(i, dict) and i.get("level") == "error":
                return True
    return False


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _load_final_decision_cutoffs(conn: sqlite3.Connection) -> dict[str, float]:
    # fact_id -> latest decided_at timestamp for accepted/rejected decisions.
    rows = conn.execute(
        """
        SELECT fact_id, MAX(decided_at) AS decided_at
        FROM fact_reviews
        WHERE new_status IN ('accepted', 'rejected')
        GROUP BY fact_id
        """
    ).fetchall()
    out: dict[str, float] = {}
    for fact_id, decided_at in rows:
        if isinstance(fact_id, str) and isinstance(decided_at, (int, float)):
            out[fact_id] = float(decided_at)
    return out


def discover_claim_files(run_dir: Path) -> list[Path]:
    claims_dir = run_dir / "claims"
    if not claims_dir.is_dir():
        return []
    return sorted(claims_dir.glob("claims_chunk_*.jsonl"))


def _chunk_id_from_claim_path(path: Path) -> str | None:
    # claims_chunk_0001.jsonl -> chunk_0001
    m = re.match(r"^claims_(chunk_\d{4})$", path.stem)
    if not m:
        return None
    return m.group(1)


def _status_from_claim(claim: dict[str, Any]) -> str:
    """
    Agent-first policy:
    - Agent sets `status` explicitly.
    - Default to accepted if missing/invalid (validation should catch it, but keep merge robust).
    """
    status = claim.get("status")
    if isinstance(status, str):
        status = status.strip()
    else:
        status = None
    return status if status in {"accepted", "needs_review"} else "accepted"


def merge_claims(
    *,
    conn: sqlite3.Connection,
    run_dir: Path,
    claim_paths: Iterable[Path],
    exclusive_categories: list[str],
    exclusive_conflict_min_conf: float,
    final_decision_cutoff_ts: dict[str, float],
    stats: MergeStats,
) -> None:
    cur = conn.cursor()

    for claim_path in claim_paths:
        before_objects = stats.claim_objects
        chunk_id = _chunk_id_from_claim_path(claim_path)
        source_path = claim_path.as_posix()
        claims_sha256 = _sha256_path(claim_path)

        with claim_path.open("r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                stats.claim_lines += 1
                if not raw_line.strip():
                    continue

                # Strict JSONL: each line is a JSON object.
                try:
                    claim = json.loads(raw_line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{source_path}:{line_no}: invalid JSON: {e.msg}") from e

                if not isinstance(claim, dict):
                    raise ValueError(f"{source_path}:{line_no}: expected JSON object per line")

                stats.claim_objects += 1

                # Defense-in-depth: refuse secrets even if validation was skipped.
                candidate_texts: list[str] = []
                for key in ("fact", "notes"):
                    v = claim.get(key)
                    if isinstance(v, str) and v:
                        candidate_texts.append(v)
                ev = claim.get("evidence")
                if isinstance(ev, list):
                    for item in ev:
                        if isinstance(item, dict) and isinstance(item.get("quote"), str):
                            candidate_texts.append(item["quote"])

                for t in candidate_texts:
                    hits = _scan_for_secrets(t)
                    if hits:
                        raise ValueError(
                            f"{source_path}:{line_no}: secret-like content detected ({', '.join(hits)}). "
                            "Redact it and re-run validate_claims."
                        )

                category = claim.get("category")
                fact_text = claim.get("fact")
                stability = claim.get("stability")
                confidence = claim.get("confidence")
                time_obj = claim.get("time")
                derived_from = claim.get("derived_from")
                desired_status = _status_from_claim(claim)
                if derived_from == "assistant" and desired_status == "accepted":
                    # Validation should have caught this; keep merge robust.
                    desired_status = "needs_review"

                if not isinstance(category, str) or not category.strip():
                    raise ValueError(f"{source_path}:{line_no}: missing/invalid category")
                if not isinstance(fact_text, str) or not fact_text.strip():
                    raise ValueError(f"{source_path}:{line_no}: missing/invalid fact")
                if stability not in {"stable", "transient"}:
                    raise ValueError(f"{source_path}:{line_no}: missing/invalid stability")
                if not isinstance(confidence, (int, float)):
                    raise ValueError(f"{source_path}:{line_no}: missing/invalid confidence")
                if derived_from not in {"user", "assistant", "mixed"}:
                    raise ValueError(f"{source_path}:{line_no}: missing/invalid derived_from")
                as_of_ts: float | None = None
                if isinstance(time_obj, dict) and isinstance(time_obj.get("as_of_ts"), (int, float)):
                    as_of_ts = float(time_obj["as_of_ts"])

                normalized = _normalize_fact_text(fact_text)
                fact_id = _sha256_str(category + "\n" + normalized)

                claim_canonical = _canonical_json(claim)
                claim_id = _sha256_str(claim_canonical)

                imported_at = time.time()
                cur.execute(
                    """
                    INSERT OR IGNORE INTO claims_raw(claim_id, source_path, source_line, chunk_id, claim_json, imported_at)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (claim_id, source_path, line_no, chunk_id, claim_canonical, imported_at),
                )
                claim_is_new = cur.rowcount == 1
                if claim_is_new:
                    stats.claims_raw_inserted += 1

                # Upsert facts.
                row = cur.execute(
                    "SELECT fact_text, stability, first_seen_ts, last_seen_ts, confidence_max, status FROM facts WHERE fact_id=?",
                    (fact_id,),
                ).fetchone()

                if row is None:
                    cur.execute(
                        """
                        INSERT INTO facts(
                          fact_id, category, fact_text, normalized_fact_text, stability,
                          first_seen_ts, last_seen_ts, confidence_max, status
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            fact_id,
                            category,
                            fact_text.strip(),
                            normalized,
                            stability,
                            as_of_ts,
                            as_of_ts,
                            float(confidence),
                            desired_status,
                        ),
                    )
                    stats.facts_inserted += 1
                else:
                    existing_fact_text, existing_stability, first_seen, last_seen, conf_max, existing_status = row

                    new_first = first_seen
                    new_last = last_seen
                    if as_of_ts is not None:
                        if new_first is None or as_of_ts < float(new_first):
                            new_first = as_of_ts
                        if new_last is None or as_of_ts > float(new_last):
                            new_last = as_of_ts

                    new_conf_max = max(float(conf_max), float(confidence)) if conf_max is not None else float(confidence)

                    # Prefer the most recent fact_text when timestamps are present.
                    updated_fact_text = existing_fact_text
                    if as_of_ts is not None:
                        if last_seen is None or as_of_ts >= float(last_seen):
                            updated_fact_text = fact_text.strip()
                    elif not isinstance(existing_fact_text, str) or not existing_fact_text.strip():
                        updated_fact_text = fact_text.strip()

                    # Human decisions in facts.db are authoritative:
                    # - accepted facts stay accepted
                    # - rejected facts stay rejected unless new evidence arrives after the rejection
                    decision_cutoff = final_decision_cutoff_ts.get(fact_id)
                    reopen_rejected = (
                        existing_status == "rejected"
                        and decision_cutoff is not None
                        and claim_is_new
                        and imported_at > float(decision_cutoff)
                    )
                    hold_status = existing_status in {"accepted", "rejected"} and not reopen_rejected

                    if hold_status:
                        new_status = existing_status
                    elif existing_status == "needs_review":
                        # Agent can promote to accepted when confident.
                        new_status = desired_status
                    else:
                        new_status = desired_status

                    if reopen_rejected:
                        new_status = "needs_review"
                        flag_id = _sha256_str(f"{fact_id}\nreopened_after_new_evidence")
                        cur.execute(
                            """
                            INSERT OR IGNORE INTO review_flags(flag_id, fact_id, flag_type, detail, created_at)
                            VALUES(?, ?, ?, ?, ?)
                            """,
                            (
                                flag_id,
                                fact_id,
                                "reopened_after_new_evidence",
                                f"decided_at={decision_cutoff}, imported_at={imported_at}",
                                imported_at,
                            ),
                        )
                        if cur.rowcount == 1:
                            stats.review_flags_inserted += 1

                    merged_stability = existing_stability
                    if existing_stability != stability:
                        merged_stability = "transient"
                        flag_id = _sha256_str(f"{fact_id}\nstability_change")
                        cur.execute(
                            """
                            INSERT OR IGNORE INTO review_flags(flag_id, fact_id, flag_type, detail, created_at)
                            VALUES(?, ?, ?, ?, ?)
                            """,
                            (
                                flag_id,
                                fact_id,
                                "stability_change",
                                f"existing={existing_stability}, incoming={stability}",
                                imported_at,
                            ),
                        )
                        if cur.rowcount == 1:
                            stats.review_flags_inserted += 1

                    if (
                        updated_fact_text != existing_fact_text
                        or merged_stability != existing_stability
                        or new_first != first_seen
                        or new_last != last_seen
                        or new_conf_max != conf_max
                        or new_status != existing_status
                    ):
                        cur.execute(
                            """
                            UPDATE facts
                            SET fact_text=?,
                                stability=?,
                                first_seen_ts=?,
                                last_seen_ts=?,
                                confidence_max=?,
                                status=?
                            WHERE fact_id=?
                            """,
                            (
                                updated_fact_text,
                                merged_stability,
                                new_first,
                                new_last,
                                new_conf_max,
                                new_status,
                                fact_id,
                            ),
                        )
                        stats.facts_updated += 1

                # Insert evidence + link claim to fact.
                evidence = claim.get("evidence")
                if not isinstance(evidence, list) or not evidence:
                    # Validation should have caught this, but keep merge robust.
                    continue

                for item in evidence:
                    if not isinstance(item, dict):
                        continue

                    role = item.get("role")
                    quote = item.get("quote")
                    conv_id = item.get("conv_id")
                    message_id = item.get("message_id")
                    ts = item.get("ts")

                    if role not in {"user", "assistant"}:
                        continue
                    if not isinstance(quote, str) or not quote.strip():
                        continue
                    if not isinstance(conv_id, str) or not conv_id.strip():
                        continue
                    if not isinstance(message_id, str) or not message_id.strip():
                        continue

                    ts_out: float | None
                    if isinstance(ts, (int, float)):
                        ts_out = float(ts)
                    else:
                        ts_out = None

                    quote_hash = _sha256_str(quote)
                    evidence_id = _sha256_str(
                        f"{fact_id}\n{conv_id}\n{message_id}\n{role}\n{quote_hash}"
                    )

                    cur.execute(
                        """
                        INSERT OR IGNORE INTO evidence(
                          evidence_id, fact_id, conv_id, message_id, ts, role, quote, quote_hash
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            evidence_id,
                            fact_id,
                            conv_id,
                            message_id,
                            ts_out,
                            role,
                            quote,
                            quote_hash,
                        ),
                    )
                    if cur.rowcount == 1:
                        stats.evidence_inserted += 1

                cur.execute(
                    "INSERT OR IGNORE INTO fact_claims(fact_id, claim_id) VALUES(?, ?)",
                    (fact_id, claim_id),
                )
                if cur.rowcount == 1:
                    stats.fact_claim_links += 1

        # Mark chunk as done in facts.db once this claims file has been applied.
        if chunk_id is not None:
            chunk_path = run_dir / "chunks" / f"{chunk_id}.jsonl"
            chunk_sha256 = _sha256_path(chunk_path) if chunk_path.is_file() else ""
            claims_objects = stats.claim_objects - before_objects
            done_at = time.time()
            note = "empty" if claims_objects == 0 else "ok"
            cur.execute(
                """
                INSERT INTO chunk_progress(
                  chunk_id, chunk_sha256, claims_path, claims_sha256, claims_objects, done_at, note
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_id) DO UPDATE SET
                  chunk_sha256=excluded.chunk_sha256,
                  claims_path=excluded.claims_path,
                  claims_sha256=excluded.claims_sha256,
                  claims_objects=excluded.claims_objects,
                  done_at=excluded.done_at,
                  note=excluded.note
                """,
                (
                    chunk_id,
                    chunk_sha256,
                    source_path,
                    claims_sha256,
                    int(claims_objects),
                    float(done_at),
                    note,
                ),
            )

    # Exclusive category conflict detection (simple heuristic).
    if exclusive_categories:
        for category in exclusive_categories:
            rows = cur.execute(
                """
                SELECT fact_id, fact_text, confidence_max, status
                FROM facts
                WHERE category=? AND status != 'rejected' AND stability='stable' AND confidence_max >= ?
                ORDER BY confidence_max DESC, last_seen_ts DESC
                """,
                (category, exclusive_conflict_min_conf),
            ).fetchall()

            if len(rows) <= 1:
                continue

            # Flag all facts in this category.
            fact_summaries = [f"{r[0]}:{r[1]}" for r in rows]
            detail = f"category has {len(rows)} competing stable facts >= {exclusive_conflict_min_conf}: " + " | ".join(
                fact_summaries[:5]
            )
            for fact_id, _, _, status in rows:
                imported_at = time.time()
                flag_id = _sha256_str(f"{fact_id}\nexclusive_conflict\n{exclusive_conflict_min_conf}")
                cur.execute(
                    """
                    INSERT OR IGNORE INTO review_flags(flag_id, fact_id, flag_type, detail, created_at)
                    VALUES(?, ?, ?, ?, ?)
                    """,
                    (flag_id, fact_id, "exclusive_conflict", detail, imported_at),
                )
                if cur.rowcount == 1:
                    stats.review_flags_inserted += 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Merge validated claim JSONL into a canonical SQLite store (facts.db).\n"
            "\n"
            "Typical usage:\n"
            "  python3 tools/pipeline/merge_claims.py --run-dir work/<run-id>\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--run-dir", required=True, help="Run directory containing claims/.")
    parser.add_argument(
        "--input",
        nargs="*",
        default=None,
        help="Explicit claim JSONL files (defaults to claims/claims_chunk_*.jsonl).",
    )
    parser.add_argument(
        "--overwrite-db",
        action="store_true",
        help="Delete and recreate facts.db in the run directory.",
    )
    parser.add_argument(
        "--require-validation",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require a successful validation report before merging (default: true).",
    )
    parser.add_argument(
        "--exclusive-category",
        action="append",
        default=[],
        help="Category where multiple stable facts should be flagged (repeatable).",
    )
    parser.add_argument(
        "--exclusive-conflict-min-confidence",
        type=float,
        default=0.7,
        help="Confidence threshold for exclusive-category conflict checks (default: 0.7).",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Manifest path (default: run-dir/manifest.merge_claims.json).",
    )
    parser.add_argument(
        "--overwrite-manifest",
        action="store_true",
        help="Allow overwriting the manifest file.",
    )
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    claims_dir = run_dir / "claims"
    db_path = run_dir / "facts.db"

    if args.input:
        claim_paths = [Path(p).resolve() for p in args.input]
    else:
        claim_paths = discover_claim_files(run_dir)

    if not claim_paths:
        print(f"No claim files found in: {claims_dir}", file=sys.stderr)
        print("Expected: claims/claims_chunk_*.jsonl", file=sys.stderr)
        return 2

    for p in claim_paths:
        if not p.is_file():
            print(f"Input not found: {p}", file=sys.stderr)
            return 2

    # Validation gate.
    report_path = claims_dir / "validation_report.json"
    if args.require_validation:
        if not report_path.is_file():
            print(f"Missing validation report: {report_path}", file=sys.stderr)
            print("Run: python3 tools/pipeline/validate_claims.py --run-dir work/<run-id> --overwrite-report", file=sys.stderr)
            return 2
        report = _load_validation_report(report_path)
        if _validation_has_errors(report):
            print("Validation report contains errors; refusing to merge.", file=sys.stderr)
            print(f"Report: {report_path}", file=sys.stderr)
            return 2

    # Optional default exclusive categories (minimal, safe signal categories).
    exclusive_categories = list(dict.fromkeys(args.exclusive_category))  # de-dupe preserve order
    if not exclusive_categories:
        exclusive_categories = [
            "identity.name",
            "identity.handle",
            "identity.email",
            "identity.phone",
            "identity.timezone",
        ]

    if args.overwrite_db and db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        _ensure_schema(conn)
        conn.commit()

        final_decision_cutoff_ts: dict[str, float] = {}
        if _table_exists(conn, "fact_reviews"):
            final_decision_cutoff_ts = _load_final_decision_cutoffs(conn)

        stats = MergeStats()
        started_at = time.time()
        with conn:
            merge_claims(
                conn=conn,
                run_dir=run_dir,
                claim_paths=claim_paths,
                exclusive_categories=exclusive_categories,
                exclusive_conflict_min_conf=args.exclusive_conflict_min_confidence,
                final_decision_cutoff_ts=final_decision_cutoff_ts,
                stats=stats,
            )

        duration_s = round(time.time() - started_at, 3)

        manifest_path = Path(args.manifest).resolve() if args.manifest else (run_dir / "manifest.merge_claims.json")
        manifest: dict[str, Any] = {
            "tool": "merge_claims",
            "version": 1,
            "created_at": _now_utc_iso(),
            "run_dir": run_dir.as_posix(),
            "inputs": [p.as_posix() for p in claim_paths],
            "db_path": db_path.as_posix(),
            "config": {
                "require_validation": args.require_validation,
                "exclusive_categories": exclusive_categories,
                "exclusive_conflict_min_confidence": args.exclusive_conflict_min_confidence,
            },
            "counts": {
                "claim_lines": stats.claim_lines,
                "claim_objects": stats.claim_objects,
                "claims_raw_inserted": stats.claims_raw_inserted,
                "facts_inserted": stats.facts_inserted,
                "facts_updated": stats.facts_updated,
                "evidence_inserted": stats.evidence_inserted,
                "fact_claim_links": stats.fact_claim_links,
                "review_flags_inserted": stats.review_flags_inserted,
            },
            "timing": {"duration_s": duration_s},
            "finished_at": _now_utc_iso(),
        }

        _atomic_write_text(
            manifest_path,
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            overwrite=args.overwrite_manifest,
        )

        print(f"DB: {db_path}")
        print(f"Manifest: {manifest_path}")
        print(
            f"Imported claims={stats.claim_objects} facts_inserted={stats.facts_inserted} "
            f"facts_updated={stats.facts_updated} evidence_inserted={stats.evidence_inserted} "
            f"flags={stats.review_flags_inserted} in {duration_s}s"
        )
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
