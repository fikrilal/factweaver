#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS fact_reviews (
  review_id TEXT PRIMARY KEY,
  fact_id TEXT NOT NULL,
  decided_at REAL NOT NULL,
  decided_by TEXT,
  action TEXT NOT NULL,
  previous_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  reason TEXT,
  source_path TEXT NOT NULL,
  source_line INTEGER,
  FOREIGN KEY(fact_id) REFERENCES facts(fact_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fact_reviews_fact_id ON fact_reviews(fact_id);
CREATE INDEX IF NOT EXISTS idx_fact_reviews_decided_at ON fact_reviews(decided_at);
"""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)


@dataclass(frozen=True)
class Decision:
    fact_id: str
    action: str
    new_status: str
    reason: str | None
    decided_by: str | None
    source_path: str
    source_line: int | None


def _action_to_status(action: str) -> str:
    a = action.strip().lower()
    if a in {"accept", "accepted"}:
        return "accepted"
    if a in {"reject", "rejected"}:
        return "rejected"
    if a in {"needs_review", "review"}:
        return "needs_review"
    raise ValueError(f"Unknown action: {action!r} (expected accept|reject|needs_review)")


def _load_review_flags(conn: sqlite3.Connection) -> dict[str, list[str]]:
    rows = conn.execute(
        """
        SELECT fact_id, flag_type
        FROM review_flags
        ORDER BY fact_id ASC, flag_type ASC
        """
    ).fetchall()
    out: dict[str, list[str]] = {}
    for r in rows:
        out.setdefault(r["fact_id"], []).append(r["flag_type"])
    return out


def _init_actions_file(
    *,
    conn: sqlite3.Connection,
    actions_path: Path,
    overwrite_actions: bool,
) -> int:
    flags = _load_review_flags(conn)
    rows = conn.execute(
        """
        SELECT fact_id, category, fact_text, stability, confidence_max, last_seen_ts, status
        FROM facts
        WHERE status='needs_review'
        ORDER BY
          category ASC,
          CASE stability WHEN 'stable' THEN 0 ELSE 1 END ASC,
          confidence_max DESC,
          last_seen_ts DESC,
          fact_id ASC
        """
    ).fetchall()

    # JSONL template: one record per fact needing review.
    lines: list[str] = []
    for r in rows:
        rec: dict[str, Any] = {
            "fact_id": r["fact_id"],
            "category": r["category"],
            "fact": r["fact_text"],
            "stability": r["stability"],
            "confidence_max": float(r["confidence_max"]),
            "last_seen_ts": r["last_seen_ts"],
            "status": r["status"],
            "flags": flags.get(r["fact_id"], []),
            "action": None,
            "reason": None,
        }
        lines.append(_canonical_json(rec))

    _atomic_write_text(actions_path, "\n".join(lines) + ("\n" if lines else ""), overwrite=overwrite_actions)
    return len(lines)


def _parse_actions_file(
    *,
    actions_path: Path,
    decided_by_default: str | None,
    strict_match: bool,
    conn: sqlite3.Connection,
) -> tuple[list[Decision], int]:
    decisions: list[Decision] = []
    skipped = 0

    with actions_path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            if not raw_line.strip():
                continue
            if raw_line.lstrip().startswith("```"):
                raise ValueError(f"{actions_path}:{line_no}: code fence detected; expected JSONL only.")

            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{actions_path}:{line_no}: invalid JSON: {e.msg}") from e
            if not isinstance(obj, dict):
                raise ValueError(f"{actions_path}:{line_no}: expected JSON object per line")

            fact_id = obj.get("fact_id")
            if not isinstance(fact_id, str) or not fact_id.strip():
                raise ValueError(f"{actions_path}:{line_no}: missing/invalid fact_id")

            action = obj.get("action")
            if action is None or (isinstance(action, str) and not action.strip()):
                skipped += 1
                continue
            if not isinstance(action, str):
                raise ValueError(f"{actions_path}:{line_no}: invalid action (expected string or null)")

            new_status = _action_to_status(action)

            reason = obj.get("reason")
            if reason is not None and not isinstance(reason, str):
                raise ValueError(f"{actions_path}:{line_no}: invalid reason (expected string or null)")

            decided_by = obj.get("decided_by")
            if decided_by is not None and not isinstance(decided_by, str):
                raise ValueError(f"{actions_path}:{line_no}: invalid decided_by (expected string or null)")
            if decided_by is None:
                decided_by = decided_by_default

            # Optional safety check: if the actions line includes category/fact, verify it matches DB.
            expected_category = obj.get("category")
            expected_fact = obj.get("fact")
            if expected_category is not None or expected_fact is not None:
                row = conn.execute(
                    "SELECT category, fact_text FROM facts WHERE fact_id=?",
                    (fact_id,),
                ).fetchone()
                if row is None:
                    # Let apply stage handle missing fact_ids uniformly.
                    pass
                else:
                    mismatches: list[str] = []
                    if isinstance(expected_category, str) and expected_category != row["category"]:
                        mismatches.append("category")
                    if isinstance(expected_fact, str) and expected_fact != row["fact_text"]:
                        mismatches.append("fact")
                    if mismatches:
                        msg = (
                            f"{actions_path}:{line_no}: fact_id mismatch vs DB for {fact_id} "
                            f"({', '.join(mismatches)} differs)."
                        )
                        if strict_match:
                            raise ValueError(msg)
                        print(f"[curate_facts] warning: {msg}", file=sys.stderr)

            decisions.append(
                Decision(
                    fact_id=fact_id,
                    action=action.strip().lower(),
                    new_status=new_status,
                    reason=reason,
                    decided_by=decided_by,
                    source_path=actions_path.as_posix(),
                    source_line=line_no,
                )
            )

    return decisions, skipped


def _apply_decisions(
    *,
    conn: sqlite3.Connection,
    decisions: list[Decision],
    dry_run: bool,
    skip_missing: bool,
) -> dict[str, int]:
    counts = {
        "decisions_total": len(decisions),
        "missing_fact_id": 0,
        "no_change": 0,
        "facts_updated": 0,
        "review_rows_inserted": 0,
    }

    now = time.time()

    for d in decisions:
        row = conn.execute(
            "SELECT status FROM facts WHERE fact_id=?",
            (d.fact_id,),
        ).fetchone()
        if row is None:
            counts["missing_fact_id"] += 1
            if skip_missing:
                continue
            raise ValueError(f"Unknown fact_id: {d.fact_id}")

        previous_status = row["status"]
        if previous_status == d.new_status:
            counts["no_change"] += 1

        review_key = {
            "fact_id": d.fact_id,
            "action": d.action,
            "new_status": d.new_status,
            "reason": d.reason or "",
            "decided_by": d.decided_by or "",
            "source_path": d.source_path,
            "source_line": d.source_line or 0,
        }
        review_id = _sha256_str(_canonical_json(review_key))

        if dry_run:
            continue

        cur = conn.execute(
            """
            INSERT OR IGNORE INTO fact_reviews(
              review_id, fact_id, decided_at, decided_by, action, previous_status, new_status, reason, source_path, source_line
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_id,
                d.fact_id,
                now,
                d.decided_by,
                d.action,
                previous_status,
                d.new_status,
                d.reason,
                d.source_path,
                d.source_line,
            ),
        )
        if cur.rowcount == 1:
            counts["review_rows_inserted"] += 1

        if previous_status != d.new_status:
            conn.execute(
                "UPDATE facts SET status=? WHERE fact_id=?",
                (d.new_status, d.fact_id),
            )
            counts["facts_updated"] += 1

    return counts


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Apply human review decisions to facts.db (stored in DB).\n"
            "\n"
            "Typical workflow:\n"
            "  python3 tools/pipeline/curate_facts.py --run-dir work/<run-id> --init-actions\n"
            "  # edit out/review_actions.jsonl to set action=accept|reject|needs_review\n"
            "  python3 tools/pipeline/curate_facts.py --run-dir work/<run-id> --apply-actions\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--run-dir", required=True, help="Run directory containing facts.db.")
    parser.add_argument("--db", default=None, help="SQLite DB path (default: run-dir/facts.db).")
    parser.add_argument(
        "--actions",
        default=None,
        help="Actions JSONL path (default: run-dir/out/review_actions.jsonl).",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--init-actions",
        action="store_true",
        help="Write a JSONL template listing all facts with status=needs_review.",
    )
    mode.add_argument(
        "--apply-actions",
        action="store_true",
        help="Apply review actions from the JSONL file into facts.db.",
    )
    parser.add_argument(
        "--overwrite-actions",
        action="store_true",
        help="Allow overwriting the actions JSONL during --init-actions.",
    )
    parser.add_argument(
        "--decided-by",
        default=None,
        help="Default decided_by to record in DB (optional).",
    )
    parser.add_argument(
        "--strict-match",
        action="store_true",
        help="Fail if an action line's category/fact doesn't match the DB for the fact_id.",
    )
    parser.add_argument(
        "--skip-missing",
        action="store_true",
        help="Skip actions referencing missing fact_id instead of failing.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse actions and show a summary without writing to the DB.",
    )
    parser.add_argument(
        "--accept",
        action="append",
        default=[],
        help="Accept a fact_id (repeatable). Applied in addition to --apply-actions input.",
    )
    parser.add_argument(
        "--reject",
        action="append",
        default=[],
        help="Reject a fact_id (repeatable). Applied in addition to --apply-actions input.",
    )
    parser.add_argument(
        "--needs-review",
        action="append",
        default=[],
        help="Set a fact_id back to needs_review (repeatable). Applied in addition to --apply-actions input.",
    )
    parser.add_argument(
        "--reason",
        default=None,
        help="Reason to record for CLI-specified --accept/--reject/--needs-review (optional).",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Manifest path (default: run-dir/manifest.curate_facts.json).",
    )
    parser.add_argument(
        "--overwrite-manifest",
        action="store_true",
        help="Allow overwriting the manifest file.",
    )
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    db_path = Path(args.db).resolve() if args.db else (run_dir / "facts.db")
    out_dir = run_dir / "out"
    actions_path = Path(args.actions).resolve() if args.actions else (out_dir / "review_actions.jsonl")
    manifest_path = Path(args.manifest).resolve() if args.manifest else (run_dir / "manifest.curate_facts.json")

    if not db_path.is_file():
        print(f"DB not found: {db_path}", file=sys.stderr)
        print("Run merge_claims.py first to create facts.db.", file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        _ensure_schema(conn)
        conn.commit()

        started_at = time.time()
        counts: dict[str, Any] = {}

        if args.init_actions:
            try:
                n = _init_actions_file(
                    conn=conn,
                    actions_path=actions_path,
                    overwrite_actions=args.overwrite_actions,
                )
            except FileExistsError as e:
                print(f"Refusing to overwrite existing file: {e}", file=sys.stderr)
                print("Pass --overwrite-actions to replace it.", file=sys.stderr)
                return 2

            duration_s = round(time.time() - started_at, 3)
            manifest = {
                "tool": "curate_facts",
                "version": 1,
                "created_at": _now_utc_iso(),
                "run_dir": run_dir.as_posix(),
                "mode": "init",
                "output": {"actions_path": actions_path.as_posix()},
                "counts": {"facts_needing_review": n},
                "timing": {"duration_s": duration_s},
                "finished_at": _now_utc_iso(),
            }
            _atomic_write_text(
                manifest_path,
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                overwrite=args.overwrite_manifest,
            )
            print(f"Wrote: {actions_path}")
            print(f"Wrote: {manifest_path}")
            print(f"Facts needing review: {n}")
            return 0

        # Apply mode.
        decisions: list[Decision] = []
        skipped_actions = 0

        if actions_path.exists():
            parsed, skipped = _parse_actions_file(
                actions_path=actions_path,
                decided_by_default=args.decided_by,
                strict_match=args.strict_match,
                conn=conn,
            )
            decisions.extend(parsed)
            skipped_actions += skipped
        else:
            print(f"Actions file not found: {actions_path}", file=sys.stderr)
            print("Run with --init-actions to create it, or pass --actions.", file=sys.stderr)
            return 2

        def _add_cli(fact_id: str, action: str, idx: int) -> None:
            decisions.append(
                Decision(
                    fact_id=fact_id,
                    action=action,
                    new_status=_action_to_status(action),
                    reason=args.reason,
                    decided_by=args.decided_by,
                    source_path="cli",
                    source_line=idx,
                )
            )

        cli_idx = 1
        for fid in args.accept:
            _add_cli(fid, "accept", cli_idx)
            cli_idx += 1
        for fid in args.reject:
            _add_cli(fid, "reject", cli_idx)
            cli_idx += 1
        for fid in args.needs_review:
            _add_cli(fid, "needs_review", cli_idx)
            cli_idx += 1

        if not decisions:
            print("No decisions to apply (all actions were null/blank).", file=sys.stderr)
            return 2

        if args.dry_run:
            with conn:
                counts = _apply_decisions(
                    conn=conn,
                    decisions=decisions,
                    dry_run=True,
                    skip_missing=args.skip_missing,
                )
        else:
            with conn:
                counts = _apply_decisions(
                    conn=conn,
                    decisions=decisions,
                    dry_run=False,
                    skip_missing=args.skip_missing,
                )

        duration_s = round(time.time() - started_at, 3)
        manifest = {
            "tool": "curate_facts",
            "version": 1,
            "created_at": _now_utc_iso(),
            "run_dir": run_dir.as_posix(),
            "mode": "apply",
            "input": {"actions_path": actions_path.as_posix()},
            "config": {
                "dry_run": args.dry_run,
                "skip_missing": args.skip_missing,
                "decided_by": args.decided_by,
                "strict_match": args.strict_match,
            },
            "counts": {
                **counts,
                "actions_skipped_null_or_blank": skipped_actions,
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
        print(f"Wrote: {manifest_path}")
        print(
            "Applied decisions: "
            f"updated={counts.get('facts_updated', 0)} "
            f"no_change={counts.get('no_change', 0)} "
            f"missing={counts.get('missing_fact_id', 0)} "
            f"review_rows_inserted={counts.get('review_rows_inserted', 0)} "
            f"skipped_null_actions={skipped_actions} "
            f"dry_run={args.dry_run}"
        )
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

