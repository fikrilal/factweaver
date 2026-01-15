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


def _single_line(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def _truncate(text: str, *, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    if max_chars <= 1:
        return text[:max_chars]
    return text[: max_chars - 1] + "…"


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "unknown"
    dt = datetime.fromtimestamp(float(ts), tz=timezone.utc).replace(microsecond=0)
    return dt.isoformat().replace("+00:00", "Z")


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


@dataclass(frozen=True)
class Fact:
    fact_id: str
    category: str
    fact_text: str
    stability: str
    first_seen_ts: float | None
    last_seen_ts: float | None
    confidence_max: float
    status: str


@dataclass(frozen=True)
class Evidence:
    role: str
    quote: str
    conv_id: str
    message_id: str
    ts: float | None


@dataclass(frozen=True)
class Flag:
    flag_type: str
    detail: str


def _file_key_for_category(category: str) -> str:
    if category.startswith("identity."):
        return "identity"
    if category.startswith("preferences.") or category.startswith("meta."):
        return "preferences"
    if category.startswith("projects."):
        return "projects"
    if category.startswith("goals."):
        return "goals"
    if category.startswith("constraints."):
        return "constraints"
    return "misc"


FILE_TITLES: dict[str, str] = {
    "identity": "Identity",
    "preferences": "Preferences",
    "projects": "Projects",
    "goals": "Goals (Transient)",
    "constraints": "Constraints / Do-Not",
    "misc": "Misc",
}


def _render_evidence_items(items: list[Evidence], *, max_quote_chars: int) -> str:
    if not items:
        return "  - Evidence: (missing)\n"
    out = "  - Evidence:\n"
    for ev in items:
        quote = _truncate(_single_line(ev.quote), max_chars=max_quote_chars)
        out += (
            f"    - “{quote}” (`conv_id={ev.conv_id}`, `message_id={ev.message_id}`, "
            f"`ts={_fmt_ts(ev.ts)}`, `role={ev.role}`)\n"
        )
    return out


def _render_fact_block(
    fact: Fact,
    *,
    evidence: list[Evidence],
    max_quote_chars: int,
    include_status: bool,
) -> str:
    lines = f"- Fact: { _single_line(fact.fact_text) }\n"
    if include_status:
        lines += f"  - Status: `{fact.status}`\n"
    lines += f"  - As of: `{_fmt_ts(fact.last_seen_ts)}`\n"
    lines += f"  - Confidence: `{fact.confidence_max:.3f}`\n"
    lines += _render_evidence_items(evidence, max_quote_chars=max_quote_chars)
    return lines


def _ensure_overwrite_policy(*, me_dir: Path, review_path: Path, overwrite: bool) -> None:
    existing_me = list(me_dir.glob("*.md")) if me_dir.is_dir() else []
    if (existing_me or review_path.exists()) and not overwrite:
        raise FileExistsError(
            f"Outputs already exist in {me_dir.parent}. Pass --overwrite to regenerate."
        )
    if overwrite:
        for p in existing_me:
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        if review_path.exists():
            try:
                review_path.unlink()
            except FileNotFoundError:
                pass


def _load_facts(conn: sqlite3.Connection) -> list[Fact]:
    rows = conn.execute(
        """
        SELECT fact_id, category, fact_text, stability, first_seen_ts, last_seen_ts, confidence_max, status
        FROM facts
        ORDER BY category ASC, stability ASC, status ASC, confidence_max DESC, last_seen_ts DESC, fact_id ASC
        """
    ).fetchall()
    facts: list[Fact] = []
    for r in rows:
        facts.append(
            Fact(
                fact_id=r["fact_id"],
                category=r["category"],
                fact_text=r["fact_text"],
                stability=r["stability"],
                first_seen_ts=r["first_seen_ts"],
                last_seen_ts=r["last_seen_ts"],
                confidence_max=float(r["confidence_max"]),
                status=r["status"],
            )
        )
    return facts


def _load_top_evidence(
    conn: sqlite3.Connection, *, max_evidence: int
) -> dict[str, list[Evidence]]:
    if max_evidence <= 0:
        return {}
    rows = conn.execute(
        """
        SELECT evidence_id, fact_id, role, quote, conv_id, message_id, ts
        FROM evidence
        ORDER BY
          fact_id ASC,
          CASE role WHEN 'user' THEN 0 ELSE 1 END ASC,
          ts DESC,
          evidence_id ASC
        """
    )
    out: dict[str, list[Evidence]] = {}
    for r in rows:
        fact_id = r["fact_id"]
        bucket = out.get(fact_id)
        if bucket is None:
            bucket = []
            out[fact_id] = bucket
        if len(bucket) >= max_evidence:
            continue
        bucket.append(
            Evidence(
                role=r["role"],
                quote=r["quote"],
                conv_id=r["conv_id"],
                message_id=r["message_id"],
                ts=r["ts"],
            )
        )
    return out


def _load_flags(conn: sqlite3.Connection) -> dict[str, list[Flag]]:
    rows = conn.execute(
        """
        SELECT fact_id, flag_type, detail
        FROM review_flags
        ORDER BY fact_id ASC, flag_type ASC, detail ASC
        """
    ).fetchall()
    out: dict[str, list[Flag]] = {}
    for r in rows:
        out.setdefault(r["fact_id"], []).append(Flag(flag_type=r["flag_type"], detail=r["detail"]))
    return out


def _load_derived_from_rollup(conn: sqlite3.Connection) -> dict[str, str]:
    # fact_id -> one of {"user","mixed","assistant","unknown"}.
    rows = conn.execute(
        """
        SELECT fc.fact_id, cr.claim_json
        FROM fact_claims fc
        JOIN claims_raw cr ON cr.claim_id = fc.claim_id
        ORDER BY fc.fact_id ASC, fc.claim_id ASC
        """
    )
    sources: dict[str, set[str]] = {}
    for r in rows:
        fact_id = r["fact_id"]
        claim_json = r["claim_json"]
        try:
            obj = json.loads(claim_json)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        v = obj.get("derived_from")
        if isinstance(v, str):
            sources.setdefault(fact_id, set()).add(v)

    rollup: dict[str, str] = {}
    for fact_id, vals in sources.items():
        if "assistant" in vals:
            rollup[fact_id] = "assistant"
        elif "mixed" in vals:
            rollup[fact_id] = "mixed"
        elif "user" in vals:
            rollup[fact_id] = "user"
        else:
            rollup[fact_id] = "unknown"
    return rollup


def _render_me_files(
    *,
    facts: list[Fact],
    evidence_by_fact: dict[str, list[Evidence]],
    me_dir: Path,
    max_quote_chars: int,
    overwrite: bool,
    include_status: bool,
) -> dict[str, int]:
    by_file: dict[str, list[Fact]] = {k: [] for k in FILE_TITLES.keys()}
    for fact in facts:
        key = _file_key_for_category(fact.category)
        by_file.setdefault(key, []).append(fact)

    counts: dict[str, int] = {}
    for file_key, title in FILE_TITLES.items():
        items = by_file.get(file_key, [])
        items_sorted = sorted(
            items,
            key=lambda f: (
                f.category,
                0 if f.stability == "stable" else 1,
                0 if f.status == "accepted" else 1,
                -f.confidence_max,
                -(f.last_seen_ts or 0.0),
                f.fact_id,
            ),
        )

        md = f"# {title}\n\n"
        if not items_sorted:
            md += "No facts yet.\n"
            _atomic_write_text(me_dir / f"{file_key}.md", md, overwrite=overwrite)
            counts[file_key] = 0
            continue

        for stability in ("stable", "transient"):
            group = [f for f in items_sorted if f.stability == stability]
            if not group:
                continue
            md += f"## {stability.capitalize()}\n\n"

            categories = sorted({f.category for f in group})
            for category in categories:
                md += f"### `{category}`\n"
                facts_in_cat = [f for f in group if f.category == category]
                for fact in facts_in_cat:
                    ev = evidence_by_fact.get(fact.fact_id, [])
                    md += _render_fact_block(
                        fact,
                        evidence=ev,
                        max_quote_chars=max_quote_chars,
                        include_status=include_status,
                    )
                md += "\n"

        # Defense-in-depth scan: refuse to write secrets into Markdown.
        hits = _scan_for_secrets(md)
        if hits:
            raise ValueError(
                f"Secret-like content detected while rendering {file_key}.md ({', '.join(hits)}). "
                "Redact upstream and re-run."
            )

        _atomic_write_text(me_dir / f"{file_key}.md", md, overwrite=overwrite)
        counts[file_key] = len(items_sorted)

    return counts


def _render_review_md(
    *,
    facts: list[Fact],
    evidence_by_fact: dict[str, list[Evidence]],
    flags_by_fact: dict[str, list[Flag]],
    derived_rollup: dict[str, str],
    low_confidence_threshold: float,
    max_quote_chars: int,
    review_path: Path,
    overwrite: bool,
) -> dict[str, int]:
    fact_by_id = {f.fact_id: f for f in facts}

    flagged = sorted(
        [fid for fid in flags_by_fact.keys() if fact_by_id.get(fid) and fact_by_id[fid].status == "needs_review"]
    )
    low_conf = sorted(
        [f.fact_id for f in facts if f.status == "needs_review" and f.confidence_max < low_confidence_threshold]
    )
    assistant_derived = sorted(
        [
            f.fact_id
            for f in facts
            if f.status == "needs_review" and derived_rollup.get(f.fact_id) in {"assistant", "mixed"}
        ]
    )
    needs_review = sorted([f.fact_id for f in facts if f.status == "needs_review"])

    listed: set[str] = set()

    md = "# Review Queue\n\n"
    md += "This file contains items that likely need manual confirmation.\n\n"

    # Conflicts
    md += "## Conflicts\n"
    if not flagged:
        md += "- (none)\n\n"
    else:
        for fact_id in sorted(flagged):
            fact = fact_by_id.get(fact_id)
            if fact is None:
                continue
            listed.add(fact_id)
            md += f"- Category: `{fact.category}`\n"
            md += f"  - Fact ID: `{fact.fact_id}`\n"
            md += f"  - Fact: { _single_line(fact.fact_text) }\n"
            md += f"  - Status: `{fact.status}`\n"
            for fl in flags_by_fact.get(fact_id, []):
                md += f"  - Flag: `{fl.flag_type}`\n"
                md += f"    - Detail: { _single_line(fl.detail) }\n"
            ev = evidence_by_fact.get(fact_id, [])
            md += _render_evidence_items(ev, max_quote_chars=max_quote_chars)
        md += "\n"

    # Low-confidence
    md += "## Low-confidence items\n"
    low_conf_nonflag = [fid for fid in low_conf if fid not in listed]
    if not low_conf_nonflag:
        md += "- (none)\n\n"
    else:
        for fact_id in low_conf_nonflag:
            fact = fact_by_id.get(fact_id)
            if fact is None:
                continue
            listed.add(fact_id)
            md += f"- Candidate: { _single_line(fact.fact_text) }\n"
            md += f"  - Fact ID: `{fact.fact_id}`\n"
            md += f"  - Category: `{fact.category}`\n"
            md += f"  - Confidence: `{fact.confidence_max:.3f}` (< `{low_confidence_threshold:.3f}`)\n"
            md += f"  - Status: `{fact.status}`\n"
            ev = evidence_by_fact.get(fact_id, [])
            md += _render_evidence_items(ev, max_quote_chars=max_quote_chars)
        md += "\n"

    # Assistant-derived
    md += "## Assistant-derived (unconfirmed)\n"
    assistant_nonlisted = [fid for fid in assistant_derived if fid not in listed]
    if not assistant_nonlisted:
        md += "- (none)\n\n"
    else:
        for fact_id in assistant_nonlisted:
            fact = fact_by_id.get(fact_id)
            if fact is None:
                continue
            listed.add(fact_id)
            derived = derived_rollup.get(fact_id, "unknown")
            md += f"- Candidate: { _single_line(fact.fact_text) }\n"
            md += f"  - Fact ID: `{fact.fact_id}`\n"
            md += f"  - Category: `{fact.category}`\n"
            md += f"  - Derived from: `{derived}`\n"
            md += f"  - Confidence: `{fact.confidence_max:.3f}`\n"
            md += f"  - Status: `{fact.status}`\n"
            ev = evidence_by_fact.get(fact_id, [])
            md += _render_evidence_items(ev, max_quote_chars=max_quote_chars)
        md += "\n"

    # Remaining needs_review
    md += "## Other needs-review\n"
    remaining = [fid for fid in needs_review if fid not in listed]
    if not remaining:
        md += "- (none)\n"
    else:
        for fact_id in remaining:
            fact = fact_by_id.get(fact_id)
            if fact is None:
                continue
            md += f"- Candidate: { _single_line(fact.fact_text) }\n"
            md += f"  - Fact ID: `{fact.fact_id}`\n"
            md += f"  - Category: `{fact.category}`\n"
            md += f"  - Confidence: `{fact.confidence_max:.3f}`\n"
            md += f"  - Status: `{fact.status}`\n"
            ev = evidence_by_fact.get(fact_id, [])
            md += _render_evidence_items(ev, max_quote_chars=max_quote_chars)

    hits = _scan_for_secrets(md)
    if hits:
        raise ValueError(
            f"Secret-like content detected while rendering review.md ({', '.join(hits)}). "
            "Redact upstream and re-run."
        )

    _atomic_write_text(review_path, md, overwrite=overwrite)

    return {
        "flagged": len(flagged),
        "low_confidence": len(low_conf),
        "assistant_derived": len(assistant_derived),
        "needs_review": len(needs_review),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Render Markdown views from facts.db.\n"
            "\n"
            "Reads:\n"
            "  work/<run-id>/facts.db\n"
            "Writes:\n"
            "  work/<run-id>/out/me/*.md\n"
            "  work/<run-id>/out/review.md\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--run-dir", required=True, help="Run directory containing facts.db.")
    parser.add_argument("--db", default=None, help="SQLite DB path (default: run-dir/facts.db).")
    parser.add_argument("--out-dir", default=None, help="Output dir (default: run-dir/out).")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting out/ files in the run directory.",
    )
    parser.add_argument(
        "--max-evidence",
        type=int,
        default=3,
        help="Max evidence quotes per fact (default: 3).",
    )
    parser.add_argument(
        "--max-quote-chars",
        type=int,
        default=240,
        help="Max characters per evidence quote (default: 240).",
    )
    parser.add_argument(
        "--low-confidence-threshold",
        type=float,
        default=0.6,
        help="Threshold for 'low-confidence' review items (default: 0.6).",
    )
    parser.add_argument(
        "--include-status",
        action="store_true",
        help="Include fact status in out/me/*.md (default: false).",
    )
    parser.add_argument(
        "--include-needs-review",
        action="store_true",
        help="Include needs_review facts in out/me/*.md (default: false; accepted-only).",
    )
    parser.add_argument(
        "--include-rejected",
        action="store_true",
        help="Include rejected facts in out/me/*.md (default: false).",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Manifest path (default: run-dir/manifest.render_md.json).",
    )
    parser.add_argument(
        "--overwrite-manifest",
        action="store_true",
        help="Allow overwriting the manifest file.",
    )
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    db_path = Path(args.db).resolve() if args.db else (run_dir / "facts.db")
    out_dir = Path(args.out_dir).resolve() if args.out_dir else (run_dir / "out")
    me_dir = out_dir / "me"
    review_path = out_dir / "review.md"
    manifest_path = Path(args.manifest).resolve() if args.manifest else (run_dir / "manifest.render_md.json")

    if not db_path.is_file():
        print(f"DB not found: {db_path}", file=sys.stderr)
        print("Run merge_claims.py first to create facts.db.", file=sys.stderr)
        return 2

    try:
        _ensure_overwrite_policy(me_dir=me_dir, review_path=review_path, overwrite=args.overwrite)
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        started_at = time.time()
        all_facts = _load_facts(conn)
        evidence_by_fact = _load_top_evidence(conn, max_evidence=args.max_evidence)
        flags_by_fact = _load_flags(conn)
        derived_rollup = _load_derived_from_rollup(conn)

        out_dir.mkdir(parents=True, exist_ok=True)
        me_dir.mkdir(parents=True, exist_ok=True)

        def _include_in_me(status: str) -> bool:
            if status == "accepted":
                return True
            if status == "needs_review":
                return args.include_needs_review
            if status == "rejected":
                return args.include_rejected
            # Unknown future statuses: treat as needs_review-like.
            return args.include_needs_review

        me_facts = [f for f in all_facts if _include_in_me(f.status)]
        review_facts = [f for f in all_facts if f.status == "needs_review"]

        me_counts = _render_me_files(
            facts=me_facts,
            evidence_by_fact=evidence_by_fact,
            me_dir=me_dir,
            max_quote_chars=args.max_quote_chars,
            overwrite=True,  # guarded by overwrite policy above
            include_status=args.include_status,
        )
        review_counts = _render_review_md(
            facts=review_facts,
            evidence_by_fact=evidence_by_fact,
            flags_by_fact=flags_by_fact,
            derived_rollup=derived_rollup,
            low_confidence_threshold=args.low_confidence_threshold,
            max_quote_chars=args.max_quote_chars,
            review_path=review_path,
            overwrite=True,  # guarded by overwrite policy above
        )

        duration_s = round(time.time() - started_at, 3)

        facts_by_status: dict[str, int] = {}
        facts_by_stability: dict[str, int] = {}
        for f in all_facts:
            facts_by_status[f.status] = facts_by_status.get(f.status, 0) + 1
            facts_by_stability[f.stability] = facts_by_stability.get(f.stability, 0) + 1

        manifest: dict[str, Any] = {
            "tool": "render_md",
            "version": 1,
            "created_at": _now_utc_iso(),
            "run_dir": run_dir.as_posix(),
            "input": {"db_path": db_path.as_posix()},
            "output": {
                "out_dir": out_dir.as_posix(),
                "me_dir": me_dir.as_posix(),
                "review_md": review_path.as_posix(),
                "me_files": {k: (me_dir / f"{k}.md").as_posix() for k in FILE_TITLES.keys()},
            },
            "config": {
                "max_evidence": args.max_evidence,
                "max_quote_chars": args.max_quote_chars,
                "low_confidence_threshold": args.low_confidence_threshold,
                "include_status": args.include_status,
                "include_needs_review": args.include_needs_review,
                "include_rejected": args.include_rejected,
            },
            "counts": {
                "facts_total": len(all_facts),
                "facts_by_status": facts_by_status,
                "facts_by_stability": facts_by_stability,
                "facts_by_file": me_counts,
                "review": review_counts,
            },
            "timing": {"duration_s": duration_s},
            "finished_at": _now_utc_iso(),
        }

        _atomic_write_text(
            manifest_path,
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            overwrite=args.overwrite_manifest,
        )

        print(f"Wrote: {me_dir}/*.md")
        print(f"Wrote: {review_path}")
        print(f"Wrote: {manifest_path}")
        print(f"Done in {duration_s}s (facts={len(all_facts)})")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
