#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import sys
from typing import Any


@dataclass(frozen=True)
class StatusItem:
    name: str
    ok: bool
    detail: str


def _fmt_bool(v: bool) -> str:
    return "OK " if v else "ERR"


def _safe_stat(path: Path) -> str:
    try:
        st = path.stat()
    except FileNotFoundError:
        return "missing"
    return f"size={st.st_size} mtime={int(st.st_mtime)}"


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception as e:  # noqa: BLE001
        print(f"[status] failed to read {path}: {e}", file=sys.stderr)
        return None


def _chunks_from_manifest(path: Path) -> list[str]:
    m = _load_json(path)
    if not isinstance(m, dict):
        return []
    chunks = m.get("chunks")
    if not isinstance(chunks, list):
        return []
    out: list[str] = []
    for c in chunks:
        if isinstance(c, dict):
            cid = c.get("chunk_id")
            if isinstance(cid, str) and cid:
                out.append(cid)
    return out


def _claim_files(run_dir: Path) -> list[Path]:
    claims_dir = run_dir / "claims"
    if not claims_dir.is_dir():
        return []
    return sorted(claims_dir.glob("claims_chunk_*.jsonl"))


def _chunk_ids_from_claim_files(files: list[Path]) -> set[str]:
    out: set[str] = set()
    for p in files:
        name = p.stem  # claims_chunk_0001
        if name.startswith("claims_chunk_") and len(name) == len("claims_chunk_0000"):
            suffix = name.removeprefix("claims_")  # chunk_0001
            out.add(suffix)
    return out


def _read_validation_summary(path: Path) -> str:
    m = _load_json(path)
    if not isinstance(m, dict):
        return "missing"
    issues = m.get("issues")
    counts = m.get("counts")
    if isinstance(counts, dict):
        e = counts.get("errors")
        w = counts.get("warnings")
        if isinstance(e, int) and isinstance(w, int):
            return f"errors={e} warnings={w}"
    if isinstance(issues, list):
        err = sum(1 for i in issues if isinstance(i, dict) and i.get("level") == "error")
        warn = sum(1 for i in issues if isinstance(i, dict) and i.get("level") == "warning")
        return f"errors={err} warnings={warn}"
    return "unknown"


def _facts_counts(db_path: Path) -> str:
    if not db_path.is_file():
        return "missing"
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
        by_status = cur.execute("SELECT status, COUNT(*) FROM facts GROUP BY status").fetchall()
        conn.close()
    except Exception as e:  # noqa: BLE001
        return f"error: {e}"

    parts = [f"total={int(total)}"]
    for status, cnt in by_status:
        if isinstance(status, str):
            parts.append(f"{status}={int(cnt)}")
    return " ".join(parts)


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _sha256_path(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _chunk_progress_summary(*, run_dir: Path, chunk_ids: list[str], db_path: Path) -> tuple[bool, str, str | None]:
    if not db_path.is_file() or not chunk_ids:
        return False, "missing", None

    try:
        conn = sqlite3.connect(db_path)
        if not _table_exists(conn, "chunk_progress"):
            conn.close()
            return False, "missing (no chunk_progress table)", None

        rows = conn.execute(
            "SELECT chunk_id, chunk_sha256, claims_objects, done_at, note FROM chunk_progress"
        ).fetchall()
        conn.close()
    except Exception as e:  # noqa: BLE001
        return False, f"error: {e}", None

    progress: dict[str, dict[str, Any]] = {}
    for chunk_id, chunk_sha, claims_objects, done_at, note in rows:
        if isinstance(chunk_id, str):
            progress[chunk_id] = {
                "chunk_sha256": chunk_sha if isinstance(chunk_sha, str) else "",
                "claims_objects": int(claims_objects) if isinstance(claims_objects, (int, float)) else 0,
                "done_at": float(done_at) if isinstance(done_at, (int, float)) else None,
                "note": note if isinstance(note, str) else "",
            }

    missing = [cid for cid in chunk_ids if cid not in progress]
    done = len(chunk_ids) - len(missing)

    stale = 0
    for cid in chunk_ids:
        row = progress.get(cid)
        if not row:
            continue
        stored = row.get("chunk_sha256") or ""
        if not stored:
            continue
        chunk_path = run_dir / "chunks" / f"{cid}.jsonl"
        if not chunk_path.is_file():
            continue
        current = _sha256_path(chunk_path)
        if current != stored:
            stale += 1

    detail = f"done={done}/{len(chunk_ids)} missing={len(missing)} stale={stale}"
    next_chunk = missing[0] if missing else None
    return True, detail, next_chunk


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Show a high-level status summary for a run directory (agent-friendly; no content printed)."
    )
    parser.add_argument("--run-dir", required=True, help="Run directory (e.g., work/run_YYYYMMDD_HHMMSSZ).")
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    items: list[StatusItem] = []

    messages = run_dir / "messages.jsonl"
    view = run_dir / "messages_view.jsonl"
    chunks_manifest = run_dir / "chunks" / "manifest.json"
    prompts_index = run_dir / "prompts" / "claims_map" / "index.json"
    claims_dir = run_dir / "claims"
    validation_report = claims_dir / "validation_report.json"
    db_path = run_dir / "facts.db"
    out_dir = run_dir / "out"
    out_me = out_dir / "me"
    review_md = out_dir / "review.md"

    items.append(StatusItem("messages.jsonl", messages.is_file(), _safe_stat(messages)))
    items.append(StatusItem("messages_view.jsonl", view.is_file(), _safe_stat(view)))
    items.append(StatusItem("chunks/manifest.json", chunks_manifest.is_file(), _safe_stat(chunks_manifest)))

    chunk_ids = _chunks_from_manifest(chunks_manifest) if chunks_manifest.is_file() else []
    if chunk_ids:
        items.append(StatusItem("chunks count", True, str(len(chunk_ids))))
    else:
        items.append(StatusItem("chunks count", False, "0 (run chunk_messages.py)"))

    items.append(StatusItem("prompts index", prompts_index.is_file(), _safe_stat(prompts_index)))

    claim_files = _claim_files(run_dir)
    items.append(StatusItem("claims dir", claims_dir.is_dir(), f"files={len(claim_files)}"))

    if chunk_ids:
        ok, detail, next_chunk = _chunk_progress_summary(run_dir=run_dir, chunk_ids=chunk_ids, db_path=db_path)
        items.append(StatusItem("chunk progress", ok, detail))
        if next_chunk:
            items.append(StatusItem("next chunk", False, next_chunk))

    items.append(
        StatusItem(
            "validation_report.json",
            validation_report.is_file(),
            _read_validation_summary(validation_report) if validation_report.is_file() else "missing",
        )
    )

    items.append(StatusItem("facts.db", db_path.is_file(), _facts_counts(db_path)))
    items.append(StatusItem("out/me", out_me.is_dir(), f"files={len(list(out_me.glob('*.md'))) if out_me.is_dir() else 0}"))
    items.append(StatusItem("out/review.md", review_md.is_file(), _safe_stat(review_md)))

    for it in items:
        print(f"{_fmt_bool(it.ok)} {it.name}: {it.detail}")

    ok = all(i.ok for i in items if i.name not in {"next chunk"})
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
