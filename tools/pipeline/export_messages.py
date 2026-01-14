#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any, Iterator, TextIO


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _skip_ws(buf: str, idx: int) -> int:
    while idx < len(buf) and buf[idx].isspace():
        idx += 1
    return idx


def iter_json_array(fp: TextIO, *, chunk_size: int = 1024 * 1024) -> Iterator[Any]:
    """
    Stream a top-level JSON array without loading it all into memory.

    This is intentionally dependency-free (no ijson), using json.JSONDecoder.raw_decode
    over a sliding buffer.
    """
    decoder = json.JSONDecoder()
    buf = ""
    idx = 0

    def _read_more() -> bool:
        nonlocal buf
        chunk = fp.read(chunk_size)
        if not chunk:
            return False
        buf += chunk
        return True

    # Prime buffer.
    if not _read_more():
        raise ValueError("Empty input")

    idx = _skip_ws(buf, idx)
    while idx >= len(buf):
        if not _read_more():
            raise ValueError("EOF before JSON start")
        idx = _skip_ws(buf, idx)

    if buf[idx] != "[":
        raise ValueError(f"Expected '[' at start of JSON array, got {buf[idx]!r}")
    idx += 1

    while True:
        idx = _skip_ws(buf, idx)
        while idx >= len(buf):
            if not _read_more():
                raise ValueError("EOF while parsing JSON array")
            idx = _skip_ws(buf, idx)

        ch = buf[idx]
        if ch == "]":
            return
        if ch == ",":
            idx += 1
            continue

        try:
            value, new_idx = decoder.raw_decode(buf, idx)
        except json.JSONDecodeError:
            if not _read_more():
                raise
            continue

        idx = new_idx
        yield value

        # Trim buffer to avoid unbounded growth.
        if idx > 8 * 1024 * 1024:
            buf = buf[idx:]
            idx = 0


def _safe_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    return str(v)


def _extract_text(message: dict[str, Any]) -> str:
    content = message.get("content") or {}
    content_type = content.get("content_type")

    # The primary export format we care about.
    if content_type == "text":
        parts = content.get("parts")
        if isinstance(parts, list):
            rendered_parts = []
            for p in parts:
                if isinstance(p, str):
                    rendered_parts.append(p)
            return "\n".join(rendered_parts).rstrip()

    # Some exports use multimodal parts; keep text subparts only.
    if content_type == "multimodal_text":
        parts = content.get("parts")
        if isinstance(parts, list):
            rendered_parts = []
            for p in parts:
                if isinstance(p, str):
                    rendered_parts.append(p)
                elif isinstance(p, dict) and isinstance(p.get("text"), str):
                    rendered_parts.append(p["text"])
            return "\n".join(rendered_parts).rstrip()

    # Everything else (e.g., user_editable_context) is intentionally dropped by default.
    return ""


def _role_of(message: dict[str, Any]) -> str:
    author = message.get("author") or {}
    role = author.get("role")
    if isinstance(role, str) and role:
        return role
    # Some exports may include a name field; keep best-effort.
    name = author.get("name")
    if isinstance(name, str) and name:
        return name
    return "unknown"


def _ts_of(message: dict[str, Any]) -> float | None:
    ts = message.get("create_time")
    if isinstance(ts, (int, float)):
        return float(ts)
    ts = message.get("update_time")
    if isinstance(ts, (int, float)):
        return float(ts)
    return None


def _conv_id_of(conv: dict[str, Any]) -> str:
    for key in ("conversation_id", "id"):
        v = conv.get(key)
        if isinstance(v, str) and v:
            return v
    return "unknown"


def _title_of(conv: dict[str, Any]) -> str:
    v = conv.get("title")
    return v if isinstance(v, str) else ""


def _choose_terminal_node(mapping: dict[str, Any]) -> str | None:
    best_id: str | None = None
    best_ts = float("-inf")
    for node_id, node in mapping.items():
        if not isinstance(node, dict):
            continue
        msg = node.get("message")
        if not isinstance(msg, dict):
            continue
        ts = _ts_of(msg)
        if ts is None:
            continue
        if ts > best_ts:
            best_ts = ts
            best_id = node_id
    return best_id


def _path_to_root(mapping: dict[str, Any], *, start: str) -> list[str]:
    path: list[str] = []
    seen: set[str] = set()
    node_id: str | None = start
    while node_id:
        if node_id in seen:
            break
        seen.add(node_id)
        path.append(node_id)
        node = mapping.get(node_id)
        if not isinstance(node, dict):
            break
        parent = node.get("parent")
        node_id = parent if isinstance(parent, str) and parent else None
    path.reverse()
    return path


@dataclass
class ExportStats:
    conversations: int = 0
    messages: int = 0
    by_role: dict[str, int] | None = None

    def __post_init__(self) -> None:
        if self.by_role is None:
            self.by_role = {}


def export_messages(
    *,
    input_path: Path,
    output_jsonl: Path,
    allowed_roles: set[str],
    include_hidden: bool,
    progress_every: int,
    max_conversations: int | None,
) -> ExportStats:
    stats = ExportStats()
    output_jsonl.parent.mkdir(parents=True, exist_ok=True)

    with input_path.open("r", encoding="utf-8") as fp, output_jsonl.open(
        "w", encoding="utf-8"
    ) as out:
        for conv in iter_json_array(fp):
            if not isinstance(conv, dict):
                continue

            conv_id = _conv_id_of(conv)
            title = _title_of(conv)

            mapping = conv.get("mapping") or {}
            if not isinstance(mapping, dict) or not mapping:
                continue

            current = conv.get("current_node")
            terminal = current if isinstance(current, str) and current in mapping else None
            if terminal is None:
                terminal = _choose_terminal_node(mapping)
            if terminal is None:
                continue

            path_ids = _path_to_root(mapping, start=terminal)
            wrote_any = False
            for node_id in path_ids:
                node = mapping.get(node_id)
                if not isinstance(node, dict):
                    continue
                msg = node.get("message")
                if not isinstance(msg, dict):
                    continue

                if not include_hidden:
                    metadata = msg.get("metadata") or {}
                    if isinstance(metadata, dict) and metadata.get("is_visually_hidden_from_conversation") is True:
                        continue

                role = _role_of(msg)
                if allowed_roles and role not in allowed_roles:
                    continue

                text = _extract_text(msg)
                if not text:
                    continue

                message_id = msg.get("id")
                if not isinstance(message_id, str) or not message_id:
                    message_id = node_id

                record = {
                    "conv_id": conv_id,
                    "title": title,
                    "ts": _ts_of(msg),
                    "role": role,
                    "message_id": message_id,
                    "text": text,
                }
                out.write(json.dumps(record, ensure_ascii=False) + "\n")

                stats.messages += 1
                stats.by_role[role] = stats.by_role.get(role, 0) + 1
                wrote_any = True

            if wrote_any:
                stats.conversations += 1

            if progress_every > 0 and stats.conversations % progress_every == 0:
                print(
                    f"[export_messages] conversations={stats.conversations} messages={stats.messages}",
                    file=sys.stderr,
                )

            if max_conversations is not None and stats.conversations >= max_conversations:
                break

    return stats


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Export a normalized, compact transcript from a ChatGPT export.\n"
            "\n"
            "Outputs JSONL (one message per line) suitable for later view+chunk+claim steps.\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--input",
        default=None,
        help="Path to ChatGPT export JSON (default: conversations.json if present).",
    )
    parser.add_argument(
        "--run-dir",
        default=None,
        help="Run directory (default: work/run_YYYYMMDD_HHMMSSZ).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting messages.jsonl in the run directory.",
    )
    parser.add_argument(
        "--include-hidden",
        action="store_true",
        help="Include messages marked as visually hidden from the conversation (default: false).",
    )
    parser.add_argument(
        "--roles",
        default="user,assistant",
        help="Comma-separated roles to include (default: user,assistant).",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=50,
        help="Print progress every N conversations (default: 50; 0 disables).",
    )
    parser.add_argument(
        "--max-conversations",
        type=int,
        default=None,
        help="Stop after N conversations (debug/smoke test).",
    )
    parser.add_argument(
        "--hash-input",
        action="store_true",
        help="Compute sha256 of the input file (slower, but good for provenance).",
    )
    args = parser.parse_args(argv)

    default_input: Path | None = None
    if Path("conversations.json").is_file():
        default_input = Path("conversations.json")
    elif Path("shared_conversations.json").is_file():
        default_input = Path("shared_conversations.json")

    input_path = Path(args.input) if args.input else default_input
    if input_path is None or not input_path.is_file():
        parser.error("Input not found. Provide --input or place conversations.json in repo root.")
    input_path = input_path.resolve()

    if args.run_dir:
        run_dir = Path(args.run_dir)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        run_dir = Path("work") / f"run_{ts}"
    run_dir = run_dir.resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    output_jsonl = run_dir / "messages.jsonl"
    manifest_path = run_dir / "manifest.json"

    if output_jsonl.exists() and not args.overwrite:
        print(f"Refusing to overwrite existing file: {output_jsonl}", file=sys.stderr)
        print("Pass --overwrite to replace it, or pick a different --run-dir.", file=sys.stderr)
        return 2

    roles = [r.strip() for r in args.roles.split(",") if r.strip()]
    allowed_roles = set(roles)

    started_at = time.time()
    started_at_iso = _now_utc_iso()

    stats = export_messages(
        input_path=input_path,
        output_jsonl=output_jsonl,
        allowed_roles=allowed_roles,
        include_hidden=args.include_hidden,
        progress_every=args.progress_every,
        max_conversations=args.max_conversations,
    )

    input_stat = input_path.stat()
    manifest: dict[str, Any] = {
        "tool": "export_messages",
        "version": 1,
        "created_at": started_at_iso,
        "finished_at": _now_utc_iso(),
        "input": {
            "path": str(input_path),
            "size_bytes": input_stat.st_size,
            "mtime": input_stat.st_mtime,
            "sha256": _sha256_file(input_path) if args.hash_input else None,
        },
        "output": {
            "run_dir": str(run_dir),
            "messages_jsonl": str(output_jsonl),
        },
        "filters": {
            "roles": sorted(allowed_roles),
            "include_hidden": args.include_hidden,
        },
        "counts": {
            "conversations": stats.conversations,
            "messages": stats.messages,
            "by_role": stats.by_role,
        },
        "timing": {
            "duration_s": round(time.time() - started_at, 3),
        },
    }

    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote: {output_jsonl}")
    print(f"Wrote: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
