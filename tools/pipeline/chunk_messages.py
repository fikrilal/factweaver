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


def _normalize_jsonl_line(line: str) -> str:
    # Normalize newline to '\n' without trimming other whitespace.
    if line.endswith("\n"):
        line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
    return line + "\n"


def _get_encoding(*, model: str | None, encoding: str | None):
    import tiktoken

    if encoding:
        return tiktoken.get_encoding(encoding)

    if model:
        try:
            return tiktoken.encoding_for_model(model)
        except KeyError:
            pass

    return tiktoken.get_encoding("o200k_base")


@dataclass(frozen=True)
class TokenCounter:
    encoding_name: str
    _enc: Any

    @classmethod
    def from_args(cls, *, model: str | None, encoding: str | None) -> "TokenCounter":
        enc = _get_encoding(model=model, encoding=encoding)
        return cls(encoding_name=enc.name, _enc=enc)

    def count(self, text: str) -> int:
        # Avoid allocating a Python list of token IDs for large inputs.
        token_buf = self._enc._core_bpe.encode_to_tiktoken_buffer(text, set())
        return memoryview(token_buf).nbytes // 4


@dataclass(frozen=True)
class BufferedLine:
    raw: str  # normalized newline, ends with '\n'
    tokens: int
    conv_id: str
    message_id: str
    ts: float | None


@dataclass
class ChunkMeta:
    chunk_id: str
    path: str
    sha256: str
    token_estimate: int
    message_count: int
    conv_ids: list[str]
    first_ts: float | None
    last_ts: float | None
    first_message_id: str | None
    last_message_id: str | None


class ChunkWriter:
    def __init__(self, *, chunk_id: str, dest_path: Path) -> None:
        self.chunk_id = chunk_id
        self.dest_path = dest_path
        self.tmp_path = dest_path.with_name(dest_path.name + ".tmp")
        self.dest_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.tmp_path.unlink()
        except FileNotFoundError:
            pass

        self._f = self.tmp_path.open("w", encoding="utf-8", newline="\n")
        self._sha = hashlib.sha256()

        self.token_estimate = 0
        self.message_count = 0
        self.conv_ids: list[str] = []
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.first_message_id: str | None = None
        self.last_message_id: str | None = None

    def write(self, line: BufferedLine) -> None:
        self._f.write(line.raw)
        self._sha.update(line.raw.encode("utf-8", errors="replace"))

        self.token_estimate += line.tokens
        self.message_count += 1

        if line.conv_id and (not self.conv_ids or self.conv_ids[-1] != line.conv_id):
            self.conv_ids.append(line.conv_id)

        if line.ts is not None:
            if self.first_ts is None:
                self.first_ts = line.ts
            self.last_ts = line.ts

        if self.first_message_id is None:
            self.first_message_id = line.message_id
        self.last_message_id = line.message_id

    def finalize(self) -> ChunkMeta:
        self._f.flush()
        self._f.close()
        self.tmp_path.replace(self.dest_path)

        return ChunkMeta(
            chunk_id=self.chunk_id,
            path=self.dest_path.as_posix(),
            sha256=self._sha.hexdigest(),
            token_estimate=self.token_estimate,
            message_count=self.message_count,
            conv_ids=self.conv_ids,
            first_ts=self.first_ts,
            last_ts=self.last_ts,
            first_message_id=self.first_message_id,
            last_message_id=self.last_message_id,
        )


@dataclass
class ChunkStats:
    messages_in: int = 0
    messages_out: int = 0
    chunks: int = 0
    invalid_lines: int = 0
    conversations_seen: int = 0


def _parse_record(line: str) -> tuple[str, str, float | None]:
    record = json.loads(line)
    if not isinstance(record, dict):
        raise ValueError("expected JSON object")

    conv_id = record.get("conv_id")
    if not isinstance(conv_id, str) or not conv_id:
        conv_id = "unknown"

    message_id = record.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        message_id = "unknown"

    ts = record.get("ts")
    ts_out: float | None
    if isinstance(ts, (int, float)):
        ts_out = float(ts)
    else:
        ts_out = None

    return conv_id, message_id, ts_out


def _iter_chunk_files(chunks_dir: Path) -> Iterable[Path]:
    return chunks_dir.glob("chunk_*.jsonl")


def _clear_existing_outputs(*, chunks_dir: Path) -> None:
    if not chunks_dir.exists():
        return

    for p in _iter_chunk_files(chunks_dir):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    for name in ("manifest.json",):
        p = chunks_dir / name
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def chunk_messages(
    *,
    input_jsonl: Path,
    chunks_dir: Path,
    manifest_path: Path,
    overwrite: bool,
    max_tokens: int,
    token_counter: TokenCounter,
    progress_every: int,
    max_messages: int | None,
    skip_invalid: bool,
) -> tuple[ChunkStats, list[ChunkMeta]]:
    if max_tokens <= 0:
        raise ValueError("--max-tokens must be > 0")

    chunks_dir.mkdir(parents=True, exist_ok=True)

    # Refuse to overwrite chunk outputs by default.
    existing = list(_iter_chunk_files(chunks_dir))
    if existing or manifest_path.exists():
        if not overwrite:
            raise FileExistsError(
                f"Chunk outputs already exist in {chunks_dir}. Pass --overwrite to regenerate."
            )
        _clear_existing_outputs(chunks_dir=chunks_dir)

    stats = ChunkStats()
    metas: list[ChunkMeta] = []

    next_chunk_index = 1
    current_writer: ChunkWriter | None = None

    pending_conv_id: str | None = None
    pending_lines: list[BufferedLine] = []
    pending_tokens = 0

    def _ensure_writer() -> ChunkWriter:
        nonlocal current_writer, next_chunk_index
        if current_writer is None:
            chunk_id = f"chunk_{next_chunk_index:04d}"
            dest = chunks_dir / f"{chunk_id}.jsonl"
            current_writer = ChunkWriter(chunk_id=chunk_id, dest_path=dest)
            next_chunk_index += 1
        return current_writer

    def _finalize_writer() -> None:
        nonlocal current_writer
        if current_writer is None:
            return
        if current_writer.message_count == 0:
            # Avoid emitting empty files.
            try:
                current_writer.tmp_path.unlink()
            except FileNotFoundError:
                pass
            current_writer = None
            return

        meta = current_writer.finalize()
        metas.append(meta)
        stats.chunks += 1
        current_writer = None

    def _write_line(line: BufferedLine) -> None:
        if line.tokens > max_tokens:
            raise ValueError(
                f"Single message exceeds max token budget ({line.tokens} > {max_tokens}) for "
                f"conv_id={line.conv_id} message_id={line.message_id}. "
                "Reduce message size via build_view.py (e.g., --max-message-chars) or increase --max-tokens."
            )

        w = _ensure_writer()
        if w.message_count > 0 and w.token_estimate + line.tokens > max_tokens:
            _finalize_writer()
            w = _ensure_writer()
        w.write(line)
        stats.messages_out += 1

    def _emit_conversation_buffer(*, conv_tokens: int) -> None:
        nonlocal pending_lines, pending_tokens
        if not pending_lines:
            return

        fits_as_unit = conv_tokens <= max_tokens

        if fits_as_unit and current_writer is not None and current_writer.message_count > 0:
            if current_writer.token_estimate + conv_tokens > max_tokens:
                _finalize_writer()

        for bl in pending_lines:
            _write_line(bl)

        pending_lines = []
        pending_tokens = 0

    started_at = time.time()
    input_stat = input_jsonl.stat()

    with input_jsonl.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            if max_messages is not None and stats.messages_in >= max_messages:
                break
            stats.messages_in += 1

            line = _normalize_jsonl_line(raw_line)

            try:
                conv_id, message_id, ts = _parse_record(line)
            except Exception as e:
                stats.invalid_lines += 1
                if skip_invalid:
                    print(f"[chunk_messages] skipping invalid line {line_no}: {e}", file=sys.stderr)
                    continue
                raise

            tokens = token_counter.count(line)
            bl = BufferedLine(raw=line, tokens=tokens, conv_id=conv_id, message_id=message_id, ts=ts)

            # Conversation boundary handling.
            if pending_conv_id is None:
                pending_conv_id = conv_id
                stats.conversations_seen += 1
            elif conv_id != pending_conv_id:
                _emit_conversation_buffer(conv_tokens=pending_tokens)
                pending_conv_id = conv_id
                stats.conversations_seen += 1

            pending_lines.append(bl)
            pending_tokens += tokens

            # If the conversation is already overbudget, start streaming it out now.
            if pending_tokens > max_tokens:
                _emit_conversation_buffer(conv_tokens=pending_tokens)

            if progress_every > 0 and stats.messages_in % progress_every == 0:
                print(
                    f"[chunk_messages] messages={stats.messages_in} chunks={stats.chunks} "
                    f"conversations={stats.conversations_seen}",
                    file=sys.stderr,
                )

    # Flush any remaining buffered conversation and current chunk.
    _emit_conversation_buffer(conv_tokens=pending_tokens)
    _finalize_writer()

    duration_s = round(time.time() - started_at, 3)

    manifest: dict[str, Any] = {
        "tool": "chunk_messages",
        "version": 1,
        "created_at": _now_utc_iso(),
        "input": {
            "path": str(input_jsonl),
            "size_bytes": input_stat.st_size,
            "mtime": input_stat.st_mtime,
        },
        "config": {
            "max_tokens": max_tokens,
            "encoding": token_counter.encoding_name,
        },
        "counts": {
            "messages_in": stats.messages_in,
            "messages_out": stats.messages_out,
            "conversations_seen": stats.conversations_seen,
            "chunks": stats.chunks,
            "invalid_lines": stats.invalid_lines,
        },
        "timing": {
            "duration_s": duration_s,
        },
        "chunks": [
            {
                "chunk_id": m.chunk_id,
                "path": m.path,
                "sha256": m.sha256,
                "token_estimate": m.token_estimate,
                "message_count": m.message_count,
                "conv_ids": m.conv_ids,
                "first_ts": m.first_ts,
                "last_ts": m.last_ts,
                "first_message_id": m.first_message_id,
                "last_message_id": m.last_message_id,
            }
            for m in metas
        ],
        "finished_at": _now_utc_iso(),
    }

    _atomic_write_text(
        manifest_path,
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        overwrite=True,  # manifest is part of overwrite policy above
    )

    return stats, metas


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Token-aware chunking for manual/agent claim extraction.\n"
            "\n"
            "Reads work/<run-id>/messages_view.jsonl and writes:\n"
            "- work/<run-id>/chunks/chunk_0001.jsonl ...\n"
            "- work/<run-id>/chunks/manifest.json\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--run-dir", required=True, help="Run directory containing messages_view.jsonl.")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting chunks/ outputs in the run directory.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=180_000,
        help="Max token budget per chunk (default: 180000).",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="Model name for encoding selection (default: gpt-4o-mini).",
    )
    parser.add_argument(
        "--encoding",
        default=None,
        help="Override encoding name (e.g. o200k_base, cl100k_base).",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10_000,
        help="Print progress every N messages (0 disables).",
    )
    parser.add_argument(
        "--max-messages",
        type=int,
        default=None,
        help="Stop after N messages (debug/smoke test).",
    )
    parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help="Skip invalid JSONL lines instead of failing.",
    )
    args = parser.parse_args(argv)

    run_dir = Path(args.run_dir).resolve()
    input_jsonl = run_dir / "messages_view.jsonl"
    chunks_dir = run_dir / "chunks"
    manifest_path = chunks_dir / "manifest.json"

    if not input_jsonl.is_file():
        print(f"Input not found: {input_jsonl}", file=sys.stderr)
        print("Run build_view.py first to create messages_view.jsonl.", file=sys.stderr)
        return 2

    try:
        import tiktoken  # noqa: F401
    except ModuleNotFoundError:
        print(
            "Missing dependency: tiktoken\n"
            "\n"
            "Quick setup:\n"
            "  python3 -m venv .venv\n"
            "  .venv/bin/python -m ensurepip --upgrade\n"
            "  .venv/bin/python -m pip install tiktoken\n"
            "\n"
            "Then run:\n"
            "  .venv/bin/python tools/pipeline/chunk_messages.py --run-dir work/<run-id>\n",
            file=sys.stderr,
        )
        return 2

    token_counter = TokenCounter.from_args(model=args.model, encoding=args.encoding)

    started = time.time()
    try:
        stats, metas = chunk_messages(
            input_jsonl=input_jsonl,
            chunks_dir=chunks_dir,
            manifest_path=manifest_path,
            overwrite=args.overwrite,
            max_tokens=args.max_tokens,
            token_counter=token_counter,
            progress_every=args.progress_every,
            max_messages=args.max_messages,
            skip_invalid=args.skip_invalid,
        )
    except FileExistsError as e:
        print(str(e), file=sys.stderr)
        return 2

    duration = round(time.time() - started, 3)
    print(f"Wrote {len(metas)} chunk(s) to: {chunks_dir}")
    print(f"Wrote: {manifest_path}")
    print(
        f"Done in {duration}s (messages_in={stats.messages_in}, messages_out={stats.messages_out}, "
        f"chunks={stats.chunks}, encoding={token_counter.encoding_name})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

