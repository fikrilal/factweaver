#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys


@dataclass(frozen=True)
class CountResult:
    path: str
    byte_count: int
    char_count: int
    token_count: int
    encoding: str


def _read_text(path: str) -> tuple[str, int]:
    if path == "-":
        data = sys.stdin.buffer.read()
    else:
        file_path = Path(path)
        byte_count = file_path.stat().st_size
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read(), byte_count

    try:
        return data.decode("utf-8"), len(data)
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), len(data)


def _get_encoding(*, model: str | None, encoding: str | None) -> "tiktoken.Encoding":
    import tiktoken

    if encoding:
        return tiktoken.get_encoding(encoding)

    if model:
        try:
            return tiktoken.encoding_for_model(model)
        except KeyError:
            # tiktoken may not recognize very new model aliases; fall back below.
            pass

    return tiktoken.get_encoding("o200k_base")


def count_tokens(path: str, *, model: str | None, encoding: str | None) -> CountResult:
    text, byte_count = _read_text(path)
    enc = _get_encoding(model=model, encoding=encoding)
    # Avoid allocating a huge Python list of token IDs for large inputs.
    # `encode_to_tiktoken_buffer` returns a compact buffer of uint32 token IDs.
    token_buf = enc._core_bpe.encode_to_tiktoken_buffer(text, set())
    token_count = memoryview(token_buf).nbytes // 4

    return CountResult(
        path=path,
        byte_count=byte_count,
        char_count=len(text),
        token_count=token_count,
        encoding=enc.name,
    )


def main(argv: list[str]) -> int:
    default_paths: list[str] = []
    if Path("conversations.json").is_file():
        default_paths = ["conversations.json"]
    elif Path("shared_conversations.json").is_file():
        default_paths = ["shared_conversations.json"]

    parser = argparse.ArgumentParser(
        description=(
            "Count tokens for one or more files using OpenAI's tiktoken encoder.\n"
            "\n"
            "Examples:\n"
            "  tools/count_tokens.py shared_conversations.json\n"
            "  tools/count_tokens.py export.json --model gpt-4o\n"
            "  tools/count_tokens.py export.json --encoding cl100k_base\n"
            "  cat export.json | tools/count_tokens.py -\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=default_paths,
        help="File paths to count, or '-' for stdin.",
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
    args = parser.parse_args(argv)

    if not args.paths:
        parser.error("No input files provided (e.g. tools/count_tokens.py conversations.json)")

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
            "  .venv/bin/python tools/count_tokens.py shared_conversations.json\n",
            file=sys.stderr,
        )
        return 2

    results: list[CountResult] = []
    for path in args.paths:
        results.append(count_tokens(path, model=args.model, encoding=args.encoding))

    total_bytes = sum(r.byte_count for r in results)
    total_chars = sum(r.char_count for r in results)
    total_tokens = sum(r.token_count for r in results)

    for r in results:
        print(
            f"{r.path}: {r.token_count} tokens ({r.byte_count} bytes, {r.char_count} chars, {r.encoding})"
        )

    if len(results) > 1:
        print(f"TOTAL: {total_tokens} tokens ({total_bytes} bytes, {total_chars} chars)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
