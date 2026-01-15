#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Pattern


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


def _atomic_open_for_write(path: Path, *, overwrite: bool) -> tuple[Path, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(str(path))

    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    f = tmp.open("w", encoding="utf-8")
    return tmp, f


def _finalize_atomic(tmp: Path, dest: Path) -> None:
    tmp.replace(dest)


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: Pattern[str]
    replacer: str | Callable[[re.Match[str]], str]


def _redact_bearer(m: re.Match[str]) -> str:
    # Keep the header text and redact only the token.
    prefix = m.group(0)
    token = m.group(1)
    return prefix.replace(token, "[REDACTED]")


def _redact_kv(m: re.Match[str]) -> str:
    # group1=key, group2=separator+whitespace, group3=value
    return f"{m.group(1)}{m.group(2)}[REDACTED]"


def _build_rules(*, redact_pii: bool) -> list[RedactionRule]:
    rules: list[RedactionRule] = [
        RedactionRule(
            name="private_key_block",
            pattern=re.compile(
                r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                re.DOTALL,
            ),
            replacer="[REDACTED]",
        ),
        RedactionRule(
            name="jwt",
            pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            replacer="[REDACTED]",
        ),
        RedactionRule(
            name="openai_key",
            pattern=re.compile(r"\bsk-[A-Za-z0-9-]{10,}\b"),
            replacer="[REDACTED]",
        ),
        RedactionRule(
            name="slack_token",
            pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
            replacer="[REDACTED]",
        ),
        RedactionRule(
            name="aws_access_key_id",
            pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            replacer="[REDACTED]",
        ),
        RedactionRule(
            name="github_token",
            pattern=re.compile(r"\b(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"),
            replacer="[REDACTED]",
        ),
        RedactionRule(
            name="google_api_key",
            pattern=re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"),
            replacer="[REDACTED]",
        ),
        RedactionRule(
            name="authorization_bearer",
            pattern=re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)"),
            replacer=_redact_bearer,
        ),
        RedactionRule(
            name="secret_kv",
            pattern=re.compile(
                r"(?i)\b(api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|passwd|pwd)\b(\s*[:=]\s*)([^\s'\"\\]+)"
            ),
            replacer=_redact_kv,
        ),
    ]

    if redact_pii:
        rules.extend(
            [
                RedactionRule(
                    name="email",
                    pattern=re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
                    replacer="[REDACTED]",
                ),
                RedactionRule(
                    name="phone_like",
                    pattern=re.compile(r"(?<!\w)(\+?\d[\d \-()]{8,}\d)(?!\w)"),
                    replacer=lambda m: _redact_phone_candidate(m.group(1)),
                ),
            ]
        )

    return rules


def _redact_phone_candidate(candidate: str) -> str:
    digits = [c for c in candidate if c.isdigit()]
    digit_count = len(digits)
    has_separators = candidate.startswith("+") or any(sep in candidate for sep in (" ", "-", "(", ")"))
    if has_separators and 10 <= digit_count <= 15:
        return "[REDACTED]"
    return candidate


def redact_text(text: str, *, redact_pii: bool) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    rules = _build_rules(redact_pii=redact_pii)

    out = text
    for rule in rules:
        if isinstance(rule.replacer, str):
            out, n = rule.pattern.subn(rule.replacer, out)
            if n:
                counts[rule.name] = counts.get(rule.name, 0) + n
            continue

        local_count = 0

        def _wrapped(m: re.Match[str]) -> str:
            nonlocal local_count
            replacement = rule.replacer(m)
            if replacement != m.group(0):
                local_count += 1
            return replacement

        out = rule.pattern.sub(_wrapped, out)
        if local_count:
            counts[rule.name] = counts.get(rule.name, 0) + local_count
    return out, counts


def _sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()


def elide_large_code_blocks(text: str, *, max_codeblock_lines: int) -> tuple[str, int]:
    if max_codeblock_lines <= 0:
        return text, 0

    lines = text.splitlines(keepends=True)
    out: list[str] = []

    in_fence = False
    fence_open_line = ""
    code_lines: list[str] = []
    elided = 0

    def _is_fence(line: str) -> bool:
        return line.lstrip().startswith("```")

    for line in lines:
        if not in_fence:
            if _is_fence(line):
                in_fence = True
                fence_open_line = line
                code_lines = []
            else:
                out.append(line)
            continue

        # Inside a fenced block.
        if _is_fence(line):
            fence_close_line = line
            code_line_count = len(code_lines)
            if code_line_count > max_codeblock_lines:
                lang = fence_open_line.strip()[3:].strip() or None
                h = _sha256_str("".join(code_lines))[:12]
                marker = f"[OMITTED CODE BLOCK: {code_line_count} lines, sha256={h}"
                if lang:
                    marker += f", lang={lang}"
                marker += "]\n"
                out.append(fence_open_line)
                out.append(marker)
                out.append(fence_close_line)
                elided += 1
            else:
                out.append(fence_open_line)
                out.extend(code_lines)
                out.append(fence_close_line)

            in_fence = False
            fence_open_line = ""
            code_lines = []
            continue

        code_lines.append(line)

    # Unbalanced fence: keep as-is.
    if in_fence:
        out.append(fence_open_line)
        out.extend(code_lines)

    return "".join(out), elided


def truncate_long_message(text: str, *, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0 or len(text) <= max_chars:
        return text, False

    # Keep a stable amount of head/tail and insert a marker in the middle.
    marker_reserve = 64
    if max_chars <= marker_reserve:
        return text[:max_chars], True

    keep_total = max_chars - marker_reserve
    keep_head = keep_total // 2
    keep_tail = keep_total - keep_head
    omitted = max(0, len(text) - keep_head - keep_tail)
    marker = f"\n[OMITTED: {omitted} chars]\n"
    truncated = text[:keep_head] + marker + text[-keep_tail:]

    if len(truncated) > max_chars:
        truncated = truncated[:max_chars]
    return truncated, True


@dataclass
class BuildViewStats:
    messages_in: int = 0
    messages_out: int = 0
    messages_changed: int = 0
    invalid_lines: int = 0
    chars_in: int = 0
    chars_out: int = 0
    redactions: dict[str, int] | None = None
    code_blocks_elided: int = 0
    messages_truncated: int = 0

    def __post_init__(self) -> None:
        if self.redactions is None:
            self.redactions = {}


def build_view(
    *,
    input_jsonl: Path,
    output_jsonl: Path,
    manifest_path: Path,
    overwrite: bool,
    redact_pii: bool,
    max_codeblock_lines: int,
    max_message_chars: int,
    progress_every: int,
    max_messages: int | None,
    skip_invalid: bool,
) -> BuildViewStats:
    stats = BuildViewStats()

    tmp_out, out_f = _atomic_open_for_write(output_jsonl, overwrite=overwrite)
    try:
        with input_jsonl.open("r", encoding="utf-8") as in_f:
            for line_no, line in enumerate(in_f, start=1):
                if max_messages is not None and stats.messages_in >= max_messages:
                    break

                stats.messages_in += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    stats.invalid_lines += 1
                    if skip_invalid:
                        print(f"[build_view] skipping invalid JSON line {line_no}: {e}", file=sys.stderr)
                        continue
                    raise

                if not isinstance(record, dict):
                    stats.invalid_lines += 1
                    if skip_invalid:
                        continue
                    raise ValueError(f"Line {line_no}: expected JSON object, got {type(record)}")

                text = record.get("text")
                if not isinstance(text, str):
                    text = ""

                stats.chars_in += len(text)

                new_text = text
                redacted_text, redaction_counts = redact_text(new_text, redact_pii=redact_pii)
                new_text = redacted_text
                for k, v in redaction_counts.items():
                    stats.redactions[k] = stats.redactions.get(k, 0) + v

                new_text, elided = elide_large_code_blocks(new_text, max_codeblock_lines=max_codeblock_lines)
                stats.code_blocks_elided += elided

                new_text, truncated = truncate_long_message(new_text, max_chars=max_message_chars)
                if truncated:
                    stats.messages_truncated += 1

                if new_text != text:
                    stats.messages_changed += 1

                record["text"] = new_text
                out_f.write(json.dumps(record, ensure_ascii=False) + "\n")
                stats.messages_out += 1
                stats.chars_out += len(new_text)

                if progress_every > 0 and stats.messages_in % progress_every == 0:
                    print(
                        f"[build_view] messages={stats.messages_in} changed={stats.messages_changed} "
                        f"redactions={sum(stats.redactions.values())} elided={stats.code_blocks_elided} "
                        f"truncated={stats.messages_truncated}",
                        file=sys.stderr,
                    )
    finally:
        out_f.close()

    _finalize_atomic(tmp_out, output_jsonl)

    input_stat = input_jsonl.stat()
    manifest: dict[str, Any] = {
        "tool": "build_view",
        "version": 1,
        "created_at": _now_utc_iso(),
        "input": {
            "path": str(input_jsonl),
            "size_bytes": input_stat.st_size,
            "mtime": input_stat.st_mtime,
        },
        "output": {
            "messages_view_jsonl": str(output_jsonl),
        },
        "config": {
            "redact_pii": redact_pii,
            "max_codeblock_lines": max_codeblock_lines,
            "max_message_chars": max_message_chars,
            "skip_invalid": skip_invalid,
        },
        "counts": {
            "messages_in": stats.messages_in,
            "messages_out": stats.messages_out,
            "messages_changed": stats.messages_changed,
            "invalid_lines": stats.invalid_lines,
            "code_blocks_elided": stats.code_blocks_elided,
            "messages_truncated": stats.messages_truncated,
            "chars_in": stats.chars_in,
            "chars_out": stats.chars_out,
            "redactions": stats.redactions,
        },
        "finished_at": _now_utc_iso(),
    }

    _atomic_write_text(
        manifest_path,
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        overwrite=overwrite,
    )

    return stats


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build an LLM-safe view of messages.jsonl by applying redaction and conservative trimming.\n"
            "\n"
            "Typical usage:\n"
            "  python3 tools/pipeline/build_view.py --run-dir work/run_YYYYMMDD_HHMMSSZ\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--run-dir", required=True, help="Run directory containing messages.jsonl.")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting messages_view.jsonl and manifest in the run directory.",
    )
    parser.add_argument(
        "--redact-pii",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Redact emails/phone-like numbers (default: true).",
    )
    parser.add_argument(
        "--max-codeblock-lines",
        type=int,
        default=120,
        help="Elide fenced code blocks with more than N lines (0 disables).",
    )
    parser.add_argument(
        "--max-message-chars",
        type=int,
        default=50_000,
        help="Truncate messages longer than N chars (0 disables).",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=5_000,
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
    input_jsonl = run_dir / "messages.jsonl"
    output_jsonl = run_dir / "messages_view.jsonl"
    manifest_path = run_dir / "manifest.build_view.json"

    if not input_jsonl.is_file():
        print(f"Input not found: {input_jsonl}", file=sys.stderr)
        return 2

    started = time.time()
    try:
        build_view(
            input_jsonl=input_jsonl,
            output_jsonl=output_jsonl,
            manifest_path=manifest_path,
            overwrite=args.overwrite,
            redact_pii=args.redact_pii,
            max_codeblock_lines=args.max_codeblock_lines,
            max_message_chars=args.max_message_chars,
            progress_every=args.progress_every,
            max_messages=args.max_messages,
            skip_invalid=args.skip_invalid,
        )
    except FileExistsError as e:
        print(f"Refusing to overwrite existing file: {e}", file=sys.stderr)
        print("Pass --overwrite to replace it.", file=sys.stderr)
        return 2

    duration = round(time.time() - started, 3)
    print(f"Wrote: {output_jsonl}")
    print(f"Wrote: {manifest_path}")
    print(f"Done in {duration}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
