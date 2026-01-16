#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time
from typing import Any, Iterable, Literal


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


Level = Literal["error", "warning"]


@dataclass(frozen=True)
class Issue:
    level: Level
    code: str
    file: str
    line: int | None
    message: str


@dataclass
class FileSummary:
    path: str
    lines_total: int = 0
    lines_blank: int = 0
    claims_parsed: int = 0
    claims_valid: int = 0
    errors: int = 0
    warnings: int = 0


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


PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("phone_like", re.compile(r"(?<!\w)(\+?\d[\d \-()]{8,}\d)(?!\w)")),
]


SECRET_KV_PATTERN = re.compile(
    r"(?i)\b(api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|passwd|pwd)\b(\s*[:=]\s*)([^\s'\"\\]+)"
)


def _looks_high_entropy(value: str) -> bool:
    if value == "[REDACTED]":
        return False
    if len(value) < 20:
        return False
    # Base64-ish / token-ish strings.
    if re.fullmatch(r"[A-Za-z0-9+/_\-=]{20,}", value):
        return True
    return False


def _scan_text(text: str) -> tuple[list[str], list[str], list[str]]:
    secret_hits: list[str] = []
    pii_hits: list[str] = []
    kv_hits: list[str] = []

    for code, pat in SECRET_PATTERNS:
        if pat.search(text):
            secret_hits.append(code)

    for code, pat in PII_PATTERNS:
        if pat.search(text):
            pii_hits.append(code)

    # Generic key/value secrets: only treat as secret if high-entropy.
    for m in SECRET_KV_PATTERN.finditer(text):
        value = m.group(3)
        if value == "[REDACTED]" or "[REDACTED]" in value:
            continue
        if _looks_high_entropy(value):
            kv_hits.append("secret_kv_high_entropy")

    return secret_hits, kv_hits, pii_hits


def _is_code_fence_line(line: str) -> bool:
    return line.lstrip().startswith("```")


def _as_posix(path: Path) -> str:
    return path.as_posix()


def _require_str(obj: dict[str, Any], key: str) -> str | None:
    v = obj.get(key)
    if isinstance(v, str) and v.strip():
        return v
    return None


def _require_number(obj: dict[str, Any], key: str) -> float | None:
    v = obj.get(key)
    if isinstance(v, (int, float)):
        return float(v)
    return None


def validate_claim(
    *,
    claim: dict[str, Any],
    file: str,
    line_no: int,
    fail_on_warnings: bool,
) -> tuple[list[Issue], list[Issue]]:
    errors: list[Issue] = []
    warnings: list[Issue] = []

    def add(level: Level, code: str, message: str) -> None:
        issue = Issue(level=level, code=code, file=file, line=line_no, message=message)
        if level == "error":
            errors.append(issue)
        else:
            warnings.append(issue)

    category = _require_str(claim, "category")
    if category is None:
        add("error", "schema.category", "Missing/invalid `category` (expected non-empty string).")

    fact = _require_str(claim, "fact")
    if fact is None:
        add("error", "schema.fact", "Missing/invalid `fact` (expected non-empty string).")

    stability = _require_str(claim, "stability")
    if stability is None or stability not in {"stable", "transient"}:
        add(
            "error",
            "schema.stability",
            "Missing/invalid `stability` (expected 'stable' or 'transient').",
        )

    status = _require_str(claim, "status")
    if status is None or status not in {"accepted", "needs_review"}:
        add(
            "error",
            "schema.status",
            "Missing/invalid `status` (expected 'accepted' or 'needs_review').",
        )

    confidence = claim.get("confidence")
    if not isinstance(confidence, (int, float)):
        add("error", "schema.confidence", "Missing/invalid `confidence` (expected number in [0,1]).")
        confidence_f: float | None = None
    else:
        confidence_f = float(confidence)
        if not (0.0 <= confidence_f <= 1.0):
            add("error", "schema.confidence", "`confidence` out of range (expected [0,1]).")

    time_obj = claim.get("time")
    if not isinstance(time_obj, dict):
        add("error", "schema.time", "Missing/invalid `time` (expected object with `as_of_ts`).")
        as_of_ts = None
    else:
        as_of_ts = time_obj.get("as_of_ts")
        if not isinstance(as_of_ts, (int, float)):
            add("error", "schema.time.as_of_ts", "Missing/invalid `time.as_of_ts` (expected number).")

    derived_from = _require_str(claim, "derived_from")
    if derived_from is None or derived_from not in {"user", "assistant", "mixed"}:
        add(
            "error",
            "schema.derived_from",
            "Missing/invalid `derived_from` (expected 'user', 'assistant', or 'mixed').",
        )

    evidence = claim.get("evidence")
    if not isinstance(evidence, list):
        add("error", "schema.evidence", "Missing/invalid `evidence` (expected array).")
        evidence_items: list[dict[str, Any]] = []
    else:
        evidence_items = [e for e in evidence if isinstance(e, dict)]
        if len(evidence) == 0:
            add("error", "schema.evidence", "`evidence` must be non-empty.")
        elif len(evidence_items) != len(evidence):
            add("error", "schema.evidence.item", "`evidence` must contain only objects.")

    # Optional fields.
    tags = claim.get("tags")
    if tags is not None:
        if not isinstance(tags, list) or any(not isinstance(t, str) for t in tags):
            add("error", "schema.tags", "Invalid `tags` (expected string array).")

    notes = claim.get("notes")
    if notes is not None and not isinstance(notes, str):
        add("error", "schema.notes", "Invalid `notes` (expected string).")

    # Grounding policy.
    has_user_evidence = False
    for idx, ev in enumerate(evidence_items):
        role = ev.get("role")
        if role == "user":
            has_user_evidence = True

        if role not in {"user", "assistant"}:
            add("error", "evidence.role", f"Evidence[{idx}].role must be 'user' or 'assistant'.")

        quote = ev.get("quote")
        if not isinstance(quote, str) or not quote.strip():
            add("error", "evidence.quote", f"Evidence[{idx}].quote must be a non-empty string.")

        conv_id = ev.get("conv_id")
        if not isinstance(conv_id, str) or not conv_id.strip():
            add("error", "evidence.conv_id", f"Evidence[{idx}].conv_id must be a non-empty string.")

        message_id = ev.get("message_id")
        if not isinstance(message_id, str) or not message_id.strip():
            add("error", "evidence.message_id", f"Evidence[{idx}].message_id must be a non-empty string.")

        ts = ev.get("ts")
        if not isinstance(ts, (int, float)):
            add("error", "evidence.ts", f"Evidence[{idx}].ts must be a number.")

        # Safety scan for secrets/PII inside evidence quotes.
        if isinstance(quote, str):
            secret_hits, kv_hits, pii_hits = _scan_text(quote)
            for hit in secret_hits + kv_hits:
                add("error", f"safety.{hit}", "Secret-like content detected in evidence quote; redact it.")
            for hit in pii_hits:
                add("warning", f"privacy.{hit}", "PII-like content detected in evidence quote; consider redacting.")

    if derived_from in {"user", "mixed"} and not has_user_evidence:
        add("error", "grounding.user_evidence", "`derived_from` requires at least one user evidence quote.")

    # Agent-in-the-loop: assistant-derived items should not be accepted automatically.
    if derived_from == "assistant" and status == "accepted":
        add(
            "error",
            "grounding.assistant_status",
            "`derived_from:'assistant'` must use `status:'needs_review'`.",
        )

    # Safety scan for secrets/PII in fact/notes.
    if isinstance(fact, str):
        secret_hits, kv_hits, pii_hits = _scan_text(fact)
        for hit in secret_hits + kv_hits:
            add("error", f"safety.{hit}", "Secret-like content detected in `fact`; redact it.")
        for hit in pii_hits:
            add("warning", f"privacy.{hit}", "PII-like content detected in `fact`; consider redacting.")

    if isinstance(notes, str):
        secret_hits, kv_hits, pii_hits = _scan_text(notes)
        for hit in secret_hits + kv_hits:
            add("error", f"safety.{hit}", "Secret-like content detected in `notes`; redact it.")
        for hit in pii_hits:
            add("warning", f"privacy.{hit}", "PII-like content detected in `notes`; consider redacting.")

    if fail_on_warnings:
        errors.extend([Issue(level="error", code=w.code, file=w.file, line=w.line, message=w.message) for w in warnings])
        warnings = []

    return errors, warnings


def discover_claim_files(run_dir: Path) -> list[Path]:
    claims_dir = run_dir / "claims"
    if not claims_dir.is_dir():
        return []
    return sorted(claims_dir.glob("claims_chunk_*.jsonl"))


def validate_files(
    *,
    paths: Iterable[Path],
    report_path: Path,
    overwrite_report: bool,
    fail_on_warnings: bool,
    progress_every: int,
    skip_invalid: bool,
) -> int:
    repo_root = Path.cwd().resolve()

    started_at = time.time()
    started_at_iso = _now_utc_iso()

    issues: list[Issue] = []
    summaries: list[FileSummary] = []

    for path in paths:
        path = path.resolve()
        file_str = _as_posix(path.relative_to(repo_root) if path.is_relative_to(repo_root) else path)

        summary = FileSummary(path=file_str)
        summaries.append(summary)

        with path.open("r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                summary.lines_total += 1

                # Permit blank lines.
                if not raw_line.strip():
                    summary.lines_blank += 1
                    continue

                # Strongly suggest removing markdown wrapping fences.
                if _is_code_fence_line(raw_line):
                    issue = Issue(
                        level="error",
                        code="format.code_fence",
                        file=file_str,
                        line=line_no,
                        message="Markdown code fence detected. Output must be JSONL only (no ``` blocks).",
                    )
                    issues.append(issue)
                    summary.errors += 1
                    continue

                line = raw_line.lstrip("\ufeff").strip()
                if not line:
                    summary.lines_blank += 1
                    continue

                if not line.startswith("{"):
                    issue = Issue(
                        level="error",
                        code="format.non_json_object_line",
                        file=file_str,
                        line=line_no,
                        message="Each non-empty line must be a JSON object. Remove commentary and arrays.",
                    )
                    issues.append(issue)
                    summary.errors += 1
                    if skip_invalid:
                        continue

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    issue = Issue(
                        level="error",
                        code="format.json_parse",
                        file=file_str,
                        line=line_no,
                        message=f"Invalid JSON on this line: {e.msg}.",
                    )
                    issues.append(issue)
                    summary.errors += 1
                    if skip_invalid:
                        continue
                    continue

                if not isinstance(obj, dict):
                    issue = Issue(
                        level="error",
                        code="format.not_object",
                        file=file_str,
                        line=line_no,
                        message="Each line must be a JSON object (not an array/number/string).",
                    )
                    issues.append(issue)
                    summary.errors += 1
                    if skip_invalid:
                        continue
                    continue

                summary.claims_parsed += 1
                errs, warns = validate_claim(
                    claim=obj, file=file_str, line_no=line_no, fail_on_warnings=fail_on_warnings
                )
                issues.extend(errs)
                issues.extend(warns)
                summary.errors += len(errs)
                summary.warnings += len(warns)

                if not errs and not warns:
                    summary.claims_valid += 1

                if progress_every > 0 and summary.lines_total % progress_every == 0:
                    print(
                        f"[validate_claims] {file_str}: lines={summary.lines_total} "
                        f"errors={summary.errors} warnings={summary.warnings}",
                        file=sys.stderr,
                    )

    finished_at_iso = _now_utc_iso()
    duration_s = round(time.time() - started_at, 3)

    report: dict[str, Any] = {
        "tool": "validate_claims",
        "version": 1,
        "created_at": started_at_iso,
        "finished_at": finished_at_iso,
        "timing": {"duration_s": duration_s},
        "config": {
            "fail_on_warnings": fail_on_warnings,
            "skip_invalid": skip_invalid,
        },
        "summaries": [s.__dict__ for s in summaries],
        "issues": [i.__dict__ for i in issues],
    }

    _atomic_write_text(report_path, json.dumps(report, ensure_ascii=False, indent=2) + "\n", overwrite=overwrite_report)

    total_errors = sum(s.errors for s in summaries)
    total_warnings = sum(s.warnings for s in summaries)

    print(f"Wrote: {report_path}")
    print(f"Files: {len(summaries)}  Errors: {total_errors}  Warnings: {total_warnings}")

    if total_errors > 0:
        return 2
    if fail_on_warnings and total_warnings > 0:
        return 2
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate extracted claim JSONL (manual/agent output) before merging into the canonical store.\n"
            "\n"
            "Examples:\n"
            "  python3 tools/pipeline/validate_claims.py --run-dir work/<run-id>\n"
            "  python3 tools/pipeline/validate_claims.py --input work/<run-id>/claims/claims_chunk_0001.jsonl\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--run-dir", default=None, help="Run directory (validates claims/claims_chunk_*.jsonl).")
    parser.add_argument("--input", nargs="*", default=None, help="Explicit claim JSONL file(s) to validate.")
    parser.add_argument(
        "--report",
        default=None,
        help="Report path (default: run-dir/claims/validation_report.json or ./validation_report.json).",
    )
    parser.add_argument(
        "--overwrite-report",
        action="store_true",
        help="Allow overwriting the report file.",
    )
    parser.add_argument(
        "--fail-on-warnings",
        action="store_true",
        help="Treat warnings as errors (exit non-zero).",
    )
    parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help="Continue on invalid lines (still reports them as errors).",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=0,
        help="Print progress every N lines per file (0 disables).",
    )
    args = parser.parse_args(argv)

    input_paths: list[Path] = []
    run_dir: Path | None = Path(args.run_dir).resolve() if args.run_dir else None

    if args.input:
        input_paths.extend(Path(p).resolve() for p in args.input)
    elif run_dir is not None:
        input_paths = discover_claim_files(run_dir)
        if not input_paths:
            claims_dir = run_dir / "claims"
            print(f"No claim files found in: {claims_dir}", file=sys.stderr)
            print("Expected: claims/claims_chunk_*.jsonl", file=sys.stderr)
            return 2
    else:
        parser.error("Provide --run-dir or --input.")

    for p in input_paths:
        if not p.is_file():
            print(f"Input not found: {p}", file=sys.stderr)
            return 2

    if args.report:
        report_path = Path(args.report).resolve()
    elif run_dir is not None:
        report_path = (run_dir / "claims" / "validation_report.json").resolve()
    else:
        report_path = Path("validation_report.json").resolve()

    try:
        return validate_files(
            paths=input_paths,
            report_path=report_path,
            overwrite_report=args.overwrite_report,
            fail_on_warnings=args.fail_on_warnings,
            progress_every=args.progress_every,
            skip_invalid=args.skip_invalid,
        )
    except FileExistsError as e:
        print(f"Refusing to overwrite existing file: {e}", file=sys.stderr)
        print("Pass --overwrite-report to replace it.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
