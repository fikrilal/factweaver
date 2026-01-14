#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import subprocess
import sys
from typing import Iterable


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    summary: str
    detail: str | None = None


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _repo_root() -> str:
    p = _run_git(["rev-parse", "--show-toplevel"])
    if p.returncode != 0:
        raise RuntimeError(f"Not a git repo (git rev-parse failed): {p.stderr.strip()}")
    return p.stdout.strip()


def _check_ignored(paths: Iterable[str]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for path in paths:
        p = _run_git(["check-ignore", "-v", path])
        if p.returncode == 0:
            results.append(CheckResult(ok=True, summary=f"ignored: {path}"))
        else:
            results.append(
                CheckResult(
                    ok=False,
                    summary=f"not ignored: {path}",
                    detail="Add it to .gitignore to avoid committing personal data/artifacts.",
                )
            )
    return results


def _check_not_tracked(paths: Iterable[str]) -> list[CheckResult]:
    results: list[CheckResult] = []
    p = _run_git(["ls-files", "--", *paths])
    tracked = [line.strip() for line in p.stdout.splitlines() if line.strip()]
    if tracked:
        results.append(
            CheckResult(
                ok=False,
                summary="sensitive paths are tracked",
                detail="Tracked: " + ", ".join(tracked),
            )
        )
    else:
        results.append(CheckResult(ok=True, summary="no sensitive paths tracked"))
    return results


def _print_results(results: list[CheckResult], *, verbose: bool) -> int:
    ok = True
    for r in results:
        prefix = "OK " if r.ok else "ERR"
        print(f"{prefix} {r.summary}")
        if verbose and r.detail:
            print(f"    {r.detail}")
        ok = ok and r.ok
    return 0 if ok else 2


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "FactWeaver doctor: safety checks to prevent committing personal data.\n"
            "\n"
            "Examples:\n"
            "  tools/dev/doctor.py\n"
            "  tools/dev/doctor.py --verbose\n"
        )
    )
    parser.add_argument("--verbose", action="store_true", help="Print extra details on failures.")
    args = parser.parse_args(argv)

    try:
        root = _repo_root()
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 2

    print(f"Repo: {root}")

    sensitive_paths = [
        "conversations.json",
        "shared_conversations.json",
        "messages.jsonl",
        "messages_view.jsonl",
        "chunks/",
        "claims/",
        "out/",
        "facts.db",
        "work/",
    ]

    results: list[CheckResult] = []
    results.extend(_check_not_tracked(["conversations.json", "shared_conversations.json"]))
    results.extend(_check_ignored(sensitive_paths))

    return _print_results(results, verbose=args.verbose)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

