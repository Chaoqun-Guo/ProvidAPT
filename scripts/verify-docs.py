#!/usr/bin/env python3
"""Validate Markdown encoding and local links."""

import re
import sys
from pathlib import Path
from typing import List, Optional, Set


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_DIRS = [ROOT / "docs", ROOT / "examples"]
MOJIBAKE = (chr(0x00C3), chr(0x00C2), chr(0xFFFD))
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^#\s+\S+", re.MULTILINE)


def markdown_files() -> List[Path]:
    files: Set[Path] = set()
    files.update(path for path in ROOT.glob("*.md") if path.is_file())
    for base in MARKDOWN_DIRS:
        if base.exists():
            files.update(path for path in base.rglob("*.md") if ".git" not in path.parts)
    return sorted(files)


def local_link_target(path: Path, raw: str) -> Optional[Path]:
    target = raw.strip().split("#", 1)[0]
    if not target or target.startswith(("http://", "https://", "mailto:", "tel:")):
        return None
    if target.startswith("/"):
        return ROOT / target.lstrip("/")
    return (path.parent / target).resolve()


def main() -> int:
    failures: List[str] = []
    for path in markdown_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            failures.append(f"{path.relative_to(ROOT)}: invalid UTF-8: {exc}")
            continue
        if text.startswith("\ufeff"):
            failures.append(f"{path.relative_to(ROOT)}: UTF-8 BOM is not allowed")
        if path.suffix == ".md" and not HEADING_RE.search(text):
            failures.append(f"{path.relative_to(ROOT)}: missing top-level heading")
        for marker in MOJIBAKE:
            if marker in text:
                failures.append(f"{path.relative_to(ROOT)}: possible mojibake marker {marker!r}")
        for match in LINK_RE.finditer(text):
            target = local_link_target(path, match.group(1))
            if target and not target.exists():
                failures.append(f"{path.relative_to(ROOT)}: broken local link {match.group(1)!r}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"checked {len(markdown_files())} markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
