#!/usr/bin/env python3

from pathlib import Path
import sys

TEXT_EXTENSIONS = {
    ".go",
    ".md",
    ".txt",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".sh",
    ".py",
    ".proto",
    ".c",
    ".h",
    ".sql",
    ".conf",
    ".service",
    ".spec",
    ".tf",
    ".tpl",
}

SKIP_PARTS = {
    ".git",
    ".tmp-bin",
    ".tmp-gocache",
    ".tmp-gopath",
    ".tmp-gomodcache",
    ".tmp-golangci-cache",
    "build/bin",
    "scripts/verify-utf8.py",
    "pkg/api/proto/container/container.pb.go",
    "pkg/api/proto/mgmt/mgmt.pb.go",
    "test/integration/cluster_test.py",
    "test/integration/final_check.sh",
    "test/integration/full_validation.sh",
    "test/integration/supply_chain_test.sh",
}

MOJIBAKE_MARKERS = ("\u95c1", "\u95b3", "\u9225", "\u951f", "\ufffd")


def should_skip(path: Path) -> bool:
    path_str = path.as_posix()
    return any(part in path_str for part in SKIP_PARTS)


def iter_targets(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if should_skip(path):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name in {"Dockerfile", "Makefile", "LICENSE"}:
            yield path


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    invalid_utf8 = []
    suspicious_text = []

    for path in iter_targets(root):
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            invalid_utf8.append(path.as_posix())
            continue

        if any(marker in text for marker in MOJIBAKE_MARKERS):
            suspicious_text.append(path.as_posix())

    if invalid_utf8:
        print("Invalid UTF-8 files:")
        for item in invalid_utf8:
            print(f"  {item}")

    if suspicious_text:
        print("Suspicious mojibake markers found:")
        for item in suspicious_text:
            print(f"  {item}")

    return 1 if invalid_utf8 or suspicious_text else 0


if __name__ == "__main__":
    raise SystemExit(main())
