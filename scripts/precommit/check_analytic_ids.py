#!/usr/bin/env python3
"""Ensure analytic_id UUIDs are unique across CustomDetections (Bicep + ARM JSON)."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTIONS = ROOT / "CustomDetections"

UUID_RE = re.compile(
    r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)
BICEP_ID_RE = re.compile(
    r"param\s+analytic_id\s+string\s*=\s*'([^']+)'",
    re.IGNORECASE,
)
JSON_ID_RE = re.compile(
    r'"analytic_id"\s*:\s*\{[^}]*?"defaultValue"\s*:\s*"([^"]+)"',
    re.DOTALL,
)


def extract_ids(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".bicep":
        return BICEP_ID_RE.findall(text)
    if path.suffix == ".json":
        return JSON_ID_RE.findall(text)
    return []


def main(argv: list[str]) -> int:
    paths = [Path(p) for p in argv[1:]] if len(argv) > 1 else []
    if not paths:
        paths = sorted(DETECTIONS.glob("*.bicep")) + sorted(DETECTIONS.glob("*.json"))

    seen: dict[str, list[str]] = {}
    errors: list[str] = []

    for path in paths:
        if "CustomDetections" not in path.parts:
            continue
        if path.name.lower().endswith(".json") and path.parent.name != "CustomDetections":
            continue
        for raw in extract_ids(path):
            if not UUID_RE.fullmatch(raw):
                errors.append(f"{path}: analytic_id is not a valid UUID: {raw!r}")
                continue
            key = raw.lower()
            seen.setdefault(key, []).append(str(path))

    for analytic_id, files in sorted(seen.items()):
        unique_files = sorted(set(files))
        # Same rule often has both .bicep and .json — allowed if exactly one logical rule.
        stems = {Path(f).stem.lower() for f in unique_files}
        if len(stems) > 1:
            errors.append(
                f"duplicate analytic_id {analytic_id} across rules: {', '.join(unique_files)}"
            )

    if errors:
        print("analytic_id checks failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: {len(seen)} unique analytic_id(s) in CustomDetections")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
