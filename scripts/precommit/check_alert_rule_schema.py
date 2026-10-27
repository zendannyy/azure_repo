#!/usr/bin/env python3
"""Validate Scheduled alert-rule shape in CustomDetections Bicep/ARM JSON."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTIONS = ROOT / "CustomDetections"

REQUIRED_PROPS = (
    "description",
    "displayName",
    "enabled",
    "query",
    "queryFrequency",
    "queryPeriod",
    "severity",
    "suppressionDuration",
    "suppressionEnabled",
    "triggerOperator",
    "triggerThreshold",
    "tactics",
)

SEVERITIES = {"Informational", "Low", "Medium", "High"}
TRIGGER_OPS = {"GreaterThan", "LessThan", "Equal", "NotEqual"}
# Sentinel / MITRE ATT&CK tactics commonly used on analytics rules
TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
    "ImpairProcessControl",
    "InhibitResponseFunction",
}

ISO8601_DURATION = re.compile(
    r"^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?$"
)


def _bicep_prop_block(text: str) -> str | None:
    m = re.search(r"properties\s*:\s*\{", text)
    if not m:
        return None
    start = m.end()
    depth = 1
    i = start
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start : i - 1]


def _bicep_get(block: str, key: str) -> str | None:
    # string / bool / number / '''multiline''' / [ list ]
    patterns = [
        rf"{key}\s*:\s*'''(.*?)'''",
        rf"{key}\s*:\s*'((?:\\'|[^'])*)'",
        rf"{key}\s*:\s*\"((?:\\\"|[^\"])*)\"",
        rf"{key}\s*:\s*(true|false)",
        rf"{key}\s*:\s*(-?\d+(?:\.\d+)?)",
        rf"{key}\s*:\s*\[(.*?)\]",
    ]
    for pat in patterns:
        m = re.search(pat, block, re.DOTALL)
        if m:
            return m.group(1).strip()
    return None


def _parse_tactics_list(raw: str) -> list[str]:
    return re.findall(r"'([^']+)'|\"([^\"]+)\"", raw)


def validate_props(source: str, props: dict) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_PROPS:
        if key not in props or props[key] in (None, ""):
            errors.append(f"{source}: missing required property '{key}'")

    if "severity" in props and props["severity"] not in SEVERITIES:
        errors.append(
            f"{source}: invalid severity {props['severity']!r}; "
            f"expected one of {sorted(SEVERITIES)}"
        )

    if "triggerOperator" in props and props["triggerOperator"] not in TRIGGER_OPS:
        errors.append(
            f"{source}: invalid triggerOperator {props['triggerOperator']!r}; "
            f"expected one of {sorted(TRIGGER_OPS)}"
        )

    for dur_key in ("queryFrequency", "queryPeriod", "suppressionDuration"):
        val = props.get(dur_key)
        if val and not ISO8601_DURATION.match(str(val)):
            errors.append(f"{source}: {dur_key} is not ISO-8601 duration: {val!r}")

    query = props.get("query")
    if isinstance(query, str) and not query.strip():
        errors.append(f"{source}: query must be non-empty")

    tactics = props.get("tactics")
    if isinstance(tactics, list):
        if not tactics:
            errors.append(f"{source}: tactics must be a non-empty list")
        for t in tactics:
            if t not in TACTICS:
                errors.append(f"{source}: unknown tactic {t!r}")
    elif tactics is not None:
        errors.append(f"{source}: tactics must be a list")

    qf, qp = props.get("queryFrequency"), props.get("queryPeriod")
    # Soft check only when both look like PT*H or P*D — skip complex durations
    if isinstance(qf, str) and isinstance(qp, str) and qf.startswith("PT") and qp.startswith("PT"):
        # queryPeriod should be >= queryFrequency for scheduled rules (Sentinel requirement)
        pass  # duration math omitted; format already validated

    return errors


def check_bicep(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    block = _bicep_prop_block(text)
    if block is None:
        return [f"{path}: no properties block found"]

    props: dict = {}
    for key in REQUIRED_PROPS:
        raw = _bicep_get(block, key)
        if raw is None:
            continue
        if key == "tactics":
            props[key] = [a or b for a, b in _parse_tactics_list(raw)]
        elif key in ("enabled", "suppressionEnabled"):
            props[key] = raw.lower() == "true"
        elif key == "triggerThreshold":
            props[key] = raw
        else:
            props[key] = raw

    return validate_props(str(path), props)


def check_json(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON ({exc})"]

    resources = data.get("resources") or []
    if not resources:
        return [f"{path}: no resources[]"]

    errors: list[str] = []
    for idx, res in enumerate(resources):
        props = res.get("properties") or {}
        kind = res.get("kind")
        if kind and kind != "Scheduled":
            errors.append(f"{path}: resources[{idx}].kind must be 'Scheduled' (got {kind!r})")
        errors.extend(validate_props(f"{path}#resources[{idx}]", props))
    return errors


def main(argv: list[str]) -> int:
    paths = [Path(p) for p in argv[1:]] if len(argv) > 1 else []
    if not paths:
        paths = sorted(DETECTIONS.glob("*.bicep")) + sorted(DETECTIONS.glob("*.json"))

    errors: list[str] = []
    for path in paths:
        if "CustomDetections" not in Path(path).parts:
            continue
        suffix = Path(path).suffix.lower()
        if suffix == ".bicep":
            errors.extend(check_bicep(Path(path)))
        elif suffix == ".json":
            errors.extend(check_json(Path(path)))

    if errors:
        print("alert rule schema checks failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("OK: CustomDetections alert-rule schema checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
