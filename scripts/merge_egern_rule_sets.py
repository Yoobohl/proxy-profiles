#!/usr/bin/env python3
# /// script
# dependencies = ["pyyaml>=6,<7"]
# ///
"""Merge Mihomo classical domain rules into an Egern-native rule set.

By default this merges rules/classical/web3.list into
rules/egern/cryptocurrency.yaml and writes a deterministic conversion report to
reports/egern/cryptocurrency-web3-merge.json.

Rule mappings:
    DOMAIN         -> domain_set (exact domain)
    DOMAIN-SUFFIX  -> domain_suffix_set
    DOMAIN-KEYWORD -> domain_keyword_set

PROCESS-NAME has no equivalent Egern domain rule and is skipped with each
original rule recorded in the report. Unknown rule types, malformed rows, or
extra qualifiers are reported as errors; in that case the output rule set is
not overwritten.

Run from any directory with:
    uv run /path/to/proxy-profiles/scripts/merge_egern_rule_sets.py

Optional --source arguments can be repeated to merge additional classical
rule lists. Entries are appended in source order within their Egern field;
only exact duplicate values in the same field are removed.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
FIELD_ORDER = (
    "domain_set",
    "domain_keyword_set",
    "domain_suffix_set",
    "domain_regex_set",
    "domain_wildcard_set",
    "ip_cidr_set",
    "ip_cidr6_set",
)
CLASSIC_DOMAIN_RULES = {
    "DOMAIN": "domain_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
}
UNSUPPORTED_RULES = {
    "PROCESS-NAME": "Egern has no equivalent process-name matcher.",
}
DEFAULT_BASE = Path("rules/egern/cryptocurrency.yaml")
DEFAULT_SOURCE = Path("rules/classical/web3.list")
DEFAULT_OUTPUT = Path("rules/egern/cryptocurrency.yaml")
DEFAULT_REPORT = Path("reports/egern/cryptocurrency-web3-merge.json")


def resolve_path(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


def load_egern_rule_set(path: Path) -> dict[str, list[str]]:
    parsed = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(parsed, dict) or not set(parsed).issubset(FIELD_ORDER):
        raise ValueError(f"{display_path(path)} is not an Egern domain rule set")

    result: dict[str, list[str]] = {}
    for field in FIELD_ORDER:
        values = parsed.get(field, [])
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError(f"{display_path(path)}: {field} must be a list of strings")
        result[field] = list(values)
    return result


def parse_classical_list(path: Path) -> tuple[dict[str, list[str]], Counter[str], list[dict[str, Any]], list[dict[str, Any]]]:
    parsed = {field: [] for field in FIELD_ORDER}
    counts: Counter[str] = Counter()
    unsupported: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue

        try:
            columns = next(csv.reader([line], skipinitialspace=True))
        except csv.Error as exc:
            errors.append({"line": line_number, "raw": raw_line, "reason": f"invalid CSV: {exc}"})
            continue
        if not columns:
            continue

        rule_type = columns[0].strip().upper()
        if rule_type in UNSUPPORTED_RULES:
            counts[rule_type] += 1
            if len(columns) != 2 or not columns[1].strip():
                errors.append({
                    "line": line_number,
                    "raw": raw_line,
                    "reason": f"{rule_type} must contain exactly one non-empty value",
                })
            else:
                unsupported.append({
                    "line": line_number,
                    "rule": raw_line.strip(),
                    "reason": UNSUPPORTED_RULES[rule_type],
                })
            continue

        field = CLASSIC_DOMAIN_RULES.get(rule_type)
        if field is None:
            errors.append({
                "line": line_number,
                "raw": raw_line,
                "reason": f"unsupported Mihomo rule type {rule_type!r}",
            })
            continue
        counts[rule_type] += 1
        if len(columns) != 2:
            errors.append({
                "line": line_number,
                "raw": raw_line,
                "reason": f"{rule_type} must contain exactly two CSV columns; qualifiers are not discarded",
            })
            continue

        value = columns[1].strip()
        if not value or any(character.isspace() for character in value):
            errors.append({
                "line": line_number,
                "raw": raw_line,
                "reason": f"invalid empty or whitespace-containing {rule_type} value",
            })
            continue
        parsed[field].append(value)

    return parsed, counts, unsupported, errors


def emit_rule_set(rule_set: dict[str, list[str]]) -> bytes:
    lines: list[str] = []
    for field in FIELD_ORDER:
        values = rule_set[field]
        if not values:
            continue
        lines.append(f'"{field}":')
        lines.extend(f"  - {json.dumps(value, ensure_ascii=False)}" for value in values)
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE, help="existing Egern YAML rule set")
    parser.add_argument(
        "--source",
        type=Path,
        action="append",
        help="Mihomo classical rule list to merge; may be repeated (default: rules/classical/web3.list)",
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="merged Egern YAML output")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="JSON conversion report")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    base_path = resolve_path(args.base)
    source_paths = [resolve_path(path) for path in (args.source or [DEFAULT_SOURCE])]
    output_path = resolve_path(args.output)
    report_path = resolve_path(args.report)

    if output_path.resolve() == report_path.resolve():
        print("error: output and report paths must be different", file=sys.stderr)
        return 2

    try:
        base = load_egern_rule_set(base_path)
        merged = {field: list(base[field]) for field in FIELD_ORDER}
        source_details: list[dict[str, Any]] = []
        unsupported_rules: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        incoming = {field: [] for field in FIELD_ORDER}

        for source_path in source_paths:
            if not source_path.is_file():
                errors.append({"source": display_path(source_path), "reason": "source file does not exist"})
                source_details.append({"path": display_path(source_path), "rule_counts": {}})
                continue
            parsed, counts, unsupported, source_errors = parse_classical_list(source_path)
            source_details.append({
                "path": display_path(source_path),
                "rule_counts": dict(sorted(counts.items())),
            })
            unsupported_rules.extend(
                {"source": display_path(source_path), **entry} for entry in unsupported
            )
            errors.extend(
                {"source": display_path(source_path), **entry} for entry in source_errors
            )
            for field in FIELD_ORDER:
                incoming[field].extend(parsed[field])

        # Preserve base-list order, then append converted sources in their input
        # order. De-duplicate only identical values in the same Egern field.
        output_counts: dict[str, int] = {}
        for field in FIELD_ORDER:
            seen: set[str] = set()
            unique: list[str] = []
            for value in [*merged[field], *incoming[field]]:
                if value not in seen:
                    unique.append(value)
                    seen.add(value)
            merged[field] = unique
            if unique:
                output_counts[field] = len(unique)

        report: dict[str, Any] = {
            "status": "conversion_errors" if errors else (
                "converted_with_reported_unsupported_rules" if unsupported_rules else "converted"
            ),
            "base": display_path(base_path),
            "sources": source_details,
            "output": display_path(output_path),
            "output_rule_counts": output_counts,
            "unsupported_rules": unsupported_rules,
            "errors": errors,
        }
        report_bytes = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        atomic_write(report_path, report_bytes)

        if errors:
            print(
                f"error: {len(errors)} rule-list issue(s); output was not overwritten. See {display_path(report_path)}",
                file=sys.stderr,
            )
            return 2

        output_bytes = emit_rule_set(merged)
        reparsed = yaml.safe_load(output_bytes.decode("utf-8"))
        expected = {field: merged[field] for field in FIELD_ORDER if merged[field]}
        if reparsed != expected:
            raise ValueError("emitted YAML did not round-trip to the merged Egern rule set")
        atomic_write(output_path, output_bytes)

        unsupported_count = len(unsupported_rules)
        print(
            f"Wrote {display_path(output_path)} ({sum(output_counts.values())} entries across "
            f"{len(output_counts)} fields); report: {display_path(report_path)}"
        )
        if unsupported_count:
            print(
                f"Warning: skipped {unsupported_count} unsupported rule(s); details are recorded in the report.",
                file=sys.stderr,
            )
        return 0
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
