#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LANGUAGE_MANIFEST = ROOT / "shared/model/src/commonMain/resources/languages.json"
UI_CATALOG_DIR = ROOT / "shared/ui/src/commonMain/resources/i18n"
STATUS_CATALOG_DIR = ROOT / "shared/ui/src/commonMain/resources/i18n-status"

PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")
ALLOWED_IDENTICAL = {
    "",
    "VPN",
    "Proxy",
    "proxy",
    "QR",
    "TCP",
    "tcp",
    "OK",
    "ok",
    "ms",
    "VPN Control",
}
ALLOWED_IDENTICAL_UI_KEYS = {
    "BYTES_COUNT",
    "CLIPBOARD",
    "NAME",
    "PROXY",
    "QR",
    "SERVER",
    "SESSION",
    "SETTINGS_LANGUAGE_SYSTEM",
    "STATUS",
    "SYSTEM_APP",
}
ALLOWED_IDENTICAL_STATUS_ITEMS = {
    "benchmark.tcp",
    "benchmark.statuses.error",
    "benchmark.statuses.manual",
    "benchmark.statuses.ok",
    "benchmark.statuses.tcp_error",
    "benchmark.statuses.tcp_timeout",
    "dynamic.refreshIntervalHours",
    "dynamic.refreshIntervalHoursMinutes",
    "dynamic.refreshIntervalMinutes",
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"{path.relative_to(ROOT)}: invalid JSON: {error}") from error


def placeholders(value: str) -> set[str]:
    return set(PLACEHOLDER_RE.findall(value))


def unchanged_ui_value_is_allowed(key: str, value: str) -> bool:
    return value in ALLOWED_IDENTICAL or key in ALLOWED_IDENTICAL_UI_KEYS


def unchanged_status_value_is_allowed(item_name: str, value: str) -> bool:
    if value in ALLOWED_IDENTICAL:
        return True
    if item_name in ALLOWED_IDENTICAL_STATUS_ITEMS:
        return True
    if not item_name.startswith("structured."):
        return False
    literal = PLACEHOLDER_RE.sub("", value).strip()
    literal = re.sub(r"[\s:.,;!?()\[\]{}•|/\\-]+", "", literal)
    return literal in {"", "xhwid"}


def language_codes() -> list[str]:
    languages = load_json(LANGUAGE_MANIFEST)
    if not isinstance(languages, list):
        raise SystemExit("languages.json must be an array")
    codes = []
    seen_codes = set()
    seen_names = set()
    for index, language in enumerate(languages):
        if not isinstance(language, dict):
            raise SystemExit(f"languages.json entry {index} must be an object")
        enum_name = language.get("enumName")
        code = language.get("code")
        native_name = language.get("nativeName")
        if not isinstance(enum_name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", enum_name):
            raise SystemExit(f"languages.json entry {index} has invalid enumName")
        if not isinstance(code, str) or not (code == "" or re.fullmatch(r"[a-z]{2,3}", code)):
            raise SystemExit(f"languages.json entry {index} has invalid code")
        if not isinstance(native_name, str) or not native_name:
            raise SystemExit(f"languages.json entry {index} has invalid nativeName")
        if enum_name in seen_names:
            raise SystemExit(f"languages.json contains duplicate enumName {enum_name}")
        if code in seen_codes:
            raise SystemExit(f"languages.json contains duplicate code {code!r}")
        seen_names.add(enum_name)
        seen_codes.add(code)
        if code:
            codes.append(code)
    if "en" not in codes:
        raise SystemExit("languages.json must include English with code en")
    return codes


def validate_ui_catalog(code: str, english: dict[str, str], strict: bool) -> tuple[int, int, list[str], list[str]]:
    path = UI_CATALOG_DIR / f"{code}.json"
    if not path.exists():
        return 0, len(english), [f"missing UI catalog {path.relative_to(ROOT)}"], []
    catalog = load_json(path)
    if not isinstance(catalog, dict):
        return 0, len(english), [f"{path.relative_to(ROOT)} must be an object"], []

    errors = []
    warnings = []
    english_keys = set(english)
    keys = set(catalog)
    for key in sorted(english_keys - keys):
        errors.append(f"{path.relative_to(ROOT)} missing UI key {key}")
    for key in sorted(keys - english_keys):
        errors.append(f"{path.relative_to(ROOT)} contains unknown UI key {key}")

    translated = 0
    total = 0
    for key in sorted(english_keys & keys):
        source = english[key]
        target = catalog[key]
        total += 1
        if not isinstance(target, str):
            errors.append(f"{path.relative_to(ROOT)} key {key} must be a string")
            continue
        if placeholders(source) != placeholders(target):
            errors.append(
                f"{path.relative_to(ROOT)} key {key} placeholder mismatch: "
                f"{sorted(placeholders(source))} != {sorted(placeholders(target))}",
            )
        if code != "en" and target == source and not unchanged_ui_value_is_allowed(key, target):
            warnings.append(f"{path.relative_to(ROOT)} key {key} is unchanged from English")
        else:
            translated += 1

    if strict:
        errors.extend(warnings)
        warnings = []
    return translated, total, errors, warnings


def replacement_pairs(section: Any, path: Path, name: str) -> list[dict[str, str]]:
    if not isinstance(section, list):
        raise ValueError(f"{path.relative_to(ROOT)} {name} must be a list")
    pairs = []
    for index, item in enumerate(section):
        if not isinstance(item, dict):
            raise ValueError(f"{path.relative_to(ROOT)} {name}[{index}] must be an object")
        source = item.get("source")
        target = item.get("target")
        if not isinstance(source, str) or not isinstance(target, str):
            raise ValueError(f"{path.relative_to(ROOT)} {name}[{index}] must have string source/target")
        pairs.append({"source": source, "target": target})
    return pairs


def status_items(catalog: dict[str, Any]) -> list[tuple[str, str, str]]:
    items = []
    dynamic = catalog.get("dynamic", {})
    if isinstance(dynamic, dict):
        for key, value in dynamic.items():
            if isinstance(value, str):
                items.append((f"dynamic.{key}", value, value))
    benchmark = catalog.get("benchmark", {})
    if isinstance(benchmark, dict):
        for key in ("best", "primary", "secondary", "tcp", "millisUnit"):
            value = benchmark.get(key)
            if isinstance(value, str):
                items.append((f"benchmark.{key}", value, value))
        statuses = benchmark.get("statuses", {})
        if isinstance(statuses, dict):
            for key, value in statuses.items():
                if isinstance(value, str):
                    items.append((f"benchmark.statuses.{key}", key, value))
    structured = catalog.get("structured", {})
    if isinstance(structured, dict):
        for key, value in structured.items():
            if isinstance(value, str):
                items.append((f"structured.{key}", value, value))
    for section_name in ("freeformReplacements", "legacyExact", "legacyReplacements"):
        section = catalog.get(section_name)
        if isinstance(section, list):
            for index, item in enumerate(section):
                if isinstance(item, dict):
                    source = item.get("source")
                    target = item.get("target")
                    if isinstance(source, str) and isinstance(target, str):
                        items.append((f"{section_name}[{index}]", source, target))
    return items


def validate_status_catalog(
    code: str,
    english: dict[str, Any],
    strict: bool,
) -> tuple[int, int, list[str], list[str]]:
    path = STATUS_CATALOG_DIR / f"{code}.json"
    if not path.exists():
        return 0, 0, [f"missing status catalog {path.relative_to(ROOT)}"], []
    catalog = load_json(path)
    if not isinstance(catalog, dict):
        return 0, 0, [f"{path.relative_to(ROOT)} must be an object"], []

    errors = []
    warnings = []
    for section in ("dynamic", "benchmark", "structured", "freeformReplacements", "legacyExact", "legacyReplacements"):
        if section not in catalog:
            errors.append(f"{path.relative_to(ROOT)} missing section {section}")

    dynamic = catalog.get("dynamic", {})
    english_dynamic = english.get("dynamic", {})
    if isinstance(dynamic, dict) and isinstance(english_dynamic, dict):
        for key, source in english_dynamic.items():
            target = dynamic.get(key)
            if not isinstance(target, str):
                errors.append(f"{path.relative_to(ROOT)} dynamic.{key} must be a string")
            elif placeholders(source) != placeholders(target):
                errors.append(f"{path.relative_to(ROOT)} dynamic.{key} placeholder mismatch")

    benchmark = catalog.get("benchmark", {})
    english_benchmark = english.get("benchmark", {})
    if isinstance(benchmark, dict) and isinstance(english_benchmark, dict):
        for key in ("best", "primary", "secondary", "tcp", "millisUnit"):
            if not isinstance(benchmark.get(key), str):
                errors.append(f"{path.relative_to(ROOT)} benchmark.{key} must be a string")
        statuses = benchmark.get("statuses")
        english_statuses = english_benchmark.get("statuses")
        if not isinstance(statuses, dict) or not isinstance(english_statuses, dict):
            errors.append(f"{path.relative_to(ROOT)} benchmark.statuses must be an object")
        else:
            missing = set(english_statuses) - set(statuses)
            extra = set(statuses) - set(english_statuses)
            for key in sorted(missing):
                errors.append(f"{path.relative_to(ROOT)} missing benchmark status {key}")
            for key in sorted(extra):
                errors.append(f"{path.relative_to(ROOT)} contains unknown benchmark status {key}")

    structured = catalog.get("structured")
    english_structured = english.get("structured")
    if not isinstance(structured, dict):
        errors.append(f"{path.relative_to(ROOT)} structured must be an object")
    elif not isinstance(english_structured, dict):
        errors.append("English status catalog structured section must be an object")
    else:
        missing = set(english_structured) - set(structured)
        extra = set(structured) - set(english_structured)
        for key in sorted(missing):
            errors.append(f"{path.relative_to(ROOT)} missing structured status {key}")
        for key in sorted(extra):
            errors.append(f"{path.relative_to(ROOT)} contains unknown structured status {key}")
        for key in sorted(set(english_structured) & set(structured)):
            source = english_structured[key]
            target = structured[key]
            if not isinstance(source, str):
                errors.append(f"English status catalog structured.{key} must be a string")
            elif not isinstance(target, str):
                errors.append(f"{path.relative_to(ROOT)} structured.{key} must be a string")
            elif placeholders(source) != placeholders(target):
                errors.append(
                    f"{path.relative_to(ROOT)} structured.{key} placeholder mismatch: "
                    f"{sorted(placeholders(source))} != {sorted(placeholders(target))}",
                )

    for section_name in ("freeformReplacements", "legacyExact", "legacyReplacements"):
        try:
            pairs = replacement_pairs(catalog.get(section_name), path, section_name)
        except ValueError as error:
            errors.append(str(error))
            continue
        for index, pair in enumerate(pairs):
            if placeholders(pair["source"]) != placeholders(pair["target"]):
                errors.append(f"{path.relative_to(ROOT)} {section_name}[{index}] placeholder mismatch")

    english_items = {name: target for name, _, target in status_items(english)}
    translated = 0
    total = 0
    for item_name, source, target in status_items(catalog):
        total += 1
        english_target = english_items.get(item_name, source)
        if code != "en" and target == english_target and not unchanged_status_value_is_allowed(item_name, target):
            warnings.append(f"{path.relative_to(ROOT)} {item_name} is unchanged from English")
        else:
            translated += 1

    if strict:
        errors.extend(warnings)
        warnings = []
    return translated, total, errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate VPN Control localization catalogs.")
    parser.add_argument("--language", help="Validate only one language code.")
    parser.add_argument("--strict", action="store_true", help="Treat unchanged translations as errors.")
    args = parser.parse_args()

    codes = language_codes()
    if args.language:
        if args.language not in codes:
            raise SystemExit(f"Unknown language code {args.language}")
        codes = [args.language]

    english_ui = load_json(UI_CATALOG_DIR / "en.json")
    english_status = load_json(STATUS_CATALOG_DIR / "en.json")
    if not isinstance(english_ui, dict) or not isinstance(english_status, dict):
        raise SystemExit("English localization catalogs are invalid")

    all_errors = []
    all_warnings = []
    for code in codes:
        ui_translated, ui_total, ui_errors, ui_warnings = validate_ui_catalog(code, english_ui, args.strict)
        status_translated, status_total, status_errors, status_warnings = validate_status_catalog(
            code,
            english_status,
            args.strict,
        )
        all_errors.extend(ui_errors)
        all_errors.extend(status_errors)
        all_warnings.extend(ui_warnings)
        all_warnings.extend(status_warnings)
        total = ui_total + status_total
        translated = ui_translated + status_translated
        percent = 100.0 if total == 0 else translated * 100.0 / total
        print(f"{code}: {translated}/{total} translated-ish ({percent:.1f}%)")

    for warning in all_warnings:
        print(f"warning: {warning}")
    for error in all_errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if all_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
