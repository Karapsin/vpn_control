#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LANGUAGE_MANIFEST = ROOT / "shared/model/src/commonMain/resources/languages.json"
MODEL_DIR = ROOT / "shared/model/src/commonMain/kotlin/com/kardinal/vpncontrol/model"
STATUS_CATALOG_DIR = ROOT / "shared/ui/src/commonMain/resources/i18n-status"
PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")
STATUS_ENUM_RE = re.compile(r"enum\s+class\s+StatusMessageKey\s*\{(?P<body>.*?)\n\s*\}", re.DOTALL)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"{path.relative_to(ROOT)}: invalid JSON: {error}") from error


def write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def placeholders(value: str) -> set[str]:
    return set(PLACEHOLDER_RE.findall(value))


def language_codes() -> list[str]:
    languages = load_json(LANGUAGE_MANIFEST)
    if not isinstance(languages, list):
        raise SystemExit("languages.json must be an array")
    codes = []
    for index, language in enumerate(languages):
        if not isinstance(language, dict):
            raise SystemExit(f"languages.json entry {index} must be an object")
        code = language.get("code")
        if not isinstance(code, str):
            raise SystemExit(f"languages.json entry {index} has invalid code")
        if code:
            codes.append(code)
    return codes


def parse_status_message_keys(source: str) -> list[str]:
    match = STATUS_ENUM_RE.search(source)
    if not match:
        raise ValueError("StatusMessageKey enum was not found")
    keys = []
    for raw_line in match.group("body").splitlines():
        line = raw_line.split("//", 1)[0].strip().rstrip(",")
        if not line:
            continue
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", line):
            continue
        keys.append(line)
    if not keys:
        raise ValueError("StatusMessageKey enum is empty")
    return keys


def kotlin_status_message_keys(model_dir: Path = MODEL_DIR) -> list[str]:
    sources = "\n".join(path.read_text(encoding="utf-8") for path in sorted(model_dir.glob("*.kt")))
    try:
        return parse_status_message_keys(sources)
    except ValueError as error:
        raise SystemExit(str(error)) from error


def structured_key_base(key: str) -> str:
    return key.split(".", 1)[0]


def status_catalog_path(code: str) -> Path:
    return STATUS_CATALOG_DIR / f"{code}.json"


def structured_catalog(path: Path) -> dict[str, str]:
    catalog = load_json(path)
    if not isinstance(catalog, dict):
        raise SystemExit(f"{path.relative_to(ROOT)} must be an object")
    structured = catalog.get("structured")
    if not isinstance(structured, dict):
        raise SystemExit(f"{path.relative_to(ROOT)} structured must be an object")
    bad_values = [key for key, value in structured.items() if not isinstance(value, str)]
    if bad_values:
        raise SystemExit(f"{path.relative_to(ROOT)} has non-string structured values: {', '.join(sorted(bad_values))}")
    return structured


def check_catalogs() -> int:
    enum_keys = set(kotlin_status_message_keys())
    english_path = status_catalog_path("en")
    english_structured = structured_catalog(english_path)
    english_keys = set(english_structured)
    errors = []

    for key in sorted(enum_keys):
        if key not in english_keys and not any(candidate.startswith(f"{key}.") for candidate in english_keys):
            errors.append(f"{english_path.relative_to(ROOT)} missing structured entry for StatusMessageKey.{key}")

    for key in sorted(english_keys):
        base = structured_key_base(key)
        if base not in enum_keys:
            errors.append(f"{english_path.relative_to(ROOT)} structured.{key} has no StatusMessageKey.{base}")

    for code in language_codes():
        path = status_catalog_path(code)
        if not path.exists():
            errors.append(f"missing status catalog {path.relative_to(ROOT)}")
            continue
        structured = structured_catalog(path)
        keys = set(structured)
        for key in sorted(english_keys - keys):
            errors.append(f"{path.relative_to(ROOT)} missing structured.{key}")
        for key in sorted(keys - english_keys):
            errors.append(f"{path.relative_to(ROOT)} contains unknown structured.{key}")
        for key in sorted(keys & english_keys):
            if placeholders(structured[key]) != placeholders(english_structured[key]):
                errors.append(
                    f"{path.relative_to(ROOT)} structured.{key} placeholder mismatch: "
                    f"{sorted(placeholders(structured[key]))} != {sorted(placeholders(english_structured[key]))}",
                )

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"status catalogs ok: {len(english_keys)} structured templates, {len(enum_keys)} status keys")
    return 0


def add_structured_key(raw_key: str, template: str, replace: bool) -> int:
    enum_keys = set(kotlin_status_message_keys())
    key = raw_key.strip().upper()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*(\.[A-Z0-9_]+)*", key):
        raise SystemExit("structured key must look like KEY or KEY.VARIANT")
    base = structured_key_base(key)
    if base not in enum_keys:
        raise SystemExit(f"StatusMessageKey.{base} does not exist")
    if not template:
        raise SystemExit("template must not be empty")

    catalogs = []
    for code in language_codes():
        path = status_catalog_path(code)
        catalog = load_json(path)
        if not isinstance(catalog, dict):
            raise SystemExit(f"{path.relative_to(ROOT)} must be an object")
        structured = catalog.setdefault("structured", {})
        if not isinstance(structured, dict):
            raise SystemExit(f"{path.relative_to(ROOT)} structured must be an object")
        if key in structured and not replace:
            raise SystemExit(f"{path.relative_to(ROOT)} already has structured.{key}; pass --replace to overwrite")
        catalogs.append((path, catalog, structured))

    changed = []
    for path, catalog, structured in catalogs:
        if key not in structured or structured[key] != template:
            structured[key] = template
            write_json(path, catalog)
            changed.append(path.relative_to(ROOT).as_posix())

    print(f"structured.{key} written to {len(changed)} catalog(s)")
    for path in changed:
        print(path)
    return check_catalogs()


def run_self_test() -> int:
    sample = """
        enum class StatusMessageKey {
            IDLE,
            STARTING_CONNECTION,
            CONNECTION_STARTED,
        }
    """
    parsed = parse_status_message_keys(sample)
    if parsed != ["IDLE", "STARTING_CONNECTION", "CONNECTION_STARTED"]:
        print(f"error: enum parser returned {parsed}", file=sys.stderr)
        return 1
    if structured_key_base("STARTING_CONNECTION.VPN") != "STARTING_CONNECTION":
        print("error: structured key base parsing failed", file=sys.stderr)
        return 1
    if placeholders("{modeLabel:0} {0}") != {"{modeLabel:0}", "{0}"}:
        print("error: placeholder parsing failed", file=sys.stderr)
        return 1
    with TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "catalog.json"
        write_json(path, {"structured": {"IDLE": "Idle"}})
        if json.loads(path.read_text(encoding="utf-8"))["structured"]["IDLE"] != "Idle":
            print("error: JSON roundtrip failed", file=sys.stderr)
            return 1
    print("status catalog tool self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Maintain typed VPN Control status localization catalogs.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("check", help="Validate StatusMessageKey coverage and structured status catalog parity.")

    add_parser = subparsers.add_parser(
        "add-structured",
        help="Seed one structured status template into every status catalog.",
    )
    add_parser.add_argument("key", help="Structured key, for example STARTING_CONNECTION.VPN.")
    add_parser.add_argument("template", help="English template to add. Translators should replace copied skeletons.")
    add_parser.add_argument("--replace", action="store_true", help="Overwrite an existing structured template.")

    subparsers.add_parser("self-test", help="Run script-level parser/JSON regression checks.")

    args = parser.parse_args()
    if args.command == "check":
        return check_catalogs()
    if args.command == "add-structured":
        return add_structured_key(args.key, args.template, args.replace)
    if args.command == "self-test":
        return run_self_test()
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
