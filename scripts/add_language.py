#!/usr/bin/env python3
import argparse
import json
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LANGUAGE_MANIFEST = ROOT / "shared/model/src/commonMain/resources/languages.json"
UI_CATALOG_DIR = ROOT / "shared/ui/src/commonMain/resources/i18n"
STATUS_CATALOG_DIR = ROOT / "shared/ui/src/commonMain/resources/i18n-status"


def enum_name_from(name: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if not value or value[0].isdigit():
        raise SystemExit("Could not derive a valid enum name. Pass --enum-name explicitly.")
    return value


def copy_catalog(source: Path, target: Path, force: bool) -> None:
    if target.exists() and not force:
        print(f"[add-language] keeping existing {target.relative_to(ROOT)}")
        return
    shutil.copyfile(source, target)
    print(f"[add-language] wrote {target.relative_to(ROOT)}")


def update_language_manifest(code: str, enum_name: str, native_name: str) -> None:
    languages = json.loads(LANGUAGE_MANIFEST.read_text(encoding="utf-8"))
    if any(language["code"] == code for language in languages):
        print(f"[add-language] languages.json already has code {code}")
        return
    if any(language["enumName"] == enum_name for language in languages):
        raise SystemExit(f"languages.json already has enumName {enum_name}")

    languages.append(
        {
            "enumName": enum_name,
            "code": code,
            "nativeName": native_name,
        },
    )
    LANGUAGE_MANIFEST.write_text(
        json.dumps(languages, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[add-language] added {enum_name} to {LANGUAGE_MANIFEST.relative_to(ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scaffold VPN Control localization catalogs.")
    parser.add_argument("--code", required=True, help="Language code, for example: it")
    parser.add_argument("--name", required=True, help="English language name, for example: Italian")
    parser.add_argument("--native", required=True, help="Native language name, for example: Italiano")
    parser.add_argument("--enum-name", help="AppLanguage enum name. Defaults to --name uppercased.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing JSON catalogs.")
    args = parser.parse_args()

    code = args.code.strip().lower()
    if not re.fullmatch(r"[a-z]{2,3}", code):
        raise SystemExit("--code must be a 2-3 letter lowercase language code")

    enum_name = args.enum_name.strip().upper() if args.enum_name else enum_name_from(args.name)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", enum_name):
        raise SystemExit("--enum-name must be a valid uppercase Kotlin enum identifier")

    UI_CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    STATUS_CATALOG_DIR.mkdir(parents=True, exist_ok=True)
    copy_catalog(UI_CATALOG_DIR / "en.json", UI_CATALOG_DIR / f"{code}.json", args.force)
    copy_catalog(STATUS_CATALOG_DIR / "en.json", STATUS_CATALOG_DIR / f"{code}.json", args.force)
    update_language_manifest(code, enum_name, args.native)

    print("[add-language] next steps:")
    print(f"[add-language] translate shared/ui/src/commonMain/resources/i18n/{code}.json")
    print(f"[add-language] translate shared/ui/src/commonMain/resources/i18n-status/{code}.json")
    print("[add-language] run ./gradlew :shared:ui:desktopTest :app:compileDebugKotlin")


if __name__ == "__main__":
    main()
