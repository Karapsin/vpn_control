# Localization

VPN Control keeps typed UI labels and most status/log translations in JSON catalogs, then generates Kotlin lookup tables during the Gradle build.

To add a new language:

1. Run `./scripts/add_language.py --code <language-code> --name <English name> --native <Native name>`.
2. Translate every value in `shared/ui/src/commonMain/resources/i18n/<language-code>.json`. Do not rename keys.
3. Translate every `target` value in `shared/ui/src/commonMain/resources/i18n-status/<language-code>.json`. Do not rename `source` values.
4. Run `./scripts/check_localization.py --language <language-code>`.
5. Run `./gradlew :shared:ui:desktopTest :app:compileDebugKotlin`.

The script updates `shared/model/src/commonMain/resources/languages.json` and copies the English UI/status catalogs as a translation skeleton. `AppLanguage` is generated from that manifest, so adding a language should not require editing Kotlin enum code.

The build generates Kotlin sources from:

- `shared/model/src/commonMain/resources/languages.json`
- `shared/ui/src/commonMain/resources/i18n/*.json`
- `shared/ui/src/commonMain/resources/i18n-status/*.json`

`AppStringsCoverageTest` fails if a UI catalog misses a `UiText` key or a status catalog is missing required benchmark/status data. Kotlin compilation fails if a UI catalog contains an unknown key.

`check_localization.py` validates manifest/catalog alignment, placeholder preservation, status catalog shape, and prints a rough completion percentage. Use `--strict` when unchanged English strings should fail the check instead of being reported as warnings.
