# Localization

VPN Control keeps typed UI labels and most status/log translations in JSON catalogs, then generates Kotlin lookup tables during the Gradle build.

To add a new language:

1. Run `./scripts/add_language.py --code <language-code> --name <English name> --native <Native name>`.
2. Translate every value in `shared/ui/src/commonMain/resources/i18n/<language-code>.json`. Do not rename keys.
3. Translate every `target` value in `shared/ui/src/commonMain/resources/i18n-status/<language-code>.json`. Do not rename `source` values.
4. Run `./gradlew :shared:ui:desktopTest :app:compileDebugKotlin`.

The script updates `AppLanguage` and copies the English UI/status catalogs as a translation skeleton.

The build generates `GeneratedI18nCatalog.kt` from:

- `shared/ui/src/commonMain/resources/i18n/*.json`
- `shared/ui/src/commonMain/resources/i18n-status/*.json`

`AppStringsCoverageTest` fails if a UI catalog misses a `UiText` key or a status catalog is missing required benchmark/status data. Kotlin compilation fails if a UI catalog contains an unknown key.
