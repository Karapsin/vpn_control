# Localization

VPN Control keeps typed UI labels in JSON catalogs and generates the Kotlin lookup table during the Gradle build.

To add a new language:

1. Add the language to `AppLanguage` in `shared/model/src/commonMain/kotlin/com/kardinal/vpncontrol/model/Models.kt`.
2. Copy `shared/ui/src/commonMain/resources/i18n/en.json` to `shared/ui/src/commonMain/resources/i18n/<language-code>.json`.
3. Translate every value in the new JSON file. Do not rename keys.
4. Add dynamic status and freeform-message translations in `AppStrings.kt` and `AppStringSupplements.kt` for generated log/status text.
5. Run `./gradlew :shared:ui:desktopTest :app:compileDebugKotlin`.

The build generates `GeneratedI18nCatalog.kt` from `shared/ui/src/commonMain/resources/i18n/*.json`.
`AppStringsCoverageTest` fails if a catalog misses a `UiText` key, and Kotlin compilation fails if a catalog contains an unknown key.
