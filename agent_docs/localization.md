# Localization

VPN Control keeps typed UI labels and most status/log translations in JSON catalogs, then generates Kotlin lookup tables during the Gradle build.

Authoritative localization invariants are `L10N-001` through `L10N-005` in `contracts.md`. This document describes the catalog workflow and owner files.

## Add A Language

To add a new language:

1. Run `./scripts/add_language.py --code <language-code> --name <English name> --native <Native name>`.
2. Translate every value in `shared/ui/src/commonMain/resources/i18n/<language-code>.json`. Do not rename keys.
3. Translate every value in the `structured`, `dynamic`, and `benchmark` sections of `shared/ui/src/commonMain/resources/i18n-status/<language-code>.json`.
4. Translate every `target` value in the replacement lists of `shared/ui/src/commonMain/resources/i18n-status/<language-code>.json`. Do not rename `source` values.
5. Run `./scripts/check_localization.py --language <language-code>`.
6. Run `./gradlew :shared:ui:desktopTest :app:compileDebugKotlin`.

The script updates `shared/model/src/commonMain/resources/languages.json` and copies the English UI/status catalogs as a translation skeleton. `AppLanguage` is generated from that manifest, so adding a language should not require editing Kotlin enum code.

The build generates Kotlin sources from:

- `shared/model/src/commonMain/resources/languages.json`
- `shared/ui/src/commonMain/resources/i18n/*.json`
- `shared/ui/src/commonMain/resources/i18n-status/*.json`

## Catalog Editing Rules

Apply `L10N-001` through `L10N-005`. `AppStrings.kt` is the UI lookup entry point; `StatusMessageRenderer.kt` performs structured lookup, placeholder substitution, dynamic parsing, and benchmark rendering; model domain facades own stable status creation. Add or update `AppStringsCoverageTest` whenever a raw legacy pattern remains or a new catalog path is introduced.

## Status Catalog Rules

Status catalogs support three main translation paths:

- `structured`: templates for typed status entries. These are the preferred path for new app/runtime statuses.
- `dynamic`: placeholder templates for known status/log patterns.
- `legacyExact`: complete legacy/freeform messages that should be translated exactly.
- `legacyReplacements`: stable prefixes or fragments used to translate older messages.

Choose the catalog section according to `L10N-003` and `L10N-005`: new stable events use `structured`; stable parameterized legacy parsing uses `dynamic`; persisted complete messages use `legacyExact`; replacement lists are the compatibility fallback.

Structured templates are keyed by `StatusMessageKey` names and optional variants, for example `STARTING_CONNECTION.VPN`, `PROFILE_SOURCE_SET.SUBSCRIPTION`, or `UI_SETTING_VISIBILITY_CHANGED.SESSION_STATS.TRUE`. Every language must contain the same structured keys as English.

Structured templates may use these placeholders:

- `{0}`, `{1}`, etc. insert encoded status arguments.
- `{refreshInterval}` formats the selected refresh interval using the language's dynamic interval templates.
- `{checkCount}` formats a localized validation-check count.
- `{valueOrNotReady}` inserts the first argument or the localized not-ready fallback.
- `{ui:KEY}` inserts a translated `UiText` value.
- `{modeLabel:0}` inserts the localized VPN/proxy-only mode label for argument 0.
- `{connectionLabel:0}` inserts the localized VPN/proxy connection noun for argument 0.

Translations may reorder placeholders but validation enforces the placeholder parity contract.

When a new typed status needs real translation work across many languages, split the work by language. Each agent or reviewer should own exactly one `shared/ui/src/commonMain/resources/i18n-status/<language-code>.json` file and preserve placeholders byte-for-byte.

## Add A Typed Status

Typed runtime/status messages are split across the shared model status files:

- `StatusMessageTypes.kt` owns `StatusMessageKey` and `StructuredStatusMessage`.
- `StatusMessageCodec.kt` owns encode/decode escaping.
- `StatusMessageKeySelectors.kt` owns domain-specific key selection.
- Domain facades such as `ConnectionStatusMessages`, `SubscriptionStatusMessages`, `BenchmarkStatusMessages`, `LocationStatusMessages`, `RoutingStatusMessages`, `DiagnosticsStatusMessages`, `RuntimeStatusMessages`, and `SettingsStatusMessages` own grouped helpers for new production code.
- `StatusMessages.kt` only exposes encode/decode for codec and renderer boundaries. Do not add domain helper wrappers there.

To add one:

1. Add a `StatusMessageKey` entry and a helper on the relevant domain facade.
2. Put non-trivial variant selection into `StatusMessageKeySelectors.kt` instead of inline UI/platform code.
3. Seed the structured catalog entry:

```bash
./scripts/status_catalog_tool.py add-structured STATUS_KEY "English template with {0} placeholders"
```

Use a variant suffix when one key has mode-specific wording:

```bash
./scripts/status_catalog_tool.py add-structured STARTING_CONNECTION.VPN "Starting VPN..."
```

The tool copies the English template into every status catalog as a translation skeleton. Translate those copied skeletons per language before relying on `--strict`.

Run the status catalog checker and the model/UI status tests after any typed-status change:

```bash
./scripts/status_catalog_tool.py check
./gradlew :shared:model:desktopTest :shared:ui:desktopTest
```

## Validation

`AppStringsCoverageTest` fails if a UI catalog misses a `UiText` key or a status catalog is missing required benchmark/status data. Kotlin compilation fails if a UI catalog contains an unknown key.

`check_localization.py` validates manifest/catalog alignment, placeholder preservation, status catalog shape, and prints a rough completion percentage. Use `--strict` when unchanged English strings should fail the check instead of being reported as warnings.

`status_catalog_tool.py check` validates `StatusMessageKey` coverage, unknown structured keys, all-language structured key parity, and structured placeholder parity.

For all-language validation, run without `--language`. This validates every UI/status catalog and catches missing `structured` keys across the full language set.

Validate one changed language:

```bash
./scripts/check_localization.py --language <language-code>
```

Validate every language catalog:

```bash
./scripts/check_localization.py
```

Validate typed status catalog parity:

```bash
./scripts/status_catalog_tool.py check
```

Run the shared UI test suite after localization changes:

```bash
./gradlew :shared:ui:desktopTest
```

For Android-visible localization changes, also run:

```bash
./gradlew :app:compileDebugKotlin
```

## When To Update Tests

Update `shared/ui/src/commonTest/kotlin/com/kardinal/vpncontrol/shared/ui/AppStringsCoverageTest.kt` when:

- A screenshot or manual run shows untranslated UI/status text.
- A new dynamic status or connection-log pattern is introduced.
- A runtime message starts from Kotlin as English text and must be routed through status localization.
- Button label length or UI layout limits become language-specific regressions.
- A new catalog section is added and needs coverage across every language.
