# Localization

VPN Control keeps typed UI labels and most status/log translations in JSON catalogs, then generates Kotlin lookup tables during the Gradle build.

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

- Keep user-facing translations in JSON catalogs, not in Kotlin source.
- Do not add `when (AppLanguage...)` branches with translated UI or status text in Kotlin.
- `AppStrings.kt` should only choose keys, parse known message shapes, and substitute placeholders. It must not own rendered English sentence templates for typed status messages.
- Prefer typed `StatusMessages` helpers for stable runtime/status events. If a raw English status string must remain for legacy compatibility, add it to status catalogs and cover it in `AppStringsCoverageTest`.
- Do not concatenate encoded `StatusMessages` into longer raw sentences. If a message needs several clauses, add one complete structured status key or keep the whole legacy sentence on the legacy translation path until it can be migrated safely.
- Shared settings and location mutation feedback should use `StatusMessages` helpers, not raw English strings from shared core.
- Desktop settings, app-mode, autostart, connection lifecycle, reconnect, shutdown, and restore messages should use `StatusMessages` helpers instead of ad hoc English strings.
- UI labels belong in `shared/ui/src/commonMain/resources/i18n/<language-code>.json`.
- Status, log, and freeform runtime message translations belong in `shared/ui/src/commonMain/resources/i18n-status/<language-code>.json`.
- Preserve placeholders exactly. If English has `{count}`, every translation must keep `{count}`.
- Preserve technical commands, file paths, URLs, capability names, and protocol identifiers. Keep strings such as `/dev/net/tun`, `sudo modprobe tun`, `CAP_NET_ADMIN`, `netsh.exe`, `sing-box`, `VLESS`, `VMess`, `SOCKS`, and `Trojan` recognizable.
- Keep language choices sorted alphabetically by visible display name in the UI, with `System` pinned first.

## Status Catalog Rules

Status catalogs support three main translation paths:

- `structured`: templates for typed `StatusMessages` entries. These are the preferred path for new app/runtime statuses.
- `dynamic`: placeholder templates for known status/log patterns.
- `legacyExact`: complete legacy/freeform messages that should be translated exactly.
- `legacyReplacements`: stable prefixes or fragments used to translate older messages.

Prefer `structured` when code can emit a `StatusMessages` helper. Prefer `dynamic` when Kotlin must parse a stable legacy source pattern with placeholders. Use `legacyExact` for complete messages that already exist in persisted logs. Use `legacyReplacements` only for stable fragments or prefixes that can safely appear inside longer messages.

Do not translate the `source` value in status entries. Translate only `target`.

Structured templates are keyed by `StatusMessageKey` names and optional variants, for example `STARTING_CONNECTION.VPN`, `PROFILE_SOURCE_SET.SUBSCRIPTION`, or `UI_SETTING_VISIBILITY_CHANGED.SESSION_STATS.TRUE`. Every language must contain the same structured keys as English.

Structured templates may use these placeholders:

- `{0}`, `{1}`, etc. insert encoded status arguments.
- `{refreshInterval}` formats the selected refresh interval using the language's dynamic interval templates.
- `{checkCount}` formats a localized validation-check count.
- `{valueOrNotReady}` inserts the first argument or the localized not-ready fallback.
- `{ui:KEY}` inserts a translated `UiText` value.
- `{modeLabel:0}` inserts the localized VPN/proxy-only mode label for argument 0.
- `{connectionLabel:0}` inserts the localized VPN/proxy connection noun for argument 0.

Preserve placeholders exactly. If a translation needs different word order, move the placeholders, but do not rename or delete them.

When a new typed status needs real translation work across many languages, split the work by language. Each agent or reviewer should own exactly one `shared/ui/src/commonMain/resources/i18n-status/<language-code>.json` file and preserve placeholders byte-for-byte.

## Validation

`AppStringsCoverageTest` fails if a UI catalog misses a `UiText` key or a status catalog is missing required benchmark/status data. Kotlin compilation fails if a UI catalog contains an unknown key.

`check_localization.py` validates manifest/catalog alignment, placeholder preservation, status catalog shape, and prints a rough completion percentage. Use `--strict` when unchanged English strings should fail the check instead of being reported as warnings.

For all-language validation, run without `--language`. This validates every UI/status catalog and catches missing `structured` keys across the full language set.

Validate one changed language:

```bash
./scripts/check_localization.py --language <language-code>
```

Validate every language catalog:

```bash
./scripts/check_localization.py
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
