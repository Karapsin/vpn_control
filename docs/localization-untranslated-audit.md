# Localization Untranslated Audit

Date: 2026-04-30

Scope:

- `shared/ui/src/commonMain/resources/i18n/*.json`
- `shared/ui/src/commonMain/resources/i18n-status/*.json`

Method:

- Started one read-only `codex exec` agent per language code in `languages.json`.
- Each agent audited the UI catalog and status catalog for untranslated or wrong-language user-facing values.
- After collecting the agent outputs, a deterministic exact-copy matrix compared every catalog against every other language to catch catalog-wide carryovers the agents missed.
- A target-only string scan then checked status `target` values and UI values for obvious mixed-language leftovers such as English suffixes, placeholder text, and `Whitelists` in non-English strings.
- Status `source` fields were intentionally ignored; only `dynamic`, `benchmark`, and `target` values were audited.
- Technical terms such as `VPN`, `QR`, `DNS`, `URL`, `JSON`, `sing-box`, `TUN`, `SOCKS`, `VLESS`, `VMess`, `Trojan`, `https://`, `/dev/net/tun`, `CAP_NET_ADMIN`, `netsh.exe`, and `PowerShell` were not treated as untranslated by themselves.
- Easter egg catalogs `sov` and `orv` were reviewed as stylized Cyrillic catalogs, so Soviet/archaic terminology was not treated as an error by itself.

Raw local agent outputs:

- `/tmp/localization_audits/results.tsv`
- `/tmp/localization_audits/outputs/<language>.json`
- `/tmp/localization_audits/logs/<language>.log`

## Catalog-Wide Problems

These catalogs are not just missing a few strings; agents found that most user-facing text is copied from another language.

| Code | Target | Dominant carryover | Evidence |
| --- | --- | --- | --- |
| `az` | Azerbaijani | Turkish | `229/239` UI values match `tr.json`; `362/362` status values match `tr.json`. |
| `uz` | Uzbek | Turkish | `228/239` UI values match `tr.json`; `362/362` status values match `tr.json`. |
| `tk` | Turkmen | Turkish | `209/239` UI values match `tr.json`; `362/362` status values match `tr.json`. |
| `ro` | Romanian | French | `207/239` UI values match `fr.json`; `300/300` status values match `fr.json`. |
| `uk` | Ukrainian | Russian | `229/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `be` | Belarusian | Russian | `227/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `kk` | Kazakh | Russian | `229/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `ky` | Kyrgyz | Russian | `229/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `tg` | Tajik | Russian | `227/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `ka` | Georgian | Russian | `227/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `hy` | Armenian | Russian | `227/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `et` | Estonian | Russian | `227/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `lv` | Latvian | Russian | `227/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `lt` | Lithuanian | Russian | `227/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `sr` | Serbian | Russian | `208/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `bg` | Bulgarian | Russian | `211/239` UI values match `ru.json`; `215/215` status values match `ru.json`. |
| `pl` | Polish | German | Validation pass found `208/239` UI values and `300/300` status values matching `de.json`. |
| `fi` | Finnish | German | Validation pass found `205/239` UI values and `300/300` status values matching `de.json`. |
| `hu` | Hungarian | German | Validation pass found `207/239` UI values and `300/300` status values matching `de.json`. |
| `vi` | Vietnamese | Indonesian | Validation pass found `204/239` UI values and `362/362` status values matching `id.json`. |

## Smaller Carryovers

These catalogs are broadly localized, but agents found isolated untranslated or mixed-language values.

| Code | Area | Examples to fix or review |
| --- | --- | --- |
| `ar` | Status | `Whitelists`; broken mixed forms like `subscriptions التحديثed`. |
| `bn` | Status | `Whitelists`; mixed Bengali/English forms like `সাবস্ক্রিপশন রিফ্রেশed`. |
| `fa` | UI/status | `helper`, `remote-profile`, `Whitelists` in Persian-facing text. |
| `fi` | UI | `SERVER`, `NAME`, `SYSTEM_APP` remain English. |
| `fr` | UI | `TAB_STATS` and `STATS_TITLE` remain `Stats`. |
| `hu` | UI | `NAME` remains `Name`. |
| `id` | Status | Mixed strings such as `Invalid langganan URL`, `Whitelists`, `Diagnostik export bukaed`. |
| `it` | UI | Placeholder-like English/Italian mixes such as `validation android summary {0}` and `rename abbonamento`. |
| `ko` | Status | `Whitelists` remains English in a Korean status string. |
| `pl` | UI | `STATUS`, `SERVER`, `IMPORT`, `NAME`, `SYSTEM_APP` remain English; review loanword intent. |
| `sov` | Status | `Whitelists` remains English in the Soviet-styled catalog. |
| `th` | Status | `Whitelists` remains English in a Thai status string. |

Validation also found that the shared status replacement for `Desktop shell: Netherlands from Whitelists` still contained `Whitelists` in many non-English catalogs, and had the wrong generic target in `el`, `hi`, and `ja`. Those replacements were normalized while preserving technical terms.

## No Agent Findings

The per-language agents did not report user-facing untranslated or wrong-language lines for:

`de`, `el`, `en`, `es`, `hi`, `ja`, `orv`, `pt`, `ru`, `tr`, `zh`.

The validation pass supersedes this initial agent-only list where it found additional issues.
