# Fast Checks command reference

This focused note preserves test-selection instructions and source-bound regression
records from `agent_docs/test-matrix.md` at `3944739d3f33` (2026-10-14).
Passing counts, timings, checkpoint words such as “current”, and native observations
are historical claims for that source and scope, not fresh acceptance or permission
to replay operations. Commands remain mapped check references; apply current
[contracts](../contracts.md), [validation tiers](../test-matrix.md#validation-tiers)
and the [active ledger](../work-in-progress.md) before use. Preserve every stated
skip, uncertainty, causal RED/GREEN requirement and separate native gate below.

## CI Shortcut

The GitHub Actions workflow `.github/workflows/fast-checks.yml` runs the usual fast guardrail set for code changes:

```bash
./scripts/check_release_hygiene.sh
./scripts/check_docs_hygiene.sh
python3 agent_tools/affected_agent_tests.py --run
python3 scripts/check_ui_theme.py
python3 scripts/test_visual_regression.py
python3 scripts/test_visual_platform.py
python3 scripts/test_visual_review.py
python3 scripts/check_contract_docs.py
./scripts/check_localization.py
./scripts/status_catalog_tool.py check
./gradlew :shared:model:desktopTest :shared:core:desktopTest :shared:ui:desktopTest :desktopApp:test :app:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin :app:verifyDebugAndroidTestSignatures
python3 scripts/test_android_instrumentation_signatures.py
python3 scripts/test_windows_qga_powershell_size.py
```

