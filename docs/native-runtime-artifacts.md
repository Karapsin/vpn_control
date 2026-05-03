# Native Runtime Artifacts

This repo intentionally tracks some Android runtime inputs and test fixtures, but desktop release/runtime binaries are prepared by scripts and must not be committed.

## Tracked Android Runtime Inputs

| Path | Purpose | Policy |
| --- | --- | --- |
| `app/libs/libbox.aar` | Android libbox runtime dependency used by the app build. | Tracked. When refreshed, record source version and checksum in the update PR/commit notes. |
| `app/src/main/jniLibs/arm64-v8a/libsing-box.so` | Android release ARM64 native sing-box runtime. | Tracked. Refresh only as part of an explicit runtime update. |
| `app/src/debug/jniLibs/x86_64/libsing-box.so` | Android emulator/debug x86_64 native sing-box runtime. | Tracked. Keep compatible with debug instrumentation/smoke testing. |

## Tracked Desktop Test Fixtures

| Path | Purpose | Policy |
| --- | --- | --- |
| `desktopApp/src/test/resources/bin/linux-amd64/sing-box` | Linux desktop runtime fixture for tests. | Tracked test fixture only. |
| `desktopApp/src/test/resources/bin/windows-amd64/sing-box.exe` | Windows desktop runtime fixture for tests. | Tracked test fixture only. |
| `desktopApp/src/test/resources/bin/darwin-amd64/sing-box` | macOS Intel runtime fixture for tests. | Tracked test fixture only. |
| `desktopApp/src/test/resources/bin/darwin-arm64/sing-box` | macOS Apple Silicon runtime fixture for tests. | Tracked test fixture only. |

## Generated Or Downloaded Artifacts

Do not commit these paths:

- `desktopApp/src/main/resources/bin/`
- `desktopApp/build/`
- `app/build/`
- `shared/**/build/`
- `dist/`
- `.runtime/`
- downloaded release packages

Packaging entry points run `scripts/check_release_hygiene.sh` before building. The check fails if generated release/runtime paths are already tracked by Git, which prevents Windows checkout failures from long generated class/dex paths.

Desktop runtime binaries are bundled into local/release packages by scripts:

```text
scripts/prepare_sing_box_desktop_runtime.sh
scripts/prepare_sing_box_desktop_runtime.ps1
scripts/prepare_sing_box_macos_runtime.sh
scripts/package_linux_desktop.sh
scripts/package_windows_desktop.ps1
scripts/package_windows_desktop_vm.sh
scripts/package_macos_desktop.sh
```

## Runtime Refresh Checklist

1. Identify the upstream runtime version and architecture set.
2. Download from the upstream release source used by existing scripts.
3. Verify checksums before replacing tracked Android or test fixture binaries.
4. Update package scripts if the version or archive layout changed.
5. Run platform config/runtime tests from `docs/test-matrix.md`.
6. Do not mix runtime binary refreshes with unrelated UI, localization, or docs patches.
