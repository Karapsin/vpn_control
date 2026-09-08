# Native Runtime Artifacts

Authoritative native and generated artifact policy is `ARTIFACT-001` through `ARTIFACT-003` in `contracts.md`. This document inventories the exact current paths and runtime refresh procedure.

## Tracked Android Runtime Inputs

| Path | Purpose | Policy |
| --- | --- | --- |
| `app/libs/libbox.aar` | Android libbox runtime dependency used by the app build. | Tracked. When refreshed, record source version and checksum in the update PR/commit notes. |
| `app/src/main/jniLibs/arm64-v8a/libsing-box.so` | Android release ARM64 native sing-box runtime. | Tracked. Refresh only as part of an explicit runtime update. |
| `app/src/debug/jniLibs/x86_64/libsing-box.so` | Android emulator/debug x86_64 native sing-box runtime. | Tracked. Keep compatible with debug instrumentation/smoke testing. |

## Application JNI Helpers

`app/src/main/cpp/` contains application-owned C sources for `vpn_control_strings`.
This helper constructs a Java String from bounded spool reads through standard JNI;
it does not replace or upgrade libbox or sing-box. Native temporary storage still
scales with the document size, and allocation/read failures must remain explicit.

Android builds pin NDK `28.2.13676358` and CMake `3.22.1`. Install them with
`sdkmanager "ndk;28.2.13676358" "cmake;3.22.1"`. Release uses ARM64 and debug also
supports x86_64, matching the existing runtime ABI filters. Generated libraries
belong under ignored `app/build/` outputs; do not commit compiled helpers.

The ordinary `:app:testDebugUnitTest` tier builds the same C implementation for
the host using the pinned SDK CMake/Ninja, the Gradle JDK JNI headers, and a host
C compiler. Host-only allocator failure hooks are excluded from Android builds.
Child JVM memory tests must propagate `java.library.path` from the parent test.
The same application-owned library also provides exclusive file publication for
generated Android routing assets. API29 may deny Java hard-link publication, so
the helper uses native atomic rename with no replacement: `renameat2` through the
system-call interface on Android/Linux, `renamex_np` on macOS hosts, and
`MoveFileExW` without replacement or copy flags on Windows hosts. Unsupported
operations fail explicitly; there is no ordinary rename/copy fallback. Paths use
validated UTF-16 and standard UTF-8 rather than JNI modified UTF-8. Ordinary app
unit tests cover publication and destination preservation alongside string tests.
The consecutive large-routing regression exercises the actual helper with a
48-MiB Java heap; passing it does not replace API29/API35 packaged verification.

## Tracked Desktop Test Fixtures

| Path | Purpose | Policy |
| --- | --- | --- |
| `desktopApp/src/test/resources/bin/linux-amd64/sing-box` | Linux desktop runtime fixture for tests. | Tracked test fixture only. |
| `desktopApp/src/test/resources/bin/windows-amd64/sing-box.exe` | Windows desktop runtime fixture for tests. | Tracked test fixture only. |
| `desktopApp/src/test/resources/bin/darwin-amd64/sing-box` | macOS Intel runtime fixture for tests. | Tracked test fixture only. |
| `desktopApp/src/test/resources/bin/darwin-arm64/sing-box` | macOS Apple Silicon runtime fixture for tests. | Tracked test fixture only. |

## Generated Or Downloaded Artifacts

`ARTIFACT-002` applies to these generated/downloaded paths:

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
scripts/package_arch_desktop_update.sh
```

Windows native helper preparation generates a canonical C# runtime hash constant
from the prepared AMD64 runtime. Product verification checks that generated source
against the current runtime and records `runtimeAuthority` (runtime SHA256, size,
and generated-source SHA256) in `native-helpers.json`. Component-only verification
may omit the binding; application staging and package inspection require it and
stream-verify exactly one `bin/windows-amd64/sing-box.exe` resource in the app JARs.
Missing, ambiguous or changed resources reject the package. PE metadata and helper
hashes are still independently recomputed. This manifest establishes build/package
consistency, not proof of compiled code: the pinned native broker's compiled hash
remains the authority when accepting runtime bytes. Never use manifest metadata
alone to authorize privileged execution.

The generated Arch update bundle contains the Compose app image and prepared Linux `sing-box` runtime. It is written under `dist/arch/`, remains untracked, and reapplies capabilities only while installing the verified release bundle.

## Runtime Refresh Checklist

1. Identify the upstream runtime version and architecture set.
2. Download from the upstream release source used by existing scripts.
3. Verify checksums before replacing tracked Android or test fixture binaries.
4. Update package scripts if the version or archive layout changed.
5. Run platform config/runtime tests from `agent_docs/test-matrix.md`.
6. Do not mix runtime binary refreshes with unrelated UI, localization, or docs patches.
