#!/usr/bin/env bash
set -euo pipefail

skip_android=false
skip_linux=false
skip_macos=false
skip_windows_vm=false
skip_tests=false

usage() {
  cat <<'EOF'
Usage: scripts/release_checklist.sh [options]

Build release artifacts and run regression checks.

Options:
  --skip-android       skip Android release APK build
  --skip-linux         skip Linux package build
  --skip-macos         skip macOS DMG build
  --skip-windows-vm    skip Windows EXE/MSI build in the local VM
  --skip-tests         skip the standalone Gradle test pass
  -h, --help           show this help

Windows VM packaging uses scripts/package_windows_desktop_vm.sh. If sudo is
required non-interactively, pass VPN_CONTROL_SUDO_PASSWORD in the environment.
EOF
}

while (($#)); do
  case "$1" in
    --skip-android)
      skip_android=true
      shift
      ;;
    --skip-linux)
      skip_linux=true
      shift
      ;;
    --skip-macos)
      skip_macos=true
      shift
      ;;
    --skip-windows-vm)
      skip_windows_vm=true
      shift
      ;;
    --skip-tests)
      skip_tests=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

log() {
  printf '[vpn-control] %s\n' "$*"
}

./scripts/check_release_hygiene.sh

if [[ "$skip_tests" != true ]]; then
  log "running standalone regression tests"
  ./gradlew :shared:core:desktopTest :shared:model:desktopTest :desktopApp:test
else
  log "skipping standalone regression tests"
fi

if [[ "$skip_android" != true ]]; then
  log "building Android release APK"
  ./gradlew :app:assembleRelease
else
  log "skipping Android release APK"
fi

if [[ "$skip_linux" != true ]]; then
  log "building Linux desktop packages"
  ./scripts/package_linux_desktop.sh --skip-tests
else
  log "skipping Linux desktop packages"
fi

if [[ "$skip_macos" != true ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    log "building macOS desktop package"
    ./scripts/package_macos_desktop.sh --skip-tests
  else
    log "skipping macOS desktop package on non-macOS host"
  fi
else
  log "skipping macOS desktop package"
fi

if [[ "$skip_windows_vm" != true ]]; then
  log "building Windows desktop packages in VM"
  ./scripts/package_windows_desktop_vm.sh
else
  log "skipping Windows VM desktop packages"
fi

log "release artifact candidates"
artifacts=()
while IFS= read -r artifact; do
  artifacts+=("$artifact")
done < <(
  find app/build/outputs/apk/release \
      desktopApp/build/compose/binaries/main \
      dist/macos \
      dist/windows-vm \
      -type f \( -name '*.apk' -o -name '*.deb' -o -name '*.rpm' -o -name '*.dmg' -o -name '*.exe' -o -name '*.msi' \) \
      2>/dev/null | sort
)

if (( ${#artifacts[@]} == 0 )); then
  echo "No release artifacts were found" >&2
  exit 1
fi

printf ' - %s\n' "${artifacts[@]}"

log "SHA256"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${artifacts[@]}"
else
  shasum -a 256 "${artifacts[@]}"
fi
