#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS package regression tests must run on macOS" >&2
  exit 1
fi

if (($# != 1)); then
  echo "Usage: scripts/test_macos_desktop_package.sh <dmg-or-directory>" >&2
  exit 2
fi

target="$1"
if [[ -d "$target" ]]; then
  dmg_files=()
  while IFS= read -r dmg_file; do
    dmg_files+=("$dmg_file")
  done < <(find "$target" -type f -name '*.dmg' | sort)
else
  dmg_files=("$target")
fi

if (( ${#dmg_files[@]} == 0 )); then
  echo "No DMG files found under $target" >&2
  exit 1
fi

for dmg in "${dmg_files[@]}"; do
  if [[ ! -f "$dmg" ]]; then
    echo "DMG does not exist: $dmg" >&2
    exit 1
  fi

  echo "[vpn-control] smoke testing macOS DMG: $dmg"
  mount_dir="$(mktemp -d)"
  attached=false
  cleanup() {
    if [[ "$attached" == true ]]; then
      hdiutil detach "$mount_dir" -quiet || true
    fi
    rm -rf "$mount_dir"
  }
  trap cleanup EXIT

  hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$mount_dir" -quiet
  attached=true

  app_path="$(find "$mount_dir" -maxdepth 2 -type d -name '*.app' | head -n 1)"
  if [[ -z "$app_path" ]]; then
    echo "DMG does not contain a .app bundle" >&2
    exit 1
  fi

  info_plist="$app_path/Contents/Info.plist"
  if [[ ! -f "$info_plist" ]]; then
    echo "App bundle is missing Info.plist: $app_path" >&2
    exit 1
  fi

  bundle_name="$(plutil -extract CFBundleName raw -o - "$info_plist")"
  version="$(plutil -extract CFBundleShortVersionString raw -o - "$info_plist")"
  executable_name="$(plutil -extract CFBundleExecutable raw -o - "$info_plist")"
  if [[ -z "$bundle_name" || -z "$version" || -z "$executable_name" ]]; then
    echo "App metadata is incomplete in $info_plist" >&2
    exit 1
  fi
  if [[ "$version" != 1.* ]]; then
    echo "macOS package version must start with 1.x, got $version" >&2
    exit 1
  fi
  if [[ ! -x "$app_path/Contents/MacOS/$executable_name" ]]; then
    echo "App executable is missing or not executable: $executable_name" >&2
    exit 1
  fi

  jar_with_sing_box=""
  while IFS= read -r jar_file; do
    if jar tf "$jar_file" | grep -E '^bin/darwin-(amd64|arm64)/sing-box$' >/dev/null; then
      jar_with_sing_box="$jar_file"
      break
    fi
  done < <(find "$app_path/Contents/app" -type f -name '*.jar' | sort)
  if [[ -z "$jar_with_sing_box" ]]; then
    echo "Bundled darwin sing-box resources were not found in app jars" >&2
    exit 1
  fi

  if [[ -n "${VPN_CONTROL_MACOS_SIGNING_IDENTITY:-}" ]]; then
    codesign --verify --deep --strict --verbose=2 "$app_path"
  else
    echo "[vpn-control] signing identity is not configured; skipping codesign verification"
  fi

  echo "[vpn-control] macOS DMG smoke passed: $bundle_name $version"
  cleanup
  trap - EXIT
done
