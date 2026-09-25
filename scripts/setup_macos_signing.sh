#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cert_base64="${VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64:-}"

if [[ -z "$cert_base64" ]]; then
  echo "[vpn-control] macOS signing certificate is not configured; building unsigned DMG"
  return 0 2>/dev/null || exit 0
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS signing setup must run on macOS" >&2
  return 1 2>/dev/null || exit 1
fi

required_vars=(
  VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_PASSWORD
  VPN_CONTROL_MACOS_SIGNING_IDENTITY
  VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD
)

for name in "${required_vars[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required when VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_BASE64 is set" >&2
    return 1 2>/dev/null || exit 1
  fi
done

runtime_dir="${RUNNER_TEMP:+$RUNNER_TEMP/macos-signing}"
runtime_dir="${runtime_dir:-$repo_root/.runtime/macos-signing}"
mkdir -p "$runtime_dir"

cert_path="$runtime_dir/vpn-control-signing.p12"
keychain_path="$runtime_dir/vpn-control-signing.keychain-db"
keychain_marker="$keychain_path.owner"
keychain_marker_contents="vpn-control-managed-keychain-v1"
created_keychain=false

if [[ -e "$keychain_path" || -e "$keychain_marker" ]]; then
  # A repeated fixture stage may reuse only the runner-temporary keychain this
  # script created. Never assume an unmarked path is safe to alter or delete.
  if [[ ! -f "$keychain_path" || -L "$keychain_path" || ! -f "$keychain_marker" || -L "$keychain_marker" ||
        "$(<"$keychain_marker")" != "$keychain_marker_contents" ]]; then
    echo "macOS signing keychain ownership marker is missing or invalid: $keychain_path" >&2
    return 1 2>/dev/null || exit 1
  fi
  echo "[vpn-control] reusing owned macOS signing keychain at $keychain_path"
else
  security create-keychain -p "$VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD" "$keychain_path"
  (umask 077; printf '%s\n' "$keychain_marker_contents" > "$keychain_marker")
  created_keychain=true
fi

security set-keychain-settings -lut 21600 "$keychain_path"
security unlock-keychain -p "$VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD" "$keychain_path"

if [[ "$created_keychain" == true ]]; then
  if ! (umask 077; printf '%s' "$cert_base64" | base64 --decode > "$cert_path") 2>/dev/null; then
    (umask 077; printf '%s' "$cert_base64" | base64 -D > "$cert_path")
  fi
  if ! security import "$cert_path" \
    -P "$VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_PASSWORD" \
    -A \
    -t cert \
    -f pkcs12 \
    -k "$keychain_path"; then
    rm -f "$cert_path"
    return 1 2>/dev/null || exit 1
  fi
  rm -f "$cert_path"
  security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s \
    -k "$VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD" \
    "$keychain_path"
fi

if ! security find-identity -v -p codesigning "$keychain_path" | grep -F "$VPN_CONTROL_MACOS_SIGNING_IDENTITY" >/dev/null; then
  echo "Signing identity was not found in imported keychain: $VPN_CONTROL_MACOS_SIGNING_IDENTITY" >&2
  security find-identity -v -p codesigning "$keychain_path" >&2 || true
  return 1 2>/dev/null || exit 1
fi

export VPN_CONTROL_MACOS_SIGNING_KEYCHAIN="$keychain_path"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'VPN_CONTROL_MACOS_SIGNING_KEYCHAIN=%s\n' "$keychain_path" >> "$GITHUB_ENV"
fi

echo "[vpn-control] macOS signing keychain prepared at $keychain_path"
