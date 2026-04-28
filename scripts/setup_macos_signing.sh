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

runtime_dir="${RUNNER_TEMP:-$repo_root/.runtime/macos-signing}"
mkdir -p "$runtime_dir"

cert_path="$runtime_dir/vpn-control-signing.p12"
keychain_path="$runtime_dir/vpn-control-signing.keychain-db"

if ! printf '%s' "$cert_base64" | base64 --decode > "$cert_path" 2>/dev/null; then
  printf '%s' "$cert_base64" | base64 -D > "$cert_path"
fi

security create-keychain -p "$VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD" "$keychain_path"
security set-keychain-settings -lut 21600 "$keychain_path"
security unlock-keychain -p "$VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD" "$keychain_path"
security import "$cert_path" \
  -P "$VPN_CONTROL_MACOS_SIGNING_CERTIFICATE_PASSWORD" \
  -A \
  -t cert \
  -f pkcs12 \
  -k "$keychain_path"
security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$VPN_CONTROL_MACOS_KEYCHAIN_PASSWORD" \
  "$keychain_path"

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
