#!/usr/bin/env bash
# Install the native Android build tools required by app/src/main/cpp.
set -euo pipefail

sdkmanager=""
for variable in ANDROID_HOME ANDROID_SDK_ROOT; do
  root="${!variable:-}"
  candidate="${root:+$root/cmdline-tools/latest/bin/sdkmanager}"
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    sdkmanager="$candidate"
    break
  fi
done

if [[ -z "$sdkmanager" ]] && command -v sdkmanager >/dev/null 2>&1; then
  sdkmanager="$(command -v sdkmanager)"
fi

if [[ -z "$sdkmanager" ]]; then
  echo "sdkmanager not found: set ANDROID_HOME or ANDROID_SDK_ROOT to an SDK with cmdline-tools/latest/bin/sdkmanager, or add sdkmanager to PATH" >&2
  exit 127
fi

"$sdkmanager" "ndk;28.2.13676358" "cmake;3.22.1"
