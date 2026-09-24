#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected_version="$(python3 "$repo_root/scripts/version_metadata.py" --field version)"

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

  dmg="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$dmg")"

  echo "[vpn-control] smoke testing macOS DMG: $dmg"
  mount_dir="$(mktemp -d)"
  attached=false
  attached_volume_device=""
  attached_device=""
  volume_attachment_matches() {
    hdiutil info -plist | python3 -c '
import plistlib
import sys

mountpoint, image_path, volume_device, image_device = sys.argv[1:]
document = plistlib.loads(sys.stdin.buffer.read())
images = document.get("images")
if not isinstance(images, list):
    raise SystemExit(1)
matching_images = [image for image in images if isinstance(image, dict) and image.get("image-path") == image_path]
if len(matching_images) != 1:
    raise SystemExit(1)
image = matching_images[0]
if image.get("writeable") is not False:
    raise SystemExit(1)
entities = image.get("system-entities")
if not isinstance(entities, list):
    raise SystemExit(1)
mounts = [entity for entity in entities if isinstance(entity, dict) and "mount-point" in entity]
if len(mounts) != 1 or mounts[0].get("mount-point") != mountpoint:
    raise SystemExit(1)
mounted_device = mounts[0].get("dev-entry")
if mounted_device != volume_device:
    raise SystemExit(1)
image_devices = [entity.get("dev-entry") for entity in entities if isinstance(entity, dict)
                 and isinstance(entity.get("dev-entry"), str) and mounted_device.startswith(entity["dev-entry"] + "s")]
if image_devices != [image_device]:
    raise SystemExit(1)
' "$mount_dir" "$dmg" "$attached_volume_device" "$attached_device"
  }
  image_attachment_matches() {
    hdiutil info -plist | python3 -c '
import plistlib
import sys

image_path, image_device = sys.argv[1:]
document = plistlib.loads(sys.stdin.buffer.read())
images = document.get("images")
if not isinstance(images, list):
    raise SystemExit(1)
matching_images = [image for image in images if isinstance(image, dict) and image.get("image-path") == image_path]
if len(matching_images) != 1:
    raise SystemExit(1)
image = matching_images[0]
if image.get("writeable") is not False:
    raise SystemExit(1)
entities = image.get("system-entities")
if not isinstance(entities, list):
    raise SystemExit(1)
devices = [entity.get("dev-entry") for entity in entities if isinstance(entity, dict)]
if image_device not in devices:
    raise SystemExit(1)
if any(isinstance(entity, dict) and "mount-point" in entity for entity in entities):
    raise SystemExit(1)
' "$dmg" "$attached_device"
  }
  image_attachment_is_absent() {
    hdiutil info -plist | python3 -c '
import plistlib
import sys

image_path = sys.argv[1]
document = plistlib.loads(sys.stdin.buffer.read())
images = document.get("images")
if not isinstance(images, list):
    raise SystemExit(1)
raise SystemExit(any(isinstance(image, dict) and image.get("image-path") == image_path for image in images))
' "$dmg"
  }
  post_detach_attachment_state() {
    hdiutil info -plist | python3 -c '
import plistlib
import sys

mountpoint, image_path, image_device = sys.argv[1:]
document = plistlib.loads(sys.stdin.buffer.read())
images = document.get("images")
if not isinstance(images, list):
    raise SystemExit(1)
matching_images = [image for image in images if isinstance(image, dict) and image.get("image-path") == image_path]
if not matching_images:
    print("absent")
    raise SystemExit(0)
if len(matching_images) != 1:
    print("ambiguous-image")
    raise SystemExit(0)
entities = matching_images[0].get("system-entities")
if not isinstance(entities, list):
    print("malformed-image")
    raise SystemExit(0)
devices = [entity.get("dev-entry") for entity in entities if isinstance(entity, dict)]
if image_device not in devices:
    print("image-device-changed")
    raise SystemExit(0)
mounts = [entity for entity in entities if isinstance(entity, dict) and entity.get("mount-point") == mountpoint]
if mounts:
    print("still-attached-owned-image")
else:
    print("image-attached-elsewhere")
' "$mount_dir" "$dmg" "$attached_device"
  }
  detach_owned() {
    if volume_attachment_matches; then
      hdiutil detach "$attached_volume_device" -quiet || return 1
    elif ! image_attachment_matches; then
      echo "DMG attachment identity changed; mounted fixture preserved at $mount_dir" >&2
      return 1
    fi
    # Detach the mounted volume first. A whole-image detach can report success
    # before macOS releases its volume mount, leaving the private mountpoint busy.
    if image_attachment_is_absent; then
      return 0
    fi
    if ! image_attachment_matches; then
      echo "DMG image attachment changed after volume detach; mounted fixture preserved at $mount_dir" >&2
      return 1
    fi
    hdiutil detach "$attached_device" -quiet
  }
  detach_owned_force() {
    if volume_attachment_matches; then
      hdiutil detach "$attached_volume_device" -force -quiet || return 1
    elif ! image_attachment_matches; then
      return 1
    fi
    if image_attachment_is_absent; then
      return 0
    fi
    image_attachment_matches && hdiutil detach "$attached_device" -force -quiet
  }
  cleanup() {
    # Do not repeat cleanup through EXIT if explicit cleanup itself fails.
    trap - EXIT
    if [[ "$attached" == true ]]; then
      for attempt in 1 2 3 4 5; do
        if detach_owned; then
          attached=false
          break
        fi
        if (( attempt < 5 )); then sleep 1; fi
      done
      if [[ "$attached" == true ]] && detach_owned_force; then
        attached=false
      fi
      if [[ "$attached" == true ]]; then
        echo "DMG could not be detached; mounted fixture preserved at $mount_dir" >&2
        return 1
      fi
    fi
    # hdiutil can report detach success before its mountpoint is released. Only
    # remove the empty directory, never recurse into a possibly mounted volume.
    for attempt in 1 2 3 4 5; do
      if rmdir "$mount_dir"; then return; fi
      if (( attempt < 5 )); then sleep 1; fi
    done
    attachment_state="unavailable"
    if ! attachment_state="$(post_detach_attachment_state)"; then
      attachment_state="unavailable"
    fi
    echo "DMG mountpoint could not be removed after detach; attachment state: $attachment_state; empty fixture preserved at $mount_dir" >&2
    return 1
  }
  trap cleanup EXIT

  attachment_devices="$(hdiutil attach "$dmg" -nobrowse -readonly -mountpoint "$mount_dir" -plist | python3 -c '
import plistlib
import sys

mountpoint = sys.argv[1]
document = plistlib.loads(sys.stdin.buffer.read())
entities = document.get("system-entities")
if not isinstance(entities, list):
    raise SystemExit(1)
mounts = [entity for entity in entities if isinstance(entity, dict) and entity.get("mount-point") == mountpoint]
if len(mounts) != 1 or not isinstance(mounts[0].get("dev-entry"), str):
    raise SystemExit(1)
mounted_device = mounts[0]["dev-entry"]
image_devices = [entity.get("dev-entry") for entity in entities if isinstance(entity, dict)
                 and isinstance(entity.get("dev-entry"), str) and mounted_device.startswith(entity["dev-entry"] + "s")]
if len(image_devices) != 1:
    raise SystemExit(1)
print(mounted_device, image_devices[0])
' "$mount_dir")"
  read -r attached_volume_device attached_device <<< "$attachment_devices"
  if [[ -z "$attached_volume_device" || -z "$attached_device" ]]; then
    echo "DMG attachment did not report an owned volume and image device" >&2
    exit 1
  fi
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
  if [[ "$version" != "$expected_version" ]]; then
    echo "macOS package version must match canonical $expected_version, got $version" >&2
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

  python3 "$repo_root/scripts/test_packaged_cli.py" \
    --launcher "$app_path/Contents/MacOS/$executable_name" --expected-version "$expected_version"

  cleanup
  echo "[vpn-control] macOS DMG smoke passed: $bundle_name $version"
done
