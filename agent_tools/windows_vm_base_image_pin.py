"""Frozen Windows fixture base image: new clones need the operator-recorded hash.

A clone is a copy-on-write child of one published image whose
`manifestSha256` covers its disk, firmware variables and TPM state. The hash
the operator last reviewed lives only in the private pin file
`.runtime/windows-vm-base-image-pin.json` under the repository root, which is
git-ignored; this module and its tests carry logic only, never a hash, path or
credential.

Policy:
* `require_pinned` runs before any new clone is prepared. A missing pin (legacy
  checkouts, before the first deliberate refresh) and a different image hash
  both refuse, and the message names the refresh step.
* `windows_vm_deploy.py` and the image/instance sources are frozen by the
  sign-in packet source pins, so the gate is not inside them. `create_clone`
  and `start_clone` here are the only sanctioned clone entry points: they
  check the pin, then delegate unchanged to `windows_vm_deploy`. A repository
  test refuses any other non-test caller that creates a clone.
* `refresh` is the only writer. It must be run on purpose with the exact hash
  to accept (`--manifest-sha256`) and appends the superseded hash to a history.
  It does not contact any host or VM.
* Existing instances, images and their histories are never read or rewritten:
  the pin gates only the creation of new clones.

CLI: `python3 -m agent_tools.windows_vm_base_image_pin show|refresh ...`
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import time

PIN_RELATIVE = Path(".runtime/windows-vm-base-image-pin.json")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
REFRESH_COMMAND = "python3 -m agent_tools.windows_vm_base_image_pin refresh --manifest-sha256 <reviewed manifestSha256>"


class BasePinError(ValueError):
    """A refusal with a stable token first, then operator guidance."""


def pin_path(root) -> Path:
    return Path(root) / PIN_RELATIVE


def _check_hash(value) -> str:
    if type(value) is not str or _HASH.match(value) is None:
        raise BasePinError("deployment_base_image_hash_invalid: expected 64 lowercase hex characters")
    return value


def read_pin(root) -> dict | None:
    """The recorded pin, or None when none was ever recorded."""
    path = pin_path(root)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise BasePinError("deployment_base_image_pin_unreadable: " + type(error).__name__) from error
    try:
        value = json.loads(raw)
    except ValueError as error:
        raise BasePinError("deployment_base_image_pin_corrupt") from error
    if (type(value) is not dict or value.get("schemaVersion") != 1
            or type(value.get("history")) is not list):
        raise BasePinError("deployment_base_image_pin_corrupt")
    _check_hash(value.get("expectedManifestSha256"))
    return value


def require_pinned(root, image) -> None:
    """Refuse a new clone from an image whose hash is not the recorded one."""
    manifest = _check_hash(image.get("manifestSha256") if type(image) is dict else None)
    pin = read_pin(root)
    if pin is None:
        raise BasePinError(
            "deployment_base_image_unpinned: no expected base image hash is recorded for this checkout; "
            "review the image and record it deliberately with: " + REFRESH_COMMAND)
    if pin["expectedManifestSha256"] != manifest:
        raise BasePinError(
            "deployment_base_image_hash_mismatch: the image selected for a new clone does not match the "
            "recorded base image hash; if the new image is intended, run: " + REFRESH_COMMAND)


def refresh(root, manifest_sha256, *, now_ms: int | None = None) -> dict:
    """Deliberately record a new expected hash; the old one moves to history."""
    manifest_sha256 = _check_hash(manifest_sha256)
    now = int(time.time() * 1000) if now_ms is None else now_ms
    previous = read_pin(root)
    history = [] if previous is None else list(previous["history"])
    if previous is not None and previous["expectedManifestSha256"] != manifest_sha256:
        history.append({"manifestSha256": previous["expectedManifestSha256"],
                        "recordedAtUnixMs": previous.get("recordedAtUnixMs"),
                        "supersededAtUnixMs": now})
    value = {"schemaVersion": 1, "expectedManifestSha256": manifest_sha256,
             "recordedAtUnixMs": now, "history": history}
    path = pin_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return value


def start_clone(root, request, setup, credential_file, *, image, network=None):
    """Start one clone of an exact published image, only from the pinned base image."""
    from . import windows_vm_deploy as deploy
    if image is None:
        raise BasePinError("deployment_base_image_required: a clone needs an exact published image")
    from .windows_vm_image import validate_context_image
    image = validate_context_image(image)
    require_pinned(root, image)
    return deploy.start(root, request, setup, credential_file, image=image, network=network)


def create_clone(root, request, setup, credential_file, *, now_ms=None):
    """`windows_vm_deploy.create` for clones: the newest matching image must be the pinned one.

    The image listing is read-only host contact, exactly as in `create`; the pin is
    checked before anything is prepared. A blank install (no image yet) is the
    next image template, not a clone, and is not this function's business.
    """
    import time
    from . import windows_vm_deploy as deploy
    from . import windows_vm_unattend as unattended
    from .windows_vm_image import choose_image
    spec = deploy.FreshWindowsVmSpec.parse(request)
    parsed = unattended.parse_setup(setup)
    image = choose_image(deploy.images(root, spec.as_dict()), spec.as_dict(), parsed,
                         time.time_ns() // 1_000_000 if now_ms is None else now_ms)
    if image is None:
        raise BasePinError("deployment_base_image_missing: no matching unexpired base image; capture one, then run: " + REFRESH_COMMAND)
    return {**start_clone(root, spec.as_dict(), parsed, credential_file, image=image),
            "image": image, "nextAction": None}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("show")
    refresh_parser = sub.add_parser("refresh")
    refresh_parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "show":
            pin = read_pin(args.root)
            print(json.dumps({"pinned": pin is not None, **({} if pin is None else
                              {"expectedManifestSha256": pin["expectedManifestSha256"], "historyLength": len(pin["history"])})}))
        else:
            value = refresh(args.root, args.manifest_sha256)
            print(json.dumps({"pinned": True, "expectedManifestSha256": value["expectedManifestSha256"],
                              "historyLength": len(value["history"])}))
    except BasePinError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
