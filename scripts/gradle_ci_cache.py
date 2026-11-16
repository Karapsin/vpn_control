#!/usr/bin/env python3
"""Hosted Gradle build-cache policy for one CI job.

`setup-gradle` saves the Gradle User Home, which holds the local build cache,
only in the `Gradle Cache Warm` workflow (.github/workflows/gradle-cache-warm.yml),
which runs on the default branch so that every branch can restore its entries.
Every other workflow sets `cache-read-only: true`.

Run with `--restore-policy` (step id `gradle-restore`) right before each
`Set up Gradle` step: it writes `restore=true` to `$GITHUB_OUTPUT` only for a
development source, and setup-gradle gets
`cache-disabled: ${{ steps.gradle-restore.outputs.restore != 'true' }}`, so a
release-ready source never restores the Gradle User Home that dev warm runs
wrote, and a missing decision restores nothing.

Run without arguments right after `Set up Gradle`, it decides whether the job's
Gradle product steps reuse task outputs:

- disabled for every release-ready source, that is one passing
  `scripts/check_release_metadata.py --require-release-ready`, which the stable
  publisher requires of the SHA it publishes, so release packages never contain
  cached task outputs;
- enabled otherwise.

It appends `GRADLE_BUILD_CACHE_OPTS` to `$GITHUB_ENV` (`-Dorg.gradle.caching=true`
or empty); only the product build steps pass it as `GRADLE_OPTS`, so fixture
Gradle builds in other steps never use the cache. It also installs an init
script that marks every `Test` task as never cacheable, so every test still
executes on every push.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
INIT_SCRIPT_NAME = "vpn-control-ci-never-cache-tests.gradle"
# Only the product build (settings.gradle.kts rootProject.name); fixture builds are untouched.
INIT_SCRIPT = """// Written by scripts/gradle_ci_cache.py: CI may reuse task outputs, but every test executes.
allprojects {
    if (rootProject.name == "vpn_control") {
        tasks.withType(Test).configureEach {
            outputs.doNotCacheIf("VPN Control CI executes every test") { true }
        }
    }
}
"""
ENABLED = "-Dorg.gradle.caching=true"


def release_ready(root: Path) -> bool:
    sys.path.insert(0, str(root / "scripts"))
    try:
        import check_release_metadata
        check_release_metadata.validate(root, True)
    except (SystemExit, Exception):
        # Unreadable or unready metadata cannot be published either.
        return False
    finally:
        sys.path.remove(str(root / "scripts"))
    return True


def decide(environment: dict[str, str], root: Path = ROOT) -> dict[str, str]:
    if release_ready(root):
        return {"mode": "disabled", "reason": "release-ready source"}
    return {"mode": "enabled", "reason": "development source"}


def install(decision: dict[str, str], environment: dict[str, str]) -> str:
    """Install the never-cache-tests init script when enabled; return the product build's Gradle options."""
    if decision["mode"] != "enabled":
        return ""
    home = Path(environment.get("GRADLE_USER_HOME") or Path.home() / ".gradle")
    init = home / "init.d"
    init.mkdir(parents=True, exist_ok=True)
    (init / INIT_SCRIPT_NAME).write_text(INIT_SCRIPT, encoding="utf-8")
    return ENABLED


def apply(decision: dict[str, str], environment: dict[str, str]) -> None:
    options = install(decision, environment)
    output = environment.get("GITHUB_ENV")
    if not output:
        raise SystemExit("GITHUB_ENV is required")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write("GRADLE_BUILD_CACHE_OPTS=%s\n" % options)


def restore_policy(decision: dict[str, str], environment: dict[str, str]) -> None:
    """Restore the shared Gradle User Home only into development builds."""
    output = environment.get("GITHUB_OUTPUT")
    if not output:
        raise SystemExit("GITHUB_OUTPUT is required")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write("restore=%s\n" % ("true" if decision["mode"] == "enabled" else "false"))


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["--restore-policy"]):
        raise SystemExit("usage: gradle_ci_cache.py [--restore-policy]")
    decision = decide(dict(os.environ))
    if arguments:
        restore_policy(decision, dict(os.environ))
        print("[vpn-control] Gradle cache restore " + json.dumps(decision, sort_keys=True))
        return 0
    apply(decision, dict(os.environ))
    print("[vpn-control] Gradle build cache " + json.dumps(decision, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
