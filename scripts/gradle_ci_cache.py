#!/usr/bin/env python3
"""Hosted Gradle build-cache policy for one CI job; run it right after `Set up Gradle`.

`setup-gradle` saves the Gradle User Home, which holds the local build cache,
only on `dev` pushes and only reads it elsewhere (its `cache-read-only` input);
`main` runs disable that cache entirely (`cache-disabled`).

This script decides whether the job's product Gradle steps reuse task outputs:

- disabled on `refs/heads/main` and for every release-ready source, that is one
  passing `scripts/check_release_metadata.py --require-release-ready`, which
  the stable publisher requires of the SHA it publishes, so release packages
  never contain cached task outputs;
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
    reference = environment.get("GITHUB_REF", "")
    if reference == "refs/heads/main":
        return {"mode": "disabled", "reason": "main run"}
    if release_ready(root):
        return {"mode": "disabled", "reason": "release-ready source"}
    return {"mode": "enabled", "reason": "development source"}


def apply(decision: dict[str, str], environment: dict[str, str]) -> None:
    if decision["mode"] == "enabled":
        home = Path(environment.get("GRADLE_USER_HOME") or Path.home() / ".gradle")
        init = home / "init.d"
        init.mkdir(parents=True, exist_ok=True)
        (init / INIT_SCRIPT_NAME).write_text(INIT_SCRIPT, encoding="utf-8")
    output = environment.get("GITHUB_ENV")
    if not output:
        raise SystemExit("GITHUB_ENV is required")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write("GRADLE_BUILD_CACHE_OPTS=%s\n" % (ENABLED if decision["mode"] == "enabled" else ""))


def main() -> int:
    decision = decide(dict(os.environ))
    apply(decision, dict(os.environ))
    print("[vpn-control] Gradle build cache " + json.dumps(decision, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
