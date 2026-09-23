#!/usr/bin/env python3
"""Disposable Android public-CLI manual subscription refresh acceptance driver."""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from android_no_update_tls_preflight import (
    public_cli_argv, public_cli_environment, require_interactive_stdin, run_fixture_lifecycle,
)


def require_fixture_source(source: str, device_port: int) -> str:
    """Accept only the local disposable relay mapped into this guest."""
    parsed = urlsplit(source)
    if (parsed.scheme != "https" or parsed.hostname != "localhost" or parsed.port != device_port
            or parsed.path != "/subscription" or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError("Fixture subscription source must be local HTTPS /subscription")
    return source


def require_local_fixture_certificate(path: Path, label: str) -> Path:
    """Reject missing/symlink certificate inputs before any ADB-side fixture work."""
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise ValueError(f"Fixture {label} must be a local regular file")
    return path.resolve(strict=True)


def cli_json(args, *command: str) -> dict:
    result = subprocess.run(
        [*public_cli_argv(args.cli), "--json", "--android", "--serial", args.serial,
         "--timeout-seconds", str(args.timeout_seconds), *command],
        check=False, text=True, capture_output=True, env=args.cli_environment,
    )
    records = getattr(args, "cli_records", None)
    if records is not None:
        records.append({"command": list(command), "exit": result.returncode,
                        "stdout": result.stdout, "stderr": result.stderr})
    if result.returncode:
        raise RuntimeError("Public Android CLI command failed")
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Public Android CLI returned invalid JSON") from error
    if not isinstance(response, dict):
        raise RuntimeError("Public Android CLI returned invalid envelope")
    return response


def require_owner(response: dict) -> tuple[str, int]:
    data = response.get("data")
    owner = response.get("controllerId")
    revision = response.get("configurationRevision")
    if (not response.get("ok") or not isinstance(data, dict) or not isinstance(owner, str) or not owner
            or isinstance(revision, bool) or not isinstance(revision, int)):
        raise RuntimeError("Public Android CLI has no usable owner identity")
    return owner, revision


def require_accepted(response: dict, owner: str) -> str:
    operation = response.get("operationId")
    if not response.get("ok") or response.get("controllerId") != owner or not isinstance(operation, str) or not operation:
        raise RuntimeError("Subscription mutation was not accepted with the guarded owner")
    return operation


def require_terminal(response: dict, owner: str, operation: str) -> dict:
    if (not response.get("ok") or not response.get("final") or response.get("controllerId") != owner
            or response.get("operationId") != operation or not isinstance(response.get("data"), dict)):
        raise RuntimeError("Subscription operation did not reach a matching terminal success")
    return response["data"]


def require_sync_success(response: dict, owner: str) -> dict:
    if not response.get("ok") or response.get("controllerId") != owner or response.get("final") is False:
        raise RuntimeError("Subscription synchronous mutation did not finish successfully")
    return response.get("data") if isinstance(response.get("data"), dict) else {}


def require_cached_locations(args, subscription_id: str, *, minimum: int) -> int:
    response = cli_json(args, "subscriptions", "show", subscription_id)
    data = response.get("data")
    count = data.get("cachedLocations") if isinstance(data, dict) else None
    if not response.get("ok") or isinstance(count, bool) or not isinstance(count, int) or count < minimum:
        raise RuntimeError("Subscription does not expose cached fixture locations")
    return count


def write_private_cli_records(args) -> None:
    records = getattr(args, "cli_records", [])
    args.probe_output.write_text(json.dumps(records, sort_keys=True) + "\n")
    args.probe_output.chmod(0o600)


def subscription_request_count(log: Path) -> int:
    """Read the relay's synthetic, credential-free request counter evidence."""
    try:
        entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Fixture request evidence is unavailable") from error
    counts = [entry.get("count") for entry in entries if isinstance(entry, dict)
              and entry.get("method") == "GET" and entry.get("endpoint") == "subscription"]
    if not entries:
        return 0
    if not counts or any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in counts):
        raise RuntimeError("Fixture request evidence is invalid")
    if counts != sorted(set(counts)):
        raise RuntimeError("Fixture request evidence is not monotonic")
    return counts[-1]


def require_new_subscription_source(args, source: str, owner: str, revision: int) -> None:
    """ADD upserts by URL; never claim an existing subscription for fixture cleanup."""
    listing = cli_json(args, "subscriptions", "list")
    if require_owner(listing) != (owner, revision):
        raise RuntimeError("Subscription admission snapshot changed")
    subscriptions = listing["data"].get("subscriptions")
    if not isinstance(subscriptions, list):
        raise RuntimeError("Subscription admission list is invalid")
    for entry in subscriptions:
        identity = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(identity, str) or not identity:
            raise RuntimeError("Subscription admission identity is invalid")
        shown = cli_json(args, "subscriptions", "show", identity)
        if require_owner(shown) != (owner, revision):
            raise RuntimeError("Subscription admission snapshot changed")
        existing_source = shown["data"].get("source")
        if shown["data"].get("id") != identity or not isinstance(existing_source, str):
            raise RuntimeError("Subscription admission source is invalid")
        if existing_source == source:
            raise RuntimeError("Fixture subscription source already exists")


def guarded_mutation(args, command: list[str], *, expected_owner: str | None = None,
                     expected_revision: int | None = None, asynchronous: bool = True) -> tuple[str, dict]:
    owner, revision = require_owner(cli_json(args, "status"))
    if expected_owner is not None and expected_owner != owner:
        raise RuntimeError("Controller owner changed; preserving accepted operation identity")
    if expected_revision is not None and revision != expected_revision:
        raise RuntimeError("Subscription admission snapshot changed")
    command_prefix = ["--controller-id", owner, "--if-revision", str(revision)]
    if asynchronous:
        command_prefix.append("--async")
    response = cli_json(args, *command_prefix, *command)
    if asynchronous:
        require_accepted(response, owner)
    else:
        require_sync_success(response, owner)
    return owner, response


def run_subscription_refresh_action(args, _adb, _receipt) -> dict:
    """Add, refresh, wait and delete through one public UID-2000 CLI owner."""
    source = require_fixture_source(args.subscription_source, args.device_port)
    subscription_id = None
    accepted = {}
    original_source = None
    owner = None
    uncertain = False
    args.cli_records = []
    try:
        source_response = cli_json(args, "source", "show")
        owner, admission_revision = require_owner(source_response)
        source_data = source_response.get("data")
        if not isinstance(source_data, dict) or source_data.get("mode") not in ("current-locations", "subscription"):
            raise RuntimeError("Original source state is unavailable")
        if source_data["mode"] == "subscription" and not isinstance(source_data.get("subscriptionId"), str):
            raise RuntimeError("Original subscription source identity is unavailable")
        require_new_subscription_source(args, source, owner, admission_revision)
        original_source = source_data
        owner, add_response = guarded_mutation(args, ["subscriptions", "add", "--source", source, "--name", args.subscription_name], expected_owner=owner, expected_revision=admission_revision)
        add_operation = add_response["operationId"]
        accepted["add"] = add_operation
        add_wait = cli_json(args, "operations", "wait", add_operation)
        add_data = require_terminal(add_wait, owner, add_operation)
        subscription_id = add_data.get("id")
        if not isinstance(subscription_id, str) or not subscription_id:
            raise RuntimeError("Subscription add did not return an exact subscription identity")
        cached_after_add = require_cached_locations(args, subscription_id, minimum=0)
        requests_before_refresh = subscription_request_count(args.server_log)
        refresh_owner, refresh_response = guarded_mutation(args, ["subscriptions", "refresh", subscription_id], expected_owner=owner)
        refresh_operation = refresh_response["operationId"]
        accepted["refresh"] = refresh_operation
        refresh_wait = cli_json(args, "operations", "wait", refresh_operation)
        require_terminal(refresh_wait, refresh_owner, refresh_operation)
        requests_after_refresh = subscription_request_count(args.server_log)
        if requests_after_refresh <= requests_before_refresh:
            raise RuntimeError("Subscription refresh did not produce a new fixture request")
        cached_after_refresh = require_cached_locations(args, subscription_id, minimum=1)
        return {"subscriptionId": subscription_id, "operations": accepted,
                "cachedLocations": {"afterAdd": cached_after_add, "afterRefresh": cached_after_refresh},
                "fixtureRequests": {"beforeRefresh": requests_before_refresh, "afterRefresh": requests_after_refresh}}
    except Exception:
        # Once an operation is accepted, a malformed/nonterminal wait leaves its
        # mutation unknown; never issue another write against that owner.
        uncertain = original_source is not None
        raise
    finally:
        # A timeout/unknown add never gets replayed or guessed at.  Delete only an
        # exact subscription ID returned by a terminal add operation.
        try:
            if subscription_id is not None and not uncertain:
                delete_owner, _ = guarded_mutation(args, ["subscriptions", "delete", subscription_id], expected_owner=owner, asynchronous=False)
                if delete_owner != owner:
                    raise RuntimeError("Controller owner changed during subscription cleanup")
            if original_source is not None and not uncertain:
                restore = ["source", "set", original_source["mode"]]
                if original_source["mode"] == "subscription":
                    restore.append(original_source["subscriptionId"])
                guarded_mutation(args, restore, expected_owner=owner, asynchronous=False)
                final_source = cli_json(args, "source", "show")
                if final_source.get("controllerId") != owner or final_source.get("data") != original_source:
                    raise RuntimeError("Original source state was not restored")
        finally:
            write_private_cli_records(args)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True); parser.add_argument("--serial", required=True)
    parser.add_argument("--cli", type=Path, required=True); parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--leaf-certificate", type=Path, required=True); parser.add_argument("--fixture-parent", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True); parser.add_argument("--probe-output", type=Path, required=True)
    parser.add_argument("--device-port", type=int, required=True); parser.add_argument("--host-port", type=int, required=True)
    parser.add_argument("--staging", required=True); parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--expected-avd", required=True); parser.add_argument("--expected-api", required=True)
    parser.add_argument("--expected-version", required=True); parser.add_argument("--expected-code", required=True)
    parser.add_argument("--base-apk", type=Path, required=True); parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--subscription-source", required=True); parser.add_argument("--subscription-name", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    require_interactive_stdin()
    require_fixture_source(args.subscription_source, args.device_port)
    args.certificate = require_local_fixture_certificate(args.certificate, "CA certificate")
    args.leaf_certificate = require_local_fixture_certificate(args.leaf_certificate, "leaf certificate")
    args.cli_environment = public_cli_environment(args.adb, args.cli)
    target = "/apex/com.android.conscrypt/cacerts" if args.expected_api == "35" else "/system/etc/security/cacerts"
    if args.expected_api not in ("29", "35"):
        raise ValueError("Fixture refresh driver supports only verified API29/API35 targets")
    run_fixture_lifecycle(args, run_subscription_refresh_action, ca_store_target=target, transport_mode="reverse-only")


if __name__ == "__main__":
    main()
