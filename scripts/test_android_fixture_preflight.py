import unittest

from android_fixture_preflight import (
    require_disconnected_effective_proxy,
    require_terminal_operation_history,
    source_inspection_guard,
)


def status(*, running=False, observation="stopped", selected=None):
    return {
        "ok": True,
        "final": True,
        "code": "OK",
        "controllerId": "owner",
        "configurationRevision": 7,
        "data": {
            "runtimeRunning": running,
            "runtimeObservation": observation,
            "selectedLocationId": selected,
        },
    }


def operations(*, owner="owner", entries=None):
    return {
        "ok": True,
        "final": True,
        "code": "OK",
        "controllerId": owner,
        "operationId": None,
        "data": {
            "scope": "android-provider-operations",
            "operations": [] if entries is None else entries,
        },
    }


def terminal_operation(*, owner="owner", phase="succeeded", code="OK"):
    return {
        "id": "operation-1",
        "operation": "subscriptions.refresh",
        "requestId": "request-1",
        "controllerId": owner,
        "configurationRevision": 2,
        "final": True,
        "phase": phase,
        "code": code,
        "cancellable": False,
        "restartRequired": False,
    }


class AndroidFixturePreflightTest(unittest.TestCase):
    def test_terminal_operation_history_is_admitted_even_when_nonempty(self):
        history = [terminal_operation(), terminal_operation(phase="failed", code="RUNTIME_FAILED"),
                   {**terminal_operation(), "restartRequired": True}]
        self.assertEqual(history, require_terminal_operation_history(operations(entries=history), "owner"))

    def test_operation_history_rejects_active_unknown_malformed_or_foreign_entries(self):
        active = {**terminal_operation(), "final": False, "phase": "running"}
        malformed = {key: value for key, value in terminal_operation().items() if key != "requestId"}
        cases = [
            operations(owner="other"),
            {**operations(), "ok": False},
            {**operations(), "final": False},
            {**operations(), "code": "OUTCOME_UNKNOWN"},
            {**operations(), "data": {}},
            operations(entries="not-a-list"),
            operations(entries=[active]),
            operations(entries=[terminal_operation(code="OUTCOME_UNKNOWN")]),
            operations(entries=[terminal_operation(code="ACCEPTED")]),
            operations(entries=[malformed]),
            operations(entries=[terminal_operation(owner="other")]),
        ]
        for response in cases:
            with self.subTest(response=response), self.assertRaisesRegex(ValueError, "Operation"):
                require_terminal_operation_history(response, "owner")

    def test_effective_proxy_rejects_stale_component_despite_null_primary_setting(self):
        stale = {
            "http_proxy": "null",
            "global_http_proxy_host": "127.0.0.1",
            "global_http_proxy_port": "29579",
            "global_http_proxy_pac": "",
            "global_http_proxy_exclusion_list": "",
        }
        with self.assertRaisesRegex(ValueError, "effective proxy"):
            require_disconnected_effective_proxy(stale)

    def test_effective_proxy_accepts_api29_and_api35_disabled_representations(self):
        for disabled in (
            {
                "http_proxy": "null",
                "global_http_proxy_host": "null",
                "global_http_proxy_port": "null",
                "global_http_proxy_pac": "null",
                "global_http_proxy_exclusion_list": "null",
            },
            {
                "http_proxy": ":0",
                "global_http_proxy_host": None,
                "global_http_proxy_port": "0",
                "global_http_proxy_pac": "",
                "global_http_proxy_exclusion_list": "",
            },
        ):
            with self.subTest(disabled=disabled):
                self.assertEqual(disabled, require_disconnected_effective_proxy(disabled))

    def test_effective_proxy_rejects_each_active_or_partial_component(self):
        disabled = {
            "http_proxy": "null",
            "global_http_proxy_host": "null",
            "global_http_proxy_port": "0",
            "global_http_proxy_pac": "null",
            "global_http_proxy_exclusion_list": "null",
        }
        active_values = {
            "http_proxy": "127.0.0.1:29579",
            "global_http_proxy_host": "127.0.0.1",
            "global_http_proxy_port": "29579",
            "global_http_proxy_pac": "https://fixture.invalid/proxy.pac",
            "global_http_proxy_exclusion_list": "localhost",
        }
        for field, active in active_values.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, "effective proxy"):
                    require_disconnected_effective_proxy({**disabled, field: active})
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    require_disconnected_effective_proxy({k: v for k, v in disabled.items() if k != field})

    def test_original_selected_identity_refuses_source_scope_inspection(self):
        with self.assertRaises(ValueError):
            source_inspection_guard(status(selected="original-selection"))

    def test_missing_unknown_or_running_runtime_is_rejected(self):
        cases = [
            {},
            {**status(), "ok": False},
            {**status(), "final": False},
            {**status(), "code": "OUTCOME_UNKNOWN"},
            {**status(), "controllerId": None},
            {**status(), "configurationRevision": None},
            {**status(), "configurationRevision": True},
            {**status(), "data": {}},
            status(observation="unknown"),
            status(running=True),
        ]
        for response in cases:
            with self.subTest(response=response), self.assertRaises(ValueError):
                source_inspection_guard(response)

    def test_off_without_selection_returns_exact_mutation_guard(self):
        self.assertEqual({"controllerId": "owner", "configurationRevision": 7},
                         source_inspection_guard(status()))


if __name__ == "__main__":
    unittest.main()
