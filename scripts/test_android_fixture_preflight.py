import unittest

from android_fixture_preflight import source_inspection_guard


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


class AndroidFixturePreflightTest(unittest.TestCase):
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
