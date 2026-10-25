import unittest

from agent_tools import readiness_windows_display as display


class WindowsDisplayTest(unittest.TestCase):
    machine = '21b29aa0-123b-4cc3-a238-b23bdfef1327'
    boot = '2026-10-20T09:04:39.5000000Z'

    def test_fixed_read_only_source(self):
        source = display.powershell_source(self.machine, self.boot)
        self.assertIn('PowerSettingRegisterNotification', source)
        self.assertIn('DISPLAY_INITIAL_VALUE_UNAVAILABLE', source)
        self.assertNotIn('SetThreadExecutionState', source)
        self.assertNotIn('SendInput', source)
        self.assertNotIn('SendMessage', source)

    def test_actual_callback_states_required(self):
        base = dict(schemaVersion=1, machine=self.machine, boot=self.boot)
        for state, expected in [(0,'asleep'), (1,'awake'), (2,'dimmed')]:
            self.assertEqual(expected, display.validate(dict(base,displayState=state),self.machine,self.boot))
        for value in [True, -1, 3, None, 'awake']:
            with self.assertRaisesRegex(ValueError, '^windows_display_observation_invalid$'):
                display.validate(dict(base,displayState=value), self.machine,self.boot)
        with self.assertRaises(ValueError):
            display.validate(dict(base,displayState=1),self.machine,'2026-10-21T00:00:00Z')


if __name__ == '__main__':
    unittest.main()
