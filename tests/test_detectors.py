import unittest
from datetime import datetime, timedelta, timezone

from app.detectors import detect_ssh_brute_force


def make_failures(seconds):
    """Создаёт события с заданными смещениями времени в секундах."""
    start = datetime(2026, 10, 29, tzinfo=timezone.utc)

    return {
        "172.16.15.1": [
            {
                "timestamp": start + timedelta(seconds=offset),
                "line_number": number,
            }
            for number, offset in enumerate(seconds, start=1)
        ]
    }


class TestSSHBruteForce(unittest.TestCase):
    def test_five_failures_detected(self):
        events = make_failures([0, 5, 10, 15, 20])

        findings = detect_ssh_brute_force(events)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["ip"], "172.16.15.1")
        self.assertEqual(findings[0]["count"], 5)
        self.assertEqual(findings[0]["lines"], [1, 2, 3, 4, 5])

    def test_four_failures_not_detected(self):
        events = make_failures([0, 5, 10, 15])

        findings = detect_ssh_brute_force(events)

        self.assertEqual(findings, [])

    def test_failures_outside_window_not_detected(self):
        events = make_failures([0, 100, 200, 300, 400])

        findings = detect_ssh_brute_force(events)

        self.assertEqual(findings, [])
