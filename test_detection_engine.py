
import unittest
from datetime import datetime, timedelta

from detection_engine import DetectionEngine


class TestDetectionEngine(unittest.TestCase):

    def setUp(self):
        self.engine = DetectionEngine(
            threshold=5,
            window_minutes=5
        )

    def test_detect_brute_force(self):

        start = datetime(2026, 11, 16, 8, 0)

        for minute in range(5):
            self.engine.add_failed_login(
                "203.0.113.25",
                start + timedelta(minutes=minute)
            )

        alerts = self.engine.detect_brute_force()

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")

    def test_no_alert_below_threshold(self):

        start = datetime(2026, 11, 16, 8, 0)

        for minute in range(4):
            self.engine.add_failed_login(
                "203.0.113.25",
                start + timedelta(minutes=minute)
            )

        self.assertEqual(
            self.engine.detect_brute_force(), []
        )

    def test_no_alert_outside_time_window(self):

        start = datetime(2026, 11, 16, 8, 0)

        for minute in [0, 10, 20, 30, 40]:
            self.engine.add_failed_login(
                "203.0.113.25",
                start + timedelta(minutes=minute)
            )

        self.assertEqual(
            self.engine.detect_brute_force(), []
        )

    def test_different_ips_are_separated(self):

        start = datetime(2026, 11, 16, 8, 0)

        for minute in range(5):
            self.engine.add_failed_login(
                f"203.0.113.{minute + 1}",
                start + timedelta(minutes=minute)
            )

        self.assertEqual(
            self.engine.detect_brute_force(), []
        )

    def test_invalid_threshold(self):

        with self.assertRaises(ValueError):
            DetectionEngine(threshold=0)

    def test_invalid_timestamp(self):

        with self.assertRaises(TypeError):
            self.engine.add_failed_login(
                "203.0.113.25",
                "2026-11-16 08:00:00"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
