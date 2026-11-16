import unittest
from datetime import datetime

from sentinel import SentinelX


class TestSentinelIntegration(unittest.TestCase):

    def setUp(self):
        self.sentinel = SentinelX(
            threshold=5,
            window_minutes=5
        )

        self.source_ip = "203.0.113.25"
        self.log_date = datetime.now().strftime("%b %d")

    def create_log(self, time, message, pid=1001):
        return (
            f"{self.log_date} {time} server "
            f"sshd[{pid}]: {message}"
        )

    def add_failed_attempts(self, times):
        for index, time in enumerate(times):
            log = self.create_log(
                time,
                f"Failed password for admin from "
                f"{self.source_ip} port 50221 ssh2",
                pid=1001 + index
            )
            self.sentinel.analyse_line(log)

    def test_brute_force_detection(self):
        times = [
            "08:00:00",
            "08:01:00",
            "08:02:00",
            "08:03:00",
            "08:04:00"
        ]

        self.add_failed_attempts(times)

        report = self.sentinel.generate_report()

        self.assertEqual(report["total_alerts"], 1)
        self.assertEqual(
            report["alerts"][0]["severity"],
            "HIGH"
        )

    def test_successful_login_after_failed_attempts(self):
        times = [
            "08:00:00",
            "08:01:00",
            "08:02:00",
            "08:03:00",
            "08:04:00"
        ]

        self.add_failed_attempts(times)

        success_log = self.create_log(
            "08:05:00",
            f"Accepted password for admin from "
            f"{self.source_ip} port 50221 ssh2"
        )

        self.sentinel.analyse_line(success_log)

        report = self.sentinel.generate_report()

        self.assertEqual(report["total_alerts"], 1)
        self.assertEqual(
            report["alerts"][0]["severity"],
            "CRITICAL"
        )

    def test_below_threshold_does_not_trigger_alert(self):
        times = [
            "08:00:00",
            "08:01:00",
            "08:02:00",
            "08:03:00"
        ]

        self.add_failed_attempts(times)

        report = self.sentinel.generate_report()

        self.assertEqual(report["total_alerts"], 0)

    def test_attempts_outside_time_window(self):
        times = [
            "08:00:00",
            "08:10:00",
            "08:20:00",
            "08:30:00",
            "08:40:00"
        ]

        self.add_failed_attempts(times)

        report = self.sentinel.generate_report()

        self.assertEqual(report["total_alerts"], 0)

    def test_unmatched_log_line(self):
        self.sentinel.analyse_line(
            "This is not a valid SSH authentication log"
        )

        report = self.sentinel.generate_report()

        self.assertEqual(report["unparsed_lines"], 1)


if __name__ == "__main__":
    unittest.main()