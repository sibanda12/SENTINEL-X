
import unittest
from sentinel import SentinelX


class TestSentinelX(unittest.TestCase):

    def setUp(self):
        self.engine = SentinelX(threshold=5)

    def test_single_failed_login(self):
        log = (
            "Nov 16 08:00:01 server sshd[1001]: "
            "Failed password for admin from "
            "203.0.113.25 port 50221 ssh2"
        )

        self.engine.analyse_line(log, 1)
        self.engine.detect_threats()

        self.assertEqual(len(self.engine.alerts), 0)

    def test_brute_force_detection(self):
        for i in range(5):
            log = (
                f"Nov 16 08:00:0{i} server sshd[100{i}]: "
                "Failed password for admin from "
                "203.0.113.25 port 50221 ssh2"
            )
            self.engine.analyse_line(log, i + 1)

        alerts = self.engine.detect_threats()

        self.assertTrue(
            any(
                alert["severity"] == "HIGH"
                for alert in alerts
            )
        )

    def test_success_after_failures(self):
        for i in range(5):
            log = (
                f"Nov 16 08:00:0{i} server sshd[100{i}]: "
                "Failed password for admin from "
                "203.0.113.25 port 50221 ssh2"
            )
            self.engine.analyse_line(log, i + 1)

        success = (
            "Nov 16 08:01:00 server sshd[2000]: "
            "Accepted password for analyst from "
            "203.0.113.25 port 50226 ssh2"
        )

        self.engine.analyse_line(success, 6)

        alerts = self.engine.detect_threats()

        self.assertTrue(
            any(
                alert["severity"] == "CRITICAL"
                for alert in alerts
            )
        )

    def test_different_ip_addresses(self):
        for i in range(5):
            log = (
                f"Nov 16 08:00:0{i} server sshd[100{i}]: "
                "Failed password for admin from "
                f"203.0.113.{i + 1} port 50221 ssh2"
            )
            self.engine.analyse_line(log, i + 1)

        alerts = self.engine.detect_threats()

        self.assertEqual(len(alerts), 0)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            SentinelX(threshold=0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
