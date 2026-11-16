
"""
SENTINEL-X Detection Engine
Time-window-based brute-force detection.

Version: 1.0.0
"""

from collections import defaultdict
from datetime import datetime, timedelta


class DetectionEngine:

    def __init__(self, threshold=5, window_minutes=5):

        if threshold < 1:
            raise ValueError("Threshold must be at least 1.")

        if window_minutes < 1:
            raise ValueError("Window must be at least 1 minute.")

        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.events = defaultdict(list)

    def add_failed_login(self, source_ip, timestamp):

        if not source_ip:
            raise ValueError("Source IP cannot be empty.")

        if not isinstance(timestamp, datetime):
            raise TypeError("Timestamp must be a datetime object.")

        self.events[source_ip].append(timestamp)

    def detect_brute_force(self):

        alerts = []

        for source_ip, timestamps in self.events.items():

            timestamps.sort()

            left = 0

            for right in range(len(timestamps)):

                while (
                    timestamps[right] - timestamps[left]
                    > self.window
                ):
                    left += 1

                attempts = right - left + 1

                if attempts >= self.threshold:

                    alert = {
                        "alert": "POSSIBLE BRUTE FORCE ATTACK",
                        "severity": "HIGH",
                        "source_ip": source_ip,
                        "failed_attempts": attempts,
                        "time_window_minutes":
                            self.window.total_seconds() / 60,
                        "technique": "T1110",
                        "framework": "MITRE ATT&CK"
                    }

                    alerts.append(alert)
                    break

        return alerts


if __name__ == "__main__":

    engine = DetectionEngine(
        threshold=5,
        window_minutes=5
    )

    sample_ip = "203.0.113.25"

    sample_times = [
        "2026-11-16 08:00:00",
        "2026-11-16 08:01:00",
        "2026-11-16 08:02:00",
        "2026-11-16 08:03:00",
        "2026-11-16 08:04:00"
    ]

    for value in sample_times:

        timestamp = datetime.strptime(
            value,
            "%Y-%m-%d %H:%M:%S"
        )

        engine.add_failed_login(
            sample_ip,
            timestamp
        )

    results = engine.detect_brute_force()

    print("\nSENTINEL-X DETECTION ENGINE")
    print("=" * 40)

    for alert in results:
        print(alert)
