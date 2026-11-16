
"""
SENTINEL-X
Security Monitoring and Threat Detection System

Version: 1.0.0
"""

import re
import json
import argparse

from datetime import datetime
from collections import defaultdict
from pathlib import Path

from detection_engine import DetectionEngine


class SentinelX:

    def __init__(self, threshold=5, window_minutes=5):

        self.engine = DetectionEngine(
            threshold=threshold,
            window_minutes=window_minutes
        )

        self.failed_attempts = defaultdict(int)
        self.successful_logins = []
        self.analysed_lines = 0
        self.unparsed_lines = 0

        self.log_pattern = re.compile(
            r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+"
            r"\d{2}:\d{2}:\d{2})\s+"
            r"\S+\s+sshd\[\d+\]:\s+(?P<event>.*)$"
        )

        self.failed_pattern = re.compile(
            r"Failed password for "
            r"(?:invalid user )?(?P<user>\S+) "
            r"from (?P<ip>\S+) port"
        )

        self.success_pattern = re.compile(
            r"Accepted (?:password|publickey) for "
            r"(?P<user>\S+) from (?P<ip>\S+) port"
        )

    def parse_timestamp(self, value):

        current_year = datetime.now().year

        timestamp = datetime.strptime(
            f"{current_year} {value}",
            "%Y %b %d %H:%M:%S"
        )

        return timestamp

    def analyse_line(self, line):

        self.analysed_lines += 1

        match = self.log_pattern.search(line)

        if not match:
            self.unparsed_lines += 1
            return

        try:
            timestamp = self.parse_timestamp(
                match.group("timestamp")
            )
        except ValueError:
            self.unparsed_lines += 1
            return

        event = match.group("event")

        failed = self.failed_pattern.search(event)

        if failed:

            ip = failed.group("ip")
            user = failed.group("user")

            self.failed_attempts[ip] += 1

            self.engine.add_failed_login(
                ip,
                timestamp
            )

            return

        successful = self.success_pattern.search(event)

        if successful:

            self.successful_logins.append({
                "source_ip": successful.group("ip"),
                "username": successful.group("user"),
                "timestamp": timestamp
            })

    def detect_threats(self):

        alerts = self.engine.detect_brute_force()

        for alert in alerts:

            source_ip = alert["source_ip"]

            matching_logins = [
                login for login in self.successful_logins
                if login["source_ip"] == source_ip
            ]

            if matching_logins:

                alert["successful_login_after_failures"] = True
                alert["severity"] = "CRITICAL"

                alert["successful_accounts"] = [
                    login["username"]
                    for login in matching_logins
                ]

            else:
                alert["successful_login_after_failures"] = False

        return alerts

    def generate_report(self):

        alerts = self.detect_threats()

        return {
            "project": "SENTINEL-X",
            "version": "1.0.0",
            "analysed_lines": self.analysed_lines,
            "unparsed_lines": self.unparsed_lines,
            "unique_source_ips": len(self.failed_attempts),
            "total_failed_attempts": sum(
                self.failed_attempts.values()
            ),
            "total_alerts": len(alerts),
            "alerts": alerts
        }


def main():

    parser = argparse.ArgumentParser(
        description="SENTINEL-X Security Monitoring System"
    )

    parser.add_argument(
        "logfile",
        help="Path to Linux SSH authentication log"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Detection window in minutes"
    )

    parser.add_argument(
        "--output",
        default="",
        help="Optional JSON report output path"
    )

    args = parser.parse_args()

    try:

        sentinel = SentinelX(
            threshold=args.threshold,
            window_minutes=args.window
        )

        with open(
            args.logfile,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as log_file:

            for line in log_file:
                sentinel.analyse_line(line)

        report = sentinel.generate_report()

        print("\n====================================")
        print("       SENTINEL-X SECURITY ENGINE")
        print("====================================")

        print("Lines analysed:", report["analysed_lines"])
        print("Unparsed lines:", report["unparsed_lines"])
        print("Failed attempts:", report["total_failed_attempts"])
        print("Alerts generated:", report["total_alerts"])

        print("\n--- SECURITY ALERTS ---")

        if report["alerts"]:

            for alert in report["alerts"]:
                print(json.dumps(alert, indent=4))

        else:
            print("No suspicious activity detected.")

        if args.output:

            Path(args.output).write_text(
                json.dumps(report, indent=4, default=str),
                encoding="utf-8"
            )

            print("\nReport saved:", args.output)

    except FileNotFoundError:
        parser.error("Log file not found.")

    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
