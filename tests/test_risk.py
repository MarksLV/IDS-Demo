from __future__ import annotations

import unittest
from datetime import datetime, timezone

from ids.models import Event
from ids.risk import RiskTracker


class RiskTrackerTests(unittest.TestCase):
    def test_normal_events_do_not_make_risk_equal_event_count(self) -> None:
        tracker = RiskTracker()
        for index in range(3):
            tracker.observe_event(
                Event(
                    kind="network_connection",
                    timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    source="test",
                    attributes={
                        "remote_ip": "93.184.216.34",
                        "remote_port": 443,
                        "local_port": 50000 + index,
                    },
                )
            )

        [host] = tracker.top_hosts()

        self.assertEqual(host.events, 3)
        self.assertEqual(host.score, 0)

    def test_suspicious_port_increases_risk(self) -> None:
        tracker = RiskTracker()
        tracker.observe_event(
            Event(
                kind="network_connection",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                source="test",
                attributes={
                    "remote_ip": "93.184.216.34",
                    "remote_port": 4444,
                    "local_port": 51000,
                },
            )
        )

        [host] = tracker.top_hosts()

        self.assertGreater(host.score, 0)
        self.assertIn("suspicious port", host.reasons)


if __name__ == "__main__":
    unittest.main()
