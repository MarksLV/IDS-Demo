from __future__ import annotations

import unittest
from datetime import datetime, timezone

from ids.models import Event
from ids.rules import MAX_TRACKED_KEYS, ConnectionBurstRule


class RuleStateTests(unittest.TestCase):
    def test_connection_burst_buckets_are_bounded(self) -> None:
        rule = ConnectionBurstRule(
            window_seconds=60,
            threshold=MAX_TRACKED_KEYS + 10,
            cooldown_seconds=1,
        )
        timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)

        for index in range(MAX_TRACKED_KEYS + 5):
            rule.evaluate(
                Event(
                    kind="network_connection",
                    timestamp=timestamp,
                    source="test",
                    attributes={
                        "remote_ip": f"host-{index}",
                        "local_port": 443,
                    },
                )
            )

        self.assertLessEqual(len(rule._by_remote), MAX_TRACKED_KEYS)


if __name__ == "__main__":
    unittest.main()
