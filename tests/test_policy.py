from __future__ import annotations

import unittest

from ids.config import PolicyConfig
from ids.models import Event
from ids.policy import SecurityPolicy


class PolicyTests(unittest.TestCase):
    def test_network_process_name_can_match_process_blocklist(self) -> None:
        policy = SecurityPolicy(
            PolicyConfig(
                allowlist_ips=(),
                blocklist_ips=(),
                allowlist_countries=(),
                blocklist_countries=(),
                allowlist_process_names=(),
                blocklist_process_names=("powershell.exe",),
            )
        )
        event = Event(
            kind="network_connection",
            source="test",
            attributes={"process_name": "PowerShell.exe", "pid": 123},
        )

        decision = policy.evaluate(event)

        self.assertEqual(decision.status, "blocklisted")
        self.assertIn("powershell.exe", decision.reason)


if __name__ == "__main__":
    unittest.main()
