from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path

from ids.models import Alert, Event, Severity
from ids.storage import JsonlWriter, RuntimeStore, load_alerts_from_jsonl, load_events_from_jsonl


class RuntimeStoreTrimTests(unittest.TestCase):
    def test_discard_oldest_events_rewrites_log(self) -> None:
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        path = root / "events-trim.jsonl"
        try:
            store = RuntimeStore(10, 10, JsonlWriter(path), JsonlWriter(None))
            for index in range(3):
                store.add_event(_event(index))

            removed = store.discard_oldest_events(2)

            self.assertEqual(removed, 2)
            self.assertEqual(store.total_events, 1)
            self.assertEqual([event.attributes["index"] for event in store.events], [2])
            self.assertEqual(
                [event.attributes["index"] for event in load_events_from_jsonl(path)],
                [2],
            )
        finally:
            path.unlink(missing_ok=True)
            try:
                root.rmdir()
            except OSError:
                pass

    def test_discard_oldest_events_preserves_history_beyond_recent_cache(self) -> None:
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        path = root / "events-history-trim.jsonl"
        try:
            store = RuntimeStore(2, 10, JsonlWriter(path), JsonlWriter(None))
            for index in range(5):
                store.add_event(_event(index))

            removed = store.discard_oldest_events(2)

            self.assertEqual(removed, 2)
            self.assertEqual(store.total_events, 3)
            self.assertEqual([event.attributes["index"] for event in store.events], [3, 4])
            self.assertEqual(
                [event.attributes["index"] for event in load_events_from_jsonl(path)],
                [2, 3, 4],
            )
        finally:
            path.unlink(missing_ok=True)
            try:
                root.rmdir()
            except OSError:
                pass

    def test_clear_alerts_rewrites_log(self) -> None:
        root = Path.cwd() / ".test_tmp"
        root.mkdir(exist_ok=True)
        path = root / "alerts-clear.jsonl"
        try:
            store = RuntimeStore(10, 10, JsonlWriter(None), JsonlWriter(path))
            store.add_alert(_alert("one"))
            store.add_alert(_alert("two"))

            removed = store.clear_alerts()

            self.assertEqual(removed, 2)
            self.assertEqual(store.total_alerts, 0)
            self.assertEqual(load_alerts_from_jsonl(path), [])
            self.assertEqual(path.read_text(encoding="utf-8"), "")
        finally:
            path.unlink(missing_ok=True)
            try:
                root.rmdir()
            except OSError:
                pass


def _event(index: int) -> Event:
    return Event(
        kind="network_connection",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source="test",
        attributes={"index": index},
    )


def _alert(rule_id: str) -> Alert:
    return Alert(
        rule_id=rule_id,
        title="Test Alert",
        severity=Severity.LOW,
        description="test",
        recommended_action="test",
        events=(_event(1),),
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


if __name__ == "__main__":
    unittest.main()
