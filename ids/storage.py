from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Deque

from .models import Alert, Event


class JsonlWriter:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, item: Event | Alert) -> None:
        if self.path is None:
            return
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item.to_dict(), sort_keys=True) + "\n")

    def rewrite(self, items: list[Event] | list[Alert]) -> None:
        if self.path is None:
            return
        with self.path.open("w", encoding="utf-8") as handle:
            for item in items:
                handle.write(json.dumps(item.to_dict(), sort_keys=True) + "\n")


class RuntimeStore:
    def __init__(
        self,
        max_recent_events: int,
        max_recent_alerts: int,
        event_writer: JsonlWriter,
        alert_writer: JsonlWriter,
    ) -> None:
        self.events: Deque[Event] = deque(maxlen=max_recent_events)
        self.alerts: Deque[Alert] = deque(maxlen=max_recent_alerts)
        self.event_writer = event_writer
        self.alert_writer = alert_writer
        self.total_events = 0
        self.total_alerts = 0

    def load_history(self, events: list[Event], alerts: list[Alert]) -> None:
        for event in events:
            self.events.append(event)
        for alert in alerts:
            self.alerts.append(alert)
        self.total_events = len(events)
        self.total_alerts = len(alerts)

    def add_event(self, event: Event) -> None:
        self.events.append(event)
        self.total_events += 1
        self.event_writer.write(event)

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        self.total_alerts += 1
        self.alert_writer.write(alert)

    def discard_oldest_events(self, count: int) -> int:
        count = max(0, count)
        if count == 0:
            return 0
        if self.event_writer.path is not None and self.event_writer.path.exists():
            events = load_events_from_jsonl(self.event_writer.path)
            removed = min(count, len(events))
            remaining = events[removed:]
            self.events.clear()
            self.events.extend(remaining)
            self.total_events = len(remaining)
            self.event_writer.rewrite(remaining)
            return removed

        removed = min(count, self.total_events)
        hidden_events = max(0, self.total_events - len(self.events))
        visible_removed = max(0, removed - hidden_events)
        for _ in range(min(visible_removed, len(self.events))):
            self.events.popleft()
        self.total_events = max(0, self.total_events - removed)
        return removed

    def discard_oldest_alerts(self, count: int) -> int:
        count = max(0, count)
        if count == 0:
            return 0
        if self.alert_writer.path is not None and self.alert_writer.path.exists():
            alerts = load_alerts_from_jsonl(self.alert_writer.path)
            removed = min(count, len(alerts))
            remaining = alerts[removed:]
            self.alerts.clear()
            self.alerts.extend(remaining)
            self.total_alerts = len(remaining)
            self.alert_writer.rewrite(remaining)
            return removed

        removed = min(count, self.total_alerts)
        hidden_alerts = max(0, self.total_alerts - len(self.alerts))
        visible_removed = max(0, removed - hidden_alerts)
        for _ in range(min(visible_removed, len(self.alerts))):
            self.alerts.popleft()
        self.total_alerts = max(0, self.total_alerts - removed)
        return removed

    def clear_events(self) -> int:
        removed = self.total_events
        self.events.clear()
        self.total_events = 0
        self.event_writer.rewrite([])
        return removed

    def clear_alerts(self) -> int:
        removed = self.total_alerts
        self.alerts.clear()
        self.total_alerts = 0
        self.alert_writer.rewrite([])
        return removed


def load_events_from_jsonl(path: Path | None) -> list[Event]:
    if path is None or not path.exists():
        return []
    events: list[Event] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                events.append(Event.from_dict(json.loads(stripped)))
    return events


def load_alerts_from_jsonl(path: Path | None) -> list[Alert]:
    if path is None or not path.exists():
        return []
    alerts: list[Alert] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                alerts.append(Alert.from_dict(json.loads(stripped)))
    return alerts
