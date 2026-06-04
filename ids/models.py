from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any
from uuid import uuid4


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return Severity(value)
        normalized = value.strip().upper()
        try:
            return Severity[normalized]
        except KeyError as exc:
            allowed = ", ".join(level.name.lower() for level in Severity)
            raise ValueError(f"Unknown severity {value!r}. Expected one of: {allowed}") from exc


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | datetime | None = None) -> datetime:
    if value is None:
        return utc_now()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class Event:
    kind: str
    timestamp: datetime = field(default_factory=utc_now)
    source: str = "unknown"
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        return cls(
            kind=str(data["kind"]),
            timestamp=parse_timestamp(data.get("timestamp")),
            source=str(data.get("source", "unknown")),
            attributes=dict(data.get("attributes", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: Severity
    description: str
    recommended_action: str
    events: tuple[Event, ...]
    timestamp: datetime = field(default_factory=utc_now)
    attributes: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid4().hex)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        return cls(
            id=str(data.get("id") or uuid4().hex),
            rule_id=str(data["rule_id"]),
            title=str(data["title"]),
            severity=Severity.parse(data["severity"]),
            description=str(data["description"]),
            recommended_action=str(data.get("recommended_action", "")),
            timestamp=parse_timestamp(data.get("timestamp")),
            attributes=dict(data.get("attributes", {})),
            events=tuple(Event.from_dict(event) for event in data.get("events", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name.lower(),
            "description": self.description,
            "recommended_action": self.recommended_action,
            "timestamp": self.timestamp.isoformat(),
            "attributes": self.attributes,
            "events": [event.to_dict() for event in self.events],
        }
