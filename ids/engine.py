from __future__ import annotations

import time
from threading import RLock
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .collectors import Collector, build_collectors
from .config import AppConfig
from .geoip import GeoIpResolver, build_geoip_resolver
from .ip_intel import IpIntelligence, IpIntelligenceService, build_ip_intelligence_service
from .models import Alert, Event
from .policy import SecurityPolicy
from .risk import HostRisk, RiskTracker, RuntimeStats
from .rules import RuleEngine, build_rule_engine
from .storage import JsonlWriter, RuntimeStore, load_alerts_from_jsonl, load_events_from_jsonl


@dataclass(frozen=True)
class RuntimeSnapshot:
    started_at: datetime
    collectors: tuple[str, ...]
    warnings: tuple[str, ...]
    total_events: int
    total_alerts: int
    recent_events: tuple[Event, ...]
    recent_alerts: tuple[Alert, ...]
    ip_intelligence: tuple[IpIntelligence, ...]
    ip_intelligence_version: int
    risk_hosts: tuple[HostRisk, ...]
    stats: RuntimeStats


class IntrusionDetectionSystem:
    def __init__(self, config: AppConfig, load_history: bool = True) -> None:
        self.config = config
        self.started_at = datetime.now(timezone.utc)
        self.collectors: list[Collector] = build_collectors(
            config.network,
            config.process,
            config.auth,
        )
        self.rules: RuleEngine = build_rule_engine(config)
        self.policy = SecurityPolicy(config.policy)
        self.risk = RiskTracker()
        self.geoip: GeoIpResolver = build_geoip_resolver(config.geoip)
        self.ip_intelligence: IpIntelligenceService = build_ip_intelligence_service(
            config.ip_intelligence
        )
        self._lock = RLock()
        self.store = RuntimeStore(
            max_recent_events=config.output.max_recent_events,
            max_recent_alerts=config.output.max_recent_alerts,
            event_writer=JsonlWriter(config.output.events_path),
            alert_writer=JsonlWriter(config.output.alerts_path),
        )
        if load_history:
            self._load_history()

    def tick(self) -> list[Alert]:
        now = time.monotonic()
        new_alerts: list[Alert] = []
        for collector in self.collectors:
            if not collector.due(now):
                continue
            collector.mark_polled(now)
            for event in collector.poll():
                new_alerts.extend(self.process_event(event))
        return new_alerts

    def process_event(self, event: Event) -> list[Alert]:
        with self._lock:
            event = self.geoip.enrich_event(event)
            event = self.ip_intelligence.enrich_event(event)
            event = self.policy.apply(event)
            self.store.add_event(event)
            self.risk.observe_event(event)
            alerts = self.rules.evaluate(event)
            for alert in alerts:
                self.store.add_alert(alert)
                self.risk.observe_alert(alert)
            return alerts

    def replay(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.process_event(event))
        return alerts

    def snapshot(self) -> RuntimeSnapshot:
        with self._lock:
            ip_intelligence_items, ip_intelligence_version = self.ip_intelligence.snapshot()
            warnings = tuple(
                warning
                for warning in [
                    *(collector.warning for collector in self.collectors if collector.warning),
                    self.geoip.warning,
                    self.ip_intelligence.warning,
                ]
                if warning
            )
            return RuntimeSnapshot(
                started_at=self.started_at,
                collectors=tuple(collector.name for collector in self.collectors if collector.enabled),
                warnings=warnings,
                total_events=self.store.total_events,
                total_alerts=self.store.total_alerts,
                recent_events=tuple(self.store.events),
                recent_alerts=tuple(self.store.alerts),
                ip_intelligence=ip_intelligence_items,
                ip_intelligence_version=ip_intelligence_version,
                risk_hosts=self.risk.top_hosts(),
                stats=self.risk.stats(),
            )

    def discard_oldest_events(self, count: int) -> int:
        with self._lock:
            removed = self.store.discard_oldest_events(count)
            if removed:
                self._rebuild_risk()
            return removed

    def discard_oldest_alerts(self, count: int) -> int:
        with self._lock:
            removed = self.store.discard_oldest_alerts(count)
            if removed:
                self._rebuild_risk()
            return removed

    def clear_events(self) -> int:
        with self._lock:
            removed = self.store.clear_events()
            if removed:
                self._rebuild_risk()
            return removed

    def clear_alerts(self) -> int:
        with self._lock:
            removed = self.store.clear_alerts()
            if removed:
                self._rebuild_risk()
            return removed

    def reset_summary(self) -> None:
        with self._lock:
            self.risk = RiskTracker()

    def close(self) -> None:
        self.ip_intelligence.close()

    def _load_history(self) -> None:
        events = load_events_from_jsonl(self.config.output.events_path)
        alerts = load_alerts_from_jsonl(self.config.output.alerts_path)
        if not events and not alerts:
            return
        self.store.load_history(events, alerts)
        for event in events:
            self.risk.observe_event(event)
        for alert in alerts:
            self.risk.observe_alert(alert)

    def _rebuild_risk(self) -> None:
        self.risk = RiskTracker()
        for event in self._events_for_risk_rebuild():
            self.risk.observe_event(event)
        for alert in self._alerts_for_risk_rebuild():
            self.risk.observe_alert(alert)

    def _events_for_risk_rebuild(self) -> list[Event]:
        path = self.config.output.events_path
        if path is not None and path.exists():
            return load_events_from_jsonl(path)
        return list(self.store.events)

    def _alerts_for_risk_rebuild(self) -> list[Alert]:
        path = self.config.output.alerts_path
        if path is not None and path.exists():
            return load_alerts_from_jsonl(path)
        return list(self.store.alerts)


def load_events_jsonl(path: str | Path) -> list[Event]:
    events: list[Event] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                import json

                events.append(Event.from_dict(json.loads(stripped)))
            except Exception as exc:  # pragma: no cover - used by CLI.
                raise ValueError(f"Invalid event JSON on line {line_number}: {exc}") from exc
    return events
