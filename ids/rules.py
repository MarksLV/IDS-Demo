from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Deque, Iterable

from .config import AppConfig
from .models import Alert, Event, Severity


MAX_TRACKED_KEYS = 10000


class Rule:
    rule_id = "rule"
    title = "Rule"
    severity = Severity.LOW

    def evaluate(self, event: Event) -> list[Alert]:
        raise NotImplementedError


class CooldownMixin:
    def __init__(self, cooldown_seconds: int, max_keys: int = MAX_TRACKED_KEYS) -> None:
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.max_keys = max_keys
        self._last_alert_at: dict[str, datetime] = {}

    def should_alert(self, key: str, timestamp: datetime) -> bool:
        self._prune_cooldowns(timestamp)
        previous = self._last_alert_at.get(key)
        if previous is not None and timestamp - previous < self.cooldown:
            return False
        self._last_alert_at[key] = timestamp
        return True

    def _prune_cooldowns(self, now: datetime) -> None:
        if len(self._last_alert_at) <= self.max_keys:
            return
        cutoff = now - self.cooldown
        for key, timestamp in tuple(self._last_alert_at.items()):
            if timestamp < cutoff:
                del self._last_alert_at[key]
        if len(self._last_alert_at) <= self.max_keys:
            return
        oldest = sorted(self._last_alert_at.items(), key=lambda item: item[1])
        for key, _ in oldest[: len(self._last_alert_at) - self.max_keys]:
            self._last_alert_at.pop(key, None)


class SuspiciousPortRule(Rule, CooldownMixin):
    rule_id = "suspicious_port"
    title = "Suspicious Network Port"
    severity = Severity.MEDIUM

    def __init__(self, ports: Iterable[int], cooldown_seconds: int) -> None:
        CooldownMixin.__init__(self, cooldown_seconds)
        self.ports = frozenset(ports)

    def evaluate(self, event: Event) -> list[Alert]:
        if event.kind != "network_connection":
            return []
        local_port = event.attributes.get("local_port")
        remote_port = event.attributes.get("remote_port")
        matched_port = local_port if local_port in self.ports else remote_port
        if matched_port not in self.ports:
            return []

        remote_ip = str(event.attributes.get("remote_ip") or "unknown")
        remote_label = format_remote_origin(event)
        key = f"{remote_ip}:{matched_port}"
        if not self.should_alert(key, event.timestamp):
            return []
        return [
            Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    f"Network activity used suspicious port {matched_port} with "
                    f"remote host {remote_label}."
                ),
                recommended_action=(
                    "Confirm whether the service or remote host is expected. If not, "
                    "block the source and inspect the owning process."
                ),
                events=(event,),
                timestamp=event.timestamp,
                attributes={
                    "port": matched_port,
                    "remote_ip": remote_ip,
                    "remote_country": event.attributes.get("remote_country"),
                    "remote_country_code": event.attributes.get("remote_country_code"),
                    "pid": event.attributes.get("pid"),
                    "process_name": event.attributes.get("process_name"),
                },
            )
        ]


class BlocklistRule(Rule, CooldownMixin):
    rule_id = "blocklist_match"
    title = "Blocklist Match"
    severity = Severity.CRITICAL

    def __init__(self, cooldown_seconds: int) -> None:
        CooldownMixin.__init__(self, cooldown_seconds)

    def evaluate(self, event: Event) -> list[Alert]:
        if event.attributes.get("policy_status") != "blocklisted":
            return []
        remote_ip = str(event.attributes.get("remote_ip") or event.attributes.get("image_name") or "unknown")
        if not self.should_alert(remote_ip, event.timestamp):
            return []
        return [
            Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=f"Blocklist policy matched: {event.attributes.get('policy_reason')}.",
                recommended_action=(
                    "Treat this as high priority. Review the event, block the source if applicable, "
                    "and check related activity around the same timestamp."
                ),
                events=(event,),
                timestamp=event.timestamp,
                attributes={
                    "remote_ip": event.attributes.get("remote_ip"),
                    "remote_country": event.attributes.get("remote_country"),
                    "remote_country_code": event.attributes.get("remote_country_code"),
                    "policy_reason": event.attributes.get("policy_reason"),
                    "image_name": event.attributes.get("image_name"),
                    "pid": event.attributes.get("pid"),
                    "process_name": event.attributes.get("process_name"),
                },
            )
        ]


class PortScanRule(Rule, CooldownMixin):
    rule_id = "port_scan"
    title = "Possible Port Scan"
    severity = Severity.HIGH

    def __init__(self, window_seconds: int, unique_ports: int, cooldown_seconds: int) -> None:
        CooldownMixin.__init__(self, cooldown_seconds)
        self.window = timedelta(seconds=window_seconds)
        self.unique_ports = unique_ports
        self._by_remote: dict[str, Deque[Event]] = defaultdict(deque)

    def evaluate(self, event: Event) -> list[Alert]:
        if event.kind != "network_connection":
            return []
        remote_ip = str(event.attributes.get("remote_ip") or "")
        local_port = event.attributes.get("local_port")
        if not remote_ip or remote_ip in {"0.0.0.0", "::", "*"} or local_port is None:
            return []

        bucket = self._by_remote[remote_ip]
        bucket.append(event)
        self._expire(bucket, event.timestamp)
        _prune_event_buckets(self._by_remote, event.timestamp, self.window)
        ports = {item.attributes.get("local_port") for item in bucket}
        if len(ports) < self.unique_ports:
            return []
        if not self.should_alert(remote_ip, event.timestamp):
            return []
        remote_label = format_remote_origin(event)
        return [
            Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    f"{remote_label} touched {len(ports)} distinct local ports within "
                    f"{int(self.window.total_seconds())} seconds."
                ),
                recommended_action=(
                    "Review firewall logs for the source, block it if unauthorized, "
                    "and check exposed services for unexpected listeners."
                ),
                events=tuple(bucket),
                timestamp=event.timestamp,
                attributes={
                    "remote_ip": remote_ip,
                    "remote_country": event.attributes.get("remote_country"),
                    "remote_country_code": event.attributes.get("remote_country_code"),
                    "unique_ports": sorted(ports),
                    "processes": _process_labels(bucket),
                },
            )
        ]

    def _expire(self, bucket: Deque[Event], now: datetime) -> None:
        while bucket and now - bucket[0].timestamp > self.window:
            bucket.popleft()


class ConnectionBurstRule(Rule, CooldownMixin):
    rule_id = "connection_burst"
    title = "Connection Burst"
    severity = Severity.MEDIUM

    def __init__(self, window_seconds: int, threshold: int, cooldown_seconds: int) -> None:
        CooldownMixin.__init__(self, cooldown_seconds)
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._by_remote: dict[str, Deque[Event]] = defaultdict(deque)

    def evaluate(self, event: Event) -> list[Alert]:
        if event.kind != "network_connection":
            return []
        remote_ip = str(event.attributes.get("remote_ip") or "")
        if not remote_ip or remote_ip in {"0.0.0.0", "::", "*"}:
            return []
        bucket = self._by_remote[remote_ip]
        bucket.append(event)
        while bucket and event.timestamp - bucket[0].timestamp > self.window:
            bucket.popleft()
        _prune_event_buckets(self._by_remote, event.timestamp, self.window)
        if len(bucket) < self.threshold:
            return []
        if not self.should_alert(remote_ip, event.timestamp):
            return []
        remote_label = format_remote_origin(event)
        return [
            Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    f"{remote_label} opened {len(bucket)} new connections within "
                    f"{int(self.window.total_seconds())} seconds."
                ),
                recommended_action=(
                    "Check whether this is expected load. If not, rate-limit or block "
                    "the source and inspect the affected service."
                ),
                events=tuple(bucket),
                timestamp=event.timestamp,
                attributes={
                    "remote_ip": remote_ip,
                    "remote_country": event.attributes.get("remote_country"),
                    "remote_country_code": event.attributes.get("remote_country_code"),
                    "connections": len(bucket),
                    "processes": _process_labels(bucket),
                },
            )
        ]


class BruteForceRule(Rule, CooldownMixin):
    rule_id = "brute_force"
    title = "Possible Brute Force"
    severity = Severity.HIGH

    def __init__(
        self,
        window_seconds: int,
        threshold: int,
        cooldown_seconds: int,
        failure_patterns: Iterable[str],
    ) -> None:
        CooldownMixin.__init__(self, cooldown_seconds)
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        pattern = "|".join(re.escape(item) for item in failure_patterns)
        self.failure_regex = re.compile(pattern, re.IGNORECASE) if pattern else None
        self._by_actor: dict[str, Deque[Event]] = defaultdict(deque)

    def evaluate(self, event: Event) -> list[Alert]:
        normalized = self._normalize_event(event)
        if normalized is None:
            return []
        actor, normalized_event = normalized
        bucket = self._by_actor[actor]
        bucket.append(normalized_event)
        while bucket and normalized_event.timestamp - bucket[0].timestamp > self.window:
            bucket.popleft()
        _prune_event_buckets(self._by_actor, normalized_event.timestamp, self.window)
        if len(bucket) < self.threshold:
            return []
        if not self.should_alert(actor, normalized_event.timestamp):
            return []
        actor_label = (
            format_remote_origin(normalized_event)
            if normalized_event.attributes.get("remote_ip")
            else actor
        )
        return [
            Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    f"{actor_label} caused {len(bucket)} failed authentication events within "
                    f"{int(self.window.total_seconds())} seconds."
                ),
                recommended_action=(
                    "Lock or rate-limit the targeted account, block the source if known, "
                    "and inspect successful logins around the same time."
                ),
                events=tuple(bucket),
                timestamp=normalized_event.timestamp,
                attributes={
                    "actor": actor,
                    "remote_ip": normalized_event.attributes.get("remote_ip"),
                    "remote_country": normalized_event.attributes.get("remote_country"),
                    "remote_country_code": normalized_event.attributes.get("remote_country_code"),
                    "failures": len(bucket),
                },
            )
        ]

    def _normalize_event(self, event: Event) -> tuple[str, Event] | None:
        if event.kind == "auth_failure":
            remote_ip = event.attributes.get("remote_ip")
            username = event.attributes.get("username")
            actor = str(remote_ip or username or "unknown")
            return actor, event
        if event.kind != "log_line" or self.failure_regex is None:
            return None
        line = str(event.attributes.get("line") or "")
        if not self.failure_regex.search(line):
            return None
        remote_ip = _extract_ip(line)
        username = _extract_username(line)
        actor = remote_ip or username or "unknown-log-actor"
        normalized = Event(
            kind="auth_failure",
            timestamp=event.timestamp,
            source=event.source,
            attributes={**event.attributes, "remote_ip": remote_ip, "username": username},
        )
        return actor, normalized


class SuspiciousProcessRule(Rule, CooldownMixin):
    rule_id = "suspicious_process"
    title = "Suspicious Process"
    severity = Severity.HIGH

    def __init__(self, process_names: Iterable[str], cooldown_seconds: int) -> None:
        CooldownMixin.__init__(self, cooldown_seconds)
        self.process_names = frozenset(name.lower() for name in process_names)

    def evaluate(self, event: Event) -> list[Alert]:
        if event.kind != "process_start":
            return []
        image_name = str(event.attributes.get("image_name") or "").lower()
        if image_name not in self.process_names:
            return []
        key = f"{image_name}:{event.attributes.get('pid')}"
        if not self.should_alert(key, event.timestamp):
            return []
        return [
            Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=f"Suspicious process started: {image_name}.",
                recommended_action=(
                    "Verify the file path and user context, terminate it if unauthorized, "
                    "and collect the binary for analysis."
                ),
                events=(event,),
                timestamp=event.timestamp,
                attributes={
                    "image_name": image_name,
                    "pid": event.attributes.get("pid"),
                    "path": event.attributes.get("path"),
                    "command_line": event.attributes.get("command_line"),
                    "user": event.attributes.get("user"),
                    "parent_pid": event.attributes.get("parent_pid"),
                    "sha256": event.attributes.get("sha256"),
                },
            )
        ]


class ProcessBurstRule(Rule, CooldownMixin):
    rule_id = "process_burst"
    title = "Process Burst"
    severity = Severity.MEDIUM

    def __init__(self, window_seconds: int, threshold: int, cooldown_seconds: int) -> None:
        CooldownMixin.__init__(self, cooldown_seconds)
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._events: Deque[Event] = deque()

    def evaluate(self, event: Event) -> list[Alert]:
        if event.kind != "process_start":
            return []
        self._events.append(event)
        while self._events and event.timestamp - self._events[0].timestamp > self.window:
            self._events.popleft()
        if len(self._events) < self.threshold:
            return []
        if not self.should_alert("global", event.timestamp):
            return []
        return [
            Alert(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=(
                    f"{len(self._events)} new processes started within "
                    f"{int(self.window.total_seconds())} seconds."
                ),
                recommended_action=(
                    "Check whether a script, installer, or suspicious payload caused the "
                    "process spike."
                ),
                events=tuple(self._events),
                timestamp=event.timestamp,
                attributes={"processes": len(self._events)},
            )
        ]


class RuleEngine:
    def __init__(self, rules: Iterable[Rule], min_severity: Severity = Severity.LOW) -> None:
        self.rules = list(rules)
        self.min_severity = min_severity

    def evaluate(self, event: Event) -> list[Alert]:
        if event.attributes.get("policy_status") == "allowlisted":
            return []
        alerts: list[Alert] = []
        for rule in self.rules:
            for alert in rule.evaluate(event):
                if alert.severity >= self.min_severity:
                    alerts.append(alert)
        return alerts


def build_rule_engine(config: AppConfig) -> RuleEngine:
    detection = config.detection
    rules: list[Rule] = [
        BlocklistRule(detection.alert_cooldown_seconds),
        SuspiciousPortRule(detection.suspicious_ports, detection.alert_cooldown_seconds),
        PortScanRule(
            detection.port_scan_window_seconds,
            detection.port_scan_unique_ports,
            detection.alert_cooldown_seconds,
        ),
        ConnectionBurstRule(
            detection.connection_burst_window_seconds,
            detection.connection_burst_threshold,
            detection.alert_cooldown_seconds,
        ),
        BruteForceRule(
            detection.brute_force_window_seconds,
            detection.brute_force_threshold,
            detection.alert_cooldown_seconds,
            config.auth.log_failure_patterns,
        ),
        SuspiciousProcessRule(
            config.process.suspicious_process_names,
            detection.alert_cooldown_seconds,
        ),
        ProcessBurstRule(
            detection.process_burst_window_seconds,
            detection.process_burst_threshold,
            detection.alert_cooldown_seconds,
        ),
    ]
    return RuleEngine(rules, config.output.min_alert_severity)


def _prune_event_buckets(
    buckets: dict[str, Deque[Event]],
    now: datetime,
    window: timedelta,
    max_buckets: int = MAX_TRACKED_KEYS,
) -> None:
    for key, bucket in tuple(buckets.items()):
        while bucket and now - bucket[0].timestamp > window:
            bucket.popleft()
        if not bucket:
            del buckets[key]
    if len(buckets) <= max_buckets:
        return
    oldest = sorted(
        buckets.items(),
        key=lambda item: item[1][-1].timestamp if item[1] else datetime.min,
    )
    for key, _ in oldest[: len(buckets) - max_buckets]:
        buckets.pop(key, None)


def _extract_ip(line: str) -> str | None:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
    return match.group(0) if match else None


def _extract_username(line: str) -> str | None:
    patterns = [
        r"invalid user\s+([^\s]+)",
        r"for\s+([^\s]+)\s+from",
        r"user[ =:]([^\s]+)",
        r"account name:\s*([^\s]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def _process_labels(events: Iterable[Event]) -> list[str]:
    labels: set[str] = set()
    for event in events:
        process_name = event.attributes.get("process_name") or event.attributes.get("image_name")
        pid = event.attributes.get("pid")
        if process_name and pid is not None:
            labels.add(f"{process_name} ({pid})")
        elif process_name:
            labels.add(str(process_name))
        elif pid is not None:
            labels.add(f"PID {pid}")
    return sorted(labels)


def format_remote_origin(event: Event) -> str:
    remote_ip = str(event.attributes.get("remote_ip") or "unknown")
    country = event.attributes.get("remote_country")
    country_code = event.attributes.get("remote_country_code")
    if not country or country == "Unknown":
        return remote_ip
    if country_code and country_code not in {"ZZ", "UN"}:
        return f"{remote_ip} ({country}, {country_code})"
    return f"{remote_ip} ({country})"
