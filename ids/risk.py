from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .models import Alert, Event, Severity


SUSPICIOUS_PORTS = {21, 23, 2323, 3389, 4444, 5555, 5900, 6667, 6697, 31337}


@dataclass
class HostRisk:
    ip: str
    score: int = 0
    events: int = 0
    alerts: int = 0
    countries: Counter[str] = field(default_factory=Counter)
    ports: Counter[int] = field(default_factory=Counter)
    reasons: Counter[str] = field(default_factory=Counter)
    last_seen: datetime | None = None

    def to_row(self) -> tuple[str, int, int, int, str, str, str]:
        country = self.countries.most_common(1)[0][0] if self.countries else ""
        top_ports = ", ".join(str(port) for port, _ in self.ports.most_common(5))
        reasons = ", ".join(reason for reason, _ in self.reasons.most_common(4))
        last_seen = self.last_seen.astimezone().strftime("%Y-%m-%d %H:%M:%S") if self.last_seen else ""
        return (self.ip, self.score, self.events, self.alerts, country, top_ports, reasons or last_seen)


@dataclass(frozen=True)
class RuntimeStats:
    severity_counts: tuple[tuple[str, int], ...]
    top_countries: tuple[tuple[str, int], ...]
    top_ports: tuple[tuple[str, int], ...]
    top_ips: tuple[tuple[str, int], ...]


class RiskTracker:
    def __init__(self) -> None:
        self.hosts: dict[str, HostRisk] = {}
        self.severity_counts: Counter[str] = Counter()
        self.country_counts: Counter[str] = Counter()
        self.port_counts: Counter[str] = Counter()
        self.ip_counts: Counter[str] = Counter()

    def observe_event(self, event: Event) -> None:
        attrs = event.attributes
        remote_ip = attrs.get("remote_ip")
        if isinstance(remote_ip, str) and remote_ip:
            host = self._host(remote_ip)
            host.events += 1
            host.last_seen = event.timestamp
            self.ip_counts[remote_ip] += 1
            country = _country_label(attrs)
            if country:
                host.countries[country] += 1
                self.country_counts[country] += 1
            local_port = attrs.get("local_port")
            if isinstance(local_port, int):
                host.ports[local_port] += 1
                self.port_counts[str(local_port)] += 1
            if attrs.get("policy_status") == "blocklisted":
                host.score += 40
                host.reasons["blocklisted"] += 1
            if attrs.get("remote_proxy") or attrs.get("remote_vpn") or attrs.get("remote_tor"):
                host.score += 10
                host.reasons["proxy/vpn/tor"] += 1
            if attrs.get("remote_hosting"):
                host.score += 2
                host.reasons["hosting"] += 1
            if _uses_suspicious_port(attrs):
                host.score += 4
                host.reasons["suspicious port"] += 1
            if event.kind == "auth_failure":
                host.score += 6
                host.reasons["auth failure"] += 1
            if event.kind == "network_connection" and _looks_inbound(attrs):
                host.score += 1
                host.reasons["possible inbound"] += 1

    def observe_alert(self, alert: Alert) -> None:
        self.severity_counts[alert.severity.name] += 1
        remote_ip = alert.attributes.get("remote_ip") or alert.attributes.get("actor")
        if not isinstance(remote_ip, str) or not remote_ip:
            return
        host = self._host(remote_ip)
        host.alerts += 1
        host.last_seen = alert.timestamp
        host.reasons[alert.rule_id] += 1
        host.score += {
            Severity.INFO: 1,
            Severity.LOW: 3,
            Severity.MEDIUM: 8,
            Severity.HIGH: 20,
            Severity.CRITICAL: 40,
        }.get(alert.severity, 5)

    def top_hosts(self, limit: int = 50) -> tuple[HostRisk, ...]:
        return tuple(
            sorted(
                self.hosts.values(),
                key=lambda host: (host.score, host.alerts, host.events),
                reverse=True,
            )[:limit]
        )

    def stats(self) -> RuntimeStats:
        return RuntimeStats(
            severity_counts=tuple(self.severity_counts.most_common()),
            top_countries=tuple(self.country_counts.most_common(10)),
            top_ports=tuple(self.port_counts.most_common(10)),
            top_ips=tuple(self.ip_counts.most_common(10)),
        )

    def _host(self, ip: str) -> HostRisk:
        if ip not in self.hosts:
            self.hosts[ip] = HostRisk(ip=ip)
        return self.hosts[ip]


def _country_label(attrs: dict[str, object]) -> str:
    country = attrs.get("remote_country")
    country_code = attrs.get("remote_country_code")
    if country and country != "Unknown":
        if country_code and country_code not in {"ZZ", "UN"}:
            return f"{country} ({country_code})"
        return str(country)
    return ""


def _uses_suspicious_port(attrs: dict[str, object]) -> bool:
    return any(attrs.get(key) in SUSPICIOUS_PORTS for key in ("local_port", "remote_port"))


def _looks_inbound(attrs: dict[str, object]) -> bool:
    local_port = attrs.get("local_port")
    remote_port = attrs.get("remote_port")
    remote_ip = attrs.get("remote_ip")
    if not isinstance(local_port, int) or not isinstance(remote_port, int):
        return False
    if not isinstance(remote_ip, str) or not _is_public_ip(remote_ip):
        return False
    return local_port < 49152 and remote_port >= 49152


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False
