from __future__ import annotations

import hashlib
import json
from datetime import datetime

from .ip_intel import IpIntelligence
from .models import Alert, Event


def alert_row(
    alert: Alert,
    ip_info_by_ip: dict[str, IpIntelligence] | None = None,
) -> tuple[str, str, str, str, str, str]:
    return (
        format_timestamp(alert.timestamp),
        alert.severity.name,
        alert_origin(alert, ip_info_by_ip),
        alert.rule_id,
        alert.title,
        alert.description,
    )


def event_row(
    event: Event,
    ip_info_by_ip: dict[str, IpIntelligence] | None = None,
) -> tuple[str, str, str, str, str, str, str, str]:
    attrs = event.attributes
    remote = str(attrs.get("remote_ip") or "")
    info = ip_info_by_ip.get(remote) if ip_info_by_ip else None
    country = country_label(attrs, "remote")
    if info is not None and info.country:
        country = country_label_from_info(info)
    local = local_label(event)
    return (
        format_timestamp(event.timestamp),
        event.kind,
        remote,
        country,
        local,
        process_label(event),
        event.source,
        event_detail(event, info),
    )


def event_signature(event: Event) -> str:
    payload = json.dumps(event.to_dict(), sort_keys=True, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def event_item_id(event: Event, occurrence: int) -> str:
    return f"event-{event_signature(event)}-{occurrence}"


def alert_origin(
    alert: Alert,
    ip_info_by_ip: dict[str, IpIntelligence] | None = None,
) -> str:
    attrs = alert.attributes
    remote_ip = attrs.get("remote_ip") or attrs.get("actor")
    if remote_ip:
        if ip_info_by_ip:
            info = ip_info_by_ip.get(str(remote_ip))
            if info is not None and info.country:
                return f"{remote_ip} - {country_label_from_info(info)}"
        return with_country(str(remote_ip), attrs, "remote")
    return "unknown"


def local_label(event: Event) -> str:
    attrs = event.attributes
    local_ip = attrs.get("local_ip")
    local_port = attrs.get("local_port")
    if local_ip and local_port:
        return f"{local_ip}:{local_port}"
    if local_ip:
        return str(local_ip)
    return ""


def process_label(event: Event) -> str:
    attrs = event.attributes
    process_name = attrs.get("process_name") or attrs.get("image_name")
    pid = _as_pid(attrs.get("pid"))
    if process_name and pid is not None:
        return f"{process_name} ({pid})"
    if process_name:
        return str(process_name)
    if pid is not None:
        return f"PID {pid}"
    return ""


def event_detail(event: Event, info: IpIntelligence | None = None) -> str:
    attrs = event.attributes
    if event.kind == "network_connection":
        parts = [
            str(attrs.get("protocol") or ""),
            str(attrs.get("state") or ""),
        ]
        process_name = attrs.get("process_name")
        if process_name:
            parts.append(f"app={process_name}")
        pid = _as_pid(attrs.get("pid"))
        if pid is not None:
            parts.append(f"pid={pid}")
        detail = " ".join(part for part in parts if part)
        if info is not None and info.status == "success":
            intel = " ".join(
                part for part in [info.isp, info.organization, info.asn] if part
            )
            if intel:
                detail = f"{detail} | {intel}"
        return detail
    if event.kind == "process_start":
        parts = [
            str(attrs.get("image_name")),
            f"pid={attrs.get('pid')}",
            f"user={attrs.get('user')}" if attrs.get("user") else "",
            f"parent={attrs.get('parent_pid')}" if attrs.get("parent_pid") else "",
            str(attrs.get("path") or ""),
        ]
        return " ".join(part for part in parts if part)
    if event.kind == "auth_failure":
        return f"user={attrs.get('username')} reason={attrs.get('reason', '')}"
    if event.kind == "log_line":
        return str(attrs.get("line") or "")[:240]
    return str(attrs)[:240]


def country_label(attrs: dict[str, object], prefix: str) -> str:
    country = attrs.get(f"{prefix}_country")
    country_code = attrs.get(f"{prefix}_country_code")
    if country and country != "Unknown":
        if country_code and country_code not in {"ZZ", "UN"}:
            return f"{country} ({country_code})"
        return str(country)
    return ""


def with_country(ip: str, attrs: dict[str, object], prefix: str) -> str:
    country = country_label(attrs, prefix)
    if country:
        return f"{ip} - {country}"
    return ip


def country_label_from_info(info: IpIntelligence) -> str:
    if info.country and info.country_code:
        return f"{info.country} ({info.country_code})"
    return info.country or ""


def ip_info_lines(info: IpIntelligence) -> list[str]:
    lines = [
        f"IP: {info.ip}",
        f"Status: {info.status}",
        f"Provider: {info.provider}",
    ]
    if info.message:
        lines.append(f"Message: {info.message}")
    if info.status == "success":
        lines.extend(
            [
                f"Location: {info.location_label or 'unknown'}",
                f"Coordinates: {format_optional(info.latitude)}, {format_optional(info.longitude)}",
                f"Timezone: {info.timezone_id or 'unknown'}",
                f"Type: {info.ip_type or 'unknown'}",
                f"Network: {info.network_label or 'unknown'}",
                f"Domain: {info.domain or 'unknown'}",
                f"Proxy/VPN/Tor/Hosting: {format_flag(info.proxy)} / {format_flag(info.vpn)} / {format_flag(info.tor)} / {format_flag(info.hosting)}",
            ]
        )
    return lines


def detail_lines(values: dict[str, object]) -> list[str]:
    lines = []
    for key, value in sorted(values.items()):
        if value is None or value == "":
            continue
        lines.append(f"{key}: {value}")
    return lines or ["No captured fields."]


def as_pid(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def format_optional(value: object) -> str:
    if value is None:
        return "unknown"
    return str(value)


def format_flag(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def format_timestamp(timestamp: datetime) -> str:
    return timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds: int) -> str:
    hours, remainder = divmod(max(0, seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


_as_pid = as_pid
_detail_lines = detail_lines
