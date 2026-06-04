from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import Severity


DEFAULT_CONFIG: dict[str, Any] = {
    "network": {
        "enabled": True,
        "poll_interval_seconds": 2.0,
        "baseline_existing_on_start": True,
        "max_seen_connections": 10000,
    },
    "process": {
        "enabled": True,
        "poll_interval_seconds": 5.0,
        "baseline_existing_on_start": True,
        "max_seen_processes": 5000,
        "detail_lookup_enabled": False,
        "detail_lookup_timeout_seconds": 2.5,
        "suspicious_process_names": [
            "mimikatz.exe",
            "nmap.exe",
            "masscan.exe",
            "netcat.exe",
            "nc.exe",
            "psexec.exe",
            "procdump.exe",
            "pwdump.exe",
            "secretsdump.py",
            "hashcat.exe",
            "hydra.exe",
        ],
    },
    "auth": {
        "windows_event_log_enabled": False,
        "windows_event_log_interval_seconds": 20.0,
        "windows_event_log_max_events": 40,
        "baseline_existing_on_start": True,
        "log_files": [],
        "log_poll_interval_seconds": 2.0,
        "log_failure_patterns": [
            "failed password",
            "authentication failure",
            "invalid user",
            "login failed",
            "failed login",
            "4625",
        ],
    },
    "geoip": {
        "enabled": True,
        "database_path": "data/geoip_country_ranges.csv",
        "cache_size": 20000,
        "unknown_country_code": "ZZ",
        "unknown_country_name": "Unknown",
    },
    "ip_intelligence": {
        "enabled": False,
        "provider": "ipwho.is",
        "url_template": "https://ipwho.is/{ip}",
        "timeout_seconds": 2.5,
        "cache_size": 5000,
        "queue_size": 1000,
        "min_request_interval_seconds": 1.1,
    },
    "llm": {
        "enabled": False,
        "provider": "lm_studio",
        "url": "http://127.0.0.1:1234/api/v1/chat",
        "model": "deepseek-r1-0528-qwen3-8b",
        "api_token": "",
        "timeout_seconds": 180.0,
        "max_tokens": 700,
        "temperature": 0.2,
    },
    "policy": {
        "allowlist_ips": [],
        "blocklist_ips": [],
        "allowlist_countries": [],
        "blocklist_countries": [],
        "allowlist_process_names": [],
        "blocklist_process_names": [],
    },
    "detection": {
        "suspicious_ports": [21, 23, 2323, 3389, 4444, 5555, 5900, 6667, 6697, 31337],
        "port_scan_window_seconds": 60,
        "port_scan_unique_ports": 8,
        "connection_burst_window_seconds": 30,
        "connection_burst_threshold": 25,
        "brute_force_window_seconds": 300,
        "brute_force_threshold": 5,
        "process_burst_window_seconds": 30,
        "process_burst_threshold": 18,
        "alert_cooldown_seconds": 120,
    },
    "output": {
        "events_path": "logs/events.jsonl",
        "alerts_path": "logs/alerts.jsonl",
        "max_recent_events": 500,
        "max_recent_alerts": 100,
        "min_alert_severity": "low",
    },
    "dashboard": {
        "enabled": True,
        "refresh_seconds": 1.0,
    },
    "ui": {
        "theme": "light",
    },
}


def _deep_update(
    base: dict[str, Any],
    override: dict[str, Any],
    path: tuple[str, ...] = (),
) -> dict[str, Any]:
    if not isinstance(override, dict):
        dotted = ".".join(path) or "configuration"
        raise ValueError(f"{dotted} must be a JSON object")
    for key, value in override.items():
        if not path and key == "notifications":
            continue
        if key not in base:
            dotted = ".".join((*path, str(key)))
            raise ValueError(f"Unknown configuration key: {dotted}")
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value, (*path, str(key)))
        else:
            base[key] = value
    return base


@dataclass(frozen=True)
class NetworkConfig:
    enabled: bool
    poll_interval_seconds: float
    baseline_existing_on_start: bool
    max_seen_connections: int


@dataclass(frozen=True)
class ProcessConfig:
    enabled: bool
    poll_interval_seconds: float
    baseline_existing_on_start: bool
    max_seen_processes: int
    detail_lookup_enabled: bool
    detail_lookup_timeout_seconds: float
    suspicious_process_names: tuple[str, ...]


@dataclass(frozen=True)
class AuthConfig:
    windows_event_log_enabled: bool
    windows_event_log_interval_seconds: float
    windows_event_log_max_events: int
    baseline_existing_on_start: bool
    log_files: tuple[str, ...]
    log_poll_interval_seconds: float
    log_failure_patterns: tuple[str, ...]


@dataclass(frozen=True)
class GeoIpConfig:
    enabled: bool
    database_path: Path | None
    cache_size: int
    unknown_country_code: str
    unknown_country_name: str


@dataclass(frozen=True)
class IpIntelligenceConfig:
    enabled: bool
    provider: str
    url_template: str
    timeout_seconds: float
    cache_size: int
    queue_size: int
    min_request_interval_seconds: float


@dataclass(frozen=True)
class LlmConfig:
    enabled: bool
    provider: str
    url: str
    model: str
    api_token: str
    timeout_seconds: float
    max_tokens: int
    temperature: float


@dataclass(frozen=True)
class PolicyConfig:
    allowlist_ips: tuple[str, ...]
    blocklist_ips: tuple[str, ...]
    allowlist_countries: tuple[str, ...]
    blocklist_countries: tuple[str, ...]
    allowlist_process_names: tuple[str, ...]
    blocklist_process_names: tuple[str, ...]


@dataclass(frozen=True)
class DetectionConfig:
    suspicious_ports: frozenset[int]
    port_scan_window_seconds: int
    port_scan_unique_ports: int
    connection_burst_window_seconds: int
    connection_burst_threshold: int
    brute_force_window_seconds: int
    brute_force_threshold: int
    process_burst_window_seconds: int
    process_burst_threshold: int
    alert_cooldown_seconds: int


@dataclass(frozen=True)
class OutputConfig:
    events_path: Path | None
    alerts_path: Path | None
    max_recent_events: int
    max_recent_alerts: int
    min_alert_severity: Severity


@dataclass(frozen=True)
class DashboardConfig:
    enabled: bool
    refresh_seconds: float


@dataclass(frozen=True)
class UiConfig:
    theme: str


@dataclass(frozen=True)
class AppConfig:
    network: NetworkConfig
    process: ProcessConfig
    auth: AuthConfig
    geoip: GeoIpConfig
    ip_intelligence: IpIntelligenceConfig
    llm: LlmConfig
    policy: PolicyConfig
    detection: DetectionConfig
    output: OutputConfig
    dashboard: DashboardConfig
    ui: UiConfig
    raw: dict[str, Any] = field(repr=False)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "AppConfig":
        network = data["network"]
        process = data["process"]
        auth = data["auth"]
        geoip = data["geoip"]
        ip_intelligence = data["ip_intelligence"]
        llm = data["llm"]
        policy = data["policy"]
        detection = data["detection"]
        output = data["output"]
        dashboard = data["dashboard"]
        ui = data["ui"]

        return cls(
            network=NetworkConfig(
                enabled=_as_bool(network["enabled"], "network.enabled"),
                poll_interval_seconds=_as_float(
                    network["poll_interval_seconds"],
                    "network.poll_interval_seconds",
                    min_value=0.2,
                ),
                baseline_existing_on_start=_as_bool(
                    network["baseline_existing_on_start"],
                    "network.baseline_existing_on_start",
                ),
                max_seen_connections=_as_int(
                    network["max_seen_connections"],
                    "network.max_seen_connections",
                    min_value=1,
                ),
            ),
            process=ProcessConfig(
                enabled=_as_bool(process["enabled"], "process.enabled"),
                poll_interval_seconds=_as_float(
                    process["poll_interval_seconds"],
                    "process.poll_interval_seconds",
                    min_value=0.2,
                ),
                baseline_existing_on_start=_as_bool(
                    process["baseline_existing_on_start"],
                    "process.baseline_existing_on_start",
                ),
                max_seen_processes=_as_int(
                    process["max_seen_processes"],
                    "process.max_seen_processes",
                    min_value=1,
                ),
                detail_lookup_enabled=_as_bool(
                    process["detail_lookup_enabled"],
                    "process.detail_lookup_enabled",
                ),
                detail_lookup_timeout_seconds=_as_float(
                    process["detail_lookup_timeout_seconds"],
                    "process.detail_lookup_timeout_seconds",
                    min_value=0.2,
                ),
                suspicious_process_names=_tuple_lower(
                    _as_list(process["suspicious_process_names"], "process.suspicious_process_names")
                ),
            ),
            auth=AuthConfig(
                windows_event_log_enabled=_as_bool(
                    auth["windows_event_log_enabled"],
                    "auth.windows_event_log_enabled",
                ),
                windows_event_log_interval_seconds=_as_float(
                    auth["windows_event_log_interval_seconds"],
                    "auth.windows_event_log_interval_seconds",
                    min_value=1.0,
                ),
                windows_event_log_max_events=_as_int(
                    auth["windows_event_log_max_events"],
                    "auth.windows_event_log_max_events",
                    min_value=1,
                ),
                baseline_existing_on_start=_as_bool(
                    auth["baseline_existing_on_start"],
                    "auth.baseline_existing_on_start",
                ),
                log_files=tuple(
                    str(path) for path in _as_list(auth["log_files"], "auth.log_files")
                ),
                log_poll_interval_seconds=_as_float(
                    auth["log_poll_interval_seconds"],
                    "auth.log_poll_interval_seconds",
                    min_value=0.2,
                ),
                log_failure_patterns=tuple(
                    str(pattern)
                    for pattern in _as_list(auth["log_failure_patterns"], "auth.log_failure_patterns")
                ),
            ),
            geoip=GeoIpConfig(
                enabled=_as_bool(geoip["enabled"], "geoip.enabled"),
                database_path=_as_path_or_none(geoip.get("database_path"), "geoip.database_path"),
                cache_size=_as_int(geoip["cache_size"], "geoip.cache_size", min_value=0),
                unknown_country_code=_as_str(
                    geoip["unknown_country_code"],
                    "geoip.unknown_country_code",
                ).upper(),
                unknown_country_name=_as_str(
                    geoip["unknown_country_name"],
                    "geoip.unknown_country_name",
                ),
            ),
            ip_intelligence=IpIntelligenceConfig(
                enabled=_as_bool(ip_intelligence["enabled"], "ip_intelligence.enabled"),
                provider=_as_str(ip_intelligence["provider"], "ip_intelligence.provider"),
                url_template=_as_url_template(
                    ip_intelligence["url_template"],
                    "ip_intelligence.url_template",
                ),
                timeout_seconds=_as_float(
                    ip_intelligence["timeout_seconds"],
                    "ip_intelligence.timeout_seconds",
                    min_value=0.2,
                ),
                cache_size=_as_int(
                    ip_intelligence["cache_size"],
                    "ip_intelligence.cache_size",
                    min_value=0,
                ),
                queue_size=_as_int(
                    ip_intelligence["queue_size"],
                    "ip_intelligence.queue_size",
                    min_value=1,
                ),
                min_request_interval_seconds=_as_float(
                    ip_intelligence["min_request_interval_seconds"],
                    "ip_intelligence.min_request_interval_seconds",
                    min_value=0.0,
                ),
            ),
            llm=LlmConfig(
                enabled=_as_bool(llm["enabled"], "llm.enabled"),
                provider=_as_str(llm["provider"], "llm.provider"),
                url=_as_local_url(llm["url"], "llm.url"),
                model=_as_str(llm["model"], "llm.model"),
                api_token=_as_str(llm["api_token"], "llm.api_token", allow_empty=True),
                timeout_seconds=_as_float(
                    llm["timeout_seconds"],
                    "llm.timeout_seconds",
                    min_value=1.0,
                ),
                max_tokens=_as_int(llm["max_tokens"], "llm.max_tokens", min_value=64),
                temperature=_as_float(
                    llm["temperature"],
                    "llm.temperature",
                    min_value=0.0,
                    max_value=1.0,
                ),
            ),
            policy=PolicyConfig(
                allowlist_ips=_tuple_lower(_as_list(policy["allowlist_ips"], "policy.allowlist_ips")),
                blocklist_ips=_tuple_lower(_as_list(policy["blocklist_ips"], "policy.blocklist_ips")),
                allowlist_countries=_tuple_upper(
                    _as_list(policy["allowlist_countries"], "policy.allowlist_countries")
                ),
                blocklist_countries=_tuple_upper(
                    _as_list(policy["blocklist_countries"], "policy.blocklist_countries")
                ),
                allowlist_process_names=_tuple_lower(
                    _as_list(policy["allowlist_process_names"], "policy.allowlist_process_names")
                ),
                blocklist_process_names=_tuple_lower(
                    _as_list(policy["blocklist_process_names"], "policy.blocklist_process_names")
                ),
            ),
            detection=DetectionConfig(
                suspicious_ports=_as_port_set(
                    detection["suspicious_ports"],
                    "detection.suspicious_ports",
                ),
                port_scan_window_seconds=_as_int(
                    detection["port_scan_window_seconds"],
                    "detection.port_scan_window_seconds",
                    min_value=1,
                ),
                port_scan_unique_ports=_as_int(
                    detection["port_scan_unique_ports"],
                    "detection.port_scan_unique_ports",
                    min_value=1,
                ),
                connection_burst_window_seconds=_as_int(
                    detection["connection_burst_window_seconds"],
                    "detection.connection_burst_window_seconds",
                    min_value=1,
                ),
                connection_burst_threshold=_as_int(
                    detection["connection_burst_threshold"],
                    "detection.connection_burst_threshold",
                    min_value=1,
                ),
                brute_force_window_seconds=_as_int(
                    detection["brute_force_window_seconds"],
                    "detection.brute_force_window_seconds",
                    min_value=1,
                ),
                brute_force_threshold=_as_int(
                    detection["brute_force_threshold"],
                    "detection.brute_force_threshold",
                    min_value=1,
                ),
                process_burst_window_seconds=_as_int(
                    detection["process_burst_window_seconds"],
                    "detection.process_burst_window_seconds",
                    min_value=1,
                ),
                process_burst_threshold=_as_int(
                    detection["process_burst_threshold"],
                    "detection.process_burst_threshold",
                    min_value=1,
                ),
                alert_cooldown_seconds=_as_int(
                    detection["alert_cooldown_seconds"],
                    "detection.alert_cooldown_seconds",
                    min_value=0,
                ),
            ),
            output=OutputConfig(
                events_path=_as_path_or_none(output.get("events_path"), "output.events_path"),
                alerts_path=_as_path_or_none(output.get("alerts_path"), "output.alerts_path"),
                max_recent_events=_as_int(
                    output["max_recent_events"],
                    "output.max_recent_events",
                    min_value=1,
                ),
                max_recent_alerts=_as_int(
                    output["max_recent_alerts"],
                    "output.max_recent_alerts",
                    min_value=1,
                ),
                min_alert_severity=Severity.parse(output["min_alert_severity"]),
            ),
            dashboard=DashboardConfig(
                enabled=_as_bool(dashboard["enabled"], "dashboard.enabled"),
                refresh_seconds=_as_float(
                    dashboard["refresh_seconds"],
                    "dashboard.refresh_seconds",
                    min_value=0.2,
                ),
            ),
            ui=UiConfig(
                theme=_as_choice(ui["theme"], "ui.theme", {"light", "night"}),
            ),
            raw=copy.deepcopy(data),
        )


def load_config(path: str | Path | None = None) -> AppConfig:
    merged = copy.deepcopy(DEFAULT_CONFIG)
    if path is not None:
        config_path = Path(path)
        with config_path.open("r", encoding="utf-8") as handle:
            user_config = json.load(handle)
        _deep_update(merged, user_config)
    return AppConfig.from_mapping(merged)


def save_config(config: dict[str, Any], path: str | Path = "config/default.json") -> None:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")


def _as_bool(value: Any, path: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    raise ValueError(f"{path} must be a boolean")


def _as_int(
    value: Any,
    path: str,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{path} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        parsed = int(value)
    else:
        raise ValueError(f"{path} must be an integer")
    if min_value is not None and parsed < min_value:
        raise ValueError(f"{path} must be at least {min_value}")
    if max_value is not None and parsed > max_value:
        raise ValueError(f"{path} must be at most {max_value}")
    return parsed


def _as_float(
    value: Any,
    path: str,
    min_value: float | None = None,
    max_value: float | None = None,
) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{path} must be a number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{path} must be a number") from exc
    if min_value is not None and parsed < min_value:
        raise ValueError(f"{path} must be at least {min_value}")
    if max_value is not None and parsed > max_value:
        raise ValueError(f"{path} must be at most {max_value}")
    return parsed


def _as_str(value: Any, path: str, allow_empty: bool = False) -> str:
    text = str(value).strip()
    if not text and not allow_empty:
        raise ValueError(f"{path} must not be empty")
    return text


def _as_choice(value: Any, path: str, allowed: set[str]) -> str:
    text = _as_str(value, path).lower()
    if text not in allowed:
        expected = ", ".join(sorted(allowed))
        raise ValueError(f"{path} must be one of: {expected}")
    return text


def _as_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    return value


def _as_path_or_none(value: Any, path: str) -> Path | None:
    if value is None:
        return None
    text = _as_str(value, path, allow_empty=True)
    return Path(text) if text else None


def _as_port_set(value: Any, path: str) -> frozenset[int]:
    ports = _as_list(value, path)
    return frozenset(
        _as_int(port, f"{path}[{index}]", min_value=1, max_value=65535)
        for index, port in enumerate(ports)
    )


def _as_url_template(value: Any, path: str) -> str:
    template = _as_str(value, path)
    if "{ip}" not in template:
        raise ValueError(f"{path} must include the {{ip}} placeholder")
    parsed = urlparse(template.format(ip="8.8.8.8"))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{path} must be an http or https URL")
    return template


def _as_local_url(value: Any, path: str) -> str:
    url = _as_str(value, path)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"{path} must be an http or https URL")
    hostname = (parsed.hostname or "").lower()
    if hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError(f"{path} must point to localhost for LM Studio")
    return url


def _tuple_lower(values: list[Any]) -> tuple[str, ...]:
    return tuple(str(value).strip().lower() for value in values if str(value).strip())


def _tuple_upper(values: list[Any]) -> tuple[str, ...]:
    return tuple(str(value).strip().upper() for value in values if str(value).strip())
