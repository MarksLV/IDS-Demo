from __future__ import annotations

import ipaddress
import json
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import IpIntelligenceConfig
from .models import Event


@dataclass(frozen=True)
class IpIntelligence:
    ip: str
    status: str
    provider: str
    message: str = ""
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    postal: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone_id: str | None = None
    ip_type: str | None = None
    isp: str | None = None
    organization: str | None = None
    asn: str | None = None
    domain: str | None = None
    proxy: bool | None = None
    vpn: bool | None = None
    tor: bool | None = None
    hosting: bool | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def location_label(self) -> str:
        parts = [part for part in [self.city, self.region, self.country] if part]
        return ", ".join(parts)

    @property
    def network_label(self) -> str:
        parts = [part for part in [self.isp, self.organization, self.asn] if part]
        return " / ".join(parts)

    def to_event_attrs(self, prefix: str) -> dict[str, object]:
        attrs: dict[str, object] = {
            f"{prefix}_ip_intel_status": self.status,
            f"{prefix}_ip_intel_provider": self.provider,
            f"{prefix}_ip_intel_message": self.message,
        }
        if self.status == "success":
            optional = {
                f"{prefix}_country": self.country,
                f"{prefix}_country_code": self.country_code,
                f"{prefix}_region": self.region,
                f"{prefix}_city": self.city,
                f"{prefix}_postal": self.postal,
                f"{prefix}_latitude": self.latitude,
                f"{prefix}_longitude": self.longitude,
                f"{prefix}_timezone": self.timezone_id,
                f"{prefix}_ip_type": self.ip_type,
                f"{prefix}_isp": self.isp,
                f"{prefix}_organization": self.organization,
                f"{prefix}_asn": self.asn,
                f"{prefix}_domain": self.domain,
                f"{prefix}_proxy": self.proxy,
                f"{prefix}_vpn": self.vpn,
                f"{prefix}_tor": self.tor,
                f"{prefix}_hosting": self.hosting,
            }
            attrs.update({key: value for key, value in optional.items() if value is not None})
        return attrs


class IpIntelligenceService:
    def __init__(self, config: IpIntelligenceConfig) -> None:
        self.config = config
        self.enabled = config.enabled
        self.provider = config.provider
        self.timeout_seconds = max(0.2, config.timeout_seconds)
        self.min_request_interval_seconds = max(0.0, config.min_request_interval_seconds)
        self._queue: queue.Queue[str] = queue.Queue(maxsize=max(1, config.queue_size))
        self._cache: OrderedDict[str, IpIntelligence] = OrderedDict()
        self._pending: set[str] = set()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._last_request_at = 0.0
        self.warning: str | None = None
        self.version = 0
        self._thread: threading.Thread | None = None
        if self.enabled:
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="IPIntelligence",
                daemon=True,
            )
            self._thread.start()

    def enrich_event(self, event: Event) -> Event:
        if not self.enabled:
            return event
        attrs = dict(event.attributes)
        changed = False
        for prefix in ("remote",):
            ip_text = attrs.get(f"{prefix}_ip")
            if not isinstance(ip_text, str) or not ip_text:
                continue
            info = self.lookup_cached(ip_text)
            if info is None:
                self.schedule(ip_text)
                attrs[f"{prefix}_ip_intel_status"] = "queued"
                attrs[f"{prefix}_ip_intel_provider"] = self.provider
                changed = True
            else:
                attrs.update(info.to_event_attrs(prefix))
                changed = True
        if not changed:
            return event
        return Event(
            kind=event.kind,
            timestamp=event.timestamp,
            source=event.source,
            attributes=attrs,
        )

    def schedule(self, ip_text: str) -> None:
        normalized = self._normalize_public_ip(ip_text)
        if normalized is None:
            return
        with self._lock:
            if normalized in self._cache or normalized in self._pending:
                return
            self._pending.add(normalized)
        try:
            self._queue.put_nowait(normalized)
        except queue.Full:
            with self._lock:
                self._pending.discard(normalized)
            self.warning = "IP intelligence lookup queue is full; new lookups are being skipped."

    def lookup_cached(self, ip_text: str) -> IpIntelligence | None:
        normalized = self._normalize_ip(ip_text)
        if normalized is None:
            return None
        with self._lock:
            cached = self._cache.get(normalized)
            if cached is not None:
                self._cache.move_to_end(normalized)
            return cached

    def cached_items(self) -> tuple[IpIntelligence, ...]:
        with self._lock:
            return tuple(self._cache.values())

    def snapshot(self) -> tuple[tuple[IpIntelligence, ...], int]:
        with self._lock:
            return tuple(self._cache.values()), self.version

    def close(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=0.2)

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                ip_text = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            wait_seconds = self.min_request_interval_seconds - (
                time.monotonic() - self._last_request_at
            )
            if wait_seconds > 0 and self._stop_event.wait(wait_seconds):
                break

            self._last_request_at = time.monotonic()
            info = self._lookup_remote(ip_text)
            with self._lock:
                self._pending.discard(ip_text)
                self._cache[ip_text] = info
                self._cache.move_to_end(ip_text)
                while len(self._cache) > self.config.cache_size:
                    self._cache.popitem(last=False)
                self.version += 1
            self._queue.task_done()

    def _lookup_remote(self, ip_text: str) -> IpIntelligence:
        url = self.config.url_template.format(ip=urllib.parse.quote(ip_text, safe=""))
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "IntrusionDetectionSystem/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read(128 * 1024).decode("utf-8", errors="replace")
            data = json.loads(payload)
            return self._parse_ipwhois(ip_text, data)
        except urllib.error.HTTPError as exc:
            message = f"HTTP {exc.code}"
            if exc.code == 429:
                message = "API rate limit reached"
            self.warning = f"IP intelligence lookup for {ip_text} failed: {message}"
            return IpIntelligence(ip=ip_text, status="error", provider=self.provider, message=message)
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            message = str(exc) or exc.__class__.__name__
            self.warning = f"IP intelligence lookup for {ip_text} failed: {message}"
            return IpIntelligence(ip=ip_text, status="error", provider=self.provider, message=message)

    def _parse_ipwhois(self, ip_text: str, data: dict[str, Any]) -> IpIntelligence:
        if data.get("success") is False:
            return IpIntelligence(
                ip=ip_text,
                status="error",
                provider=self.provider,
                message=str(data.get("message") or "lookup failed"),
            )
        connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
        timezone_data = data.get("timezone") if isinstance(data.get("timezone"), dict) else {}
        security = data.get("security") if isinstance(data.get("security"), dict) else {}
        asn = connection.get("asn")
        return IpIntelligence(
            ip=str(data.get("ip") or ip_text),
            status="success",
            provider=self.provider,
            country=_optional_str(data.get("country")),
            country_code=_optional_str(data.get("country_code")),
            region=_optional_str(data.get("region")),
            city=_optional_str(data.get("city")),
            postal=_optional_str(data.get("postal")),
            latitude=_optional_float(data.get("latitude")),
            longitude=_optional_float(data.get("longitude")),
            timezone_id=_optional_str(timezone_data.get("id")),
            ip_type=_optional_str(data.get("type")),
            isp=_optional_str(connection.get("isp")),
            organization=_optional_str(connection.get("org")),
            asn=f"AS{asn}" if asn not in {None, ""} else None,
            domain=_optional_str(connection.get("domain")),
            proxy=_optional_bool(security.get("proxy")),
            vpn=_optional_bool(security.get("vpn")),
            tor=_optional_bool(security.get("tor")),
            hosting=_optional_bool(security.get("hosting")),
        )

    def _normalize_public_ip(self, ip_text: str) -> str | None:
        normalized = self._normalize_ip(ip_text)
        if normalized is None:
            return None
        try:
            ip = ipaddress.ip_address(normalized)
        except ValueError:
            return None
        if not ip.is_global:
            self._remember_special_ip(normalized, ip)
            return None
        return normalized

    def _remember_special_ip(self, normalized: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        reason = "non-public IP; external lookup skipped"
        if ip.is_loopback:
            reason = "loopback IP; external lookup skipped"
        elif ip.is_private:
            reason = "private IP; external lookup skipped"
        elif ip.is_link_local:
            reason = "link-local IP; external lookup skipped"
        elif ip.is_reserved:
            reason = "reserved IP; external lookup skipped"
        info = IpIntelligence(
            ip=normalized,
            status="skipped",
            provider=self.provider,
            message=reason,
            ip_type=f"IPv{ip.version}",
        )
        with self._lock:
            if normalized not in self._cache:
                self._cache[normalized] = info
                self.version += 1

    def _normalize_ip(self, ip_text: str) -> str | None:
        try:
            return str(ipaddress.ip_address(ip_text.strip()))
        except ValueError:
            return None


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_float(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    return None


def build_ip_intelligence_service(config: IpIntelligenceConfig) -> IpIntelligenceService:
    return IpIntelligenceService(config)
