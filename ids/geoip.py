from __future__ import annotations

import csv
import ipaddress
from bisect import bisect_right
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from .config import GeoIpConfig
from .models import Event


@dataclass(frozen=True)
class GeoLocation:
    country_code: str
    country_name: str
    source: str


@dataclass(frozen=True)
class CountryRange:
    start: int
    end: int
    version: int
    country_code: str
    country_name: str


class GeoIpResolver:
    def __init__(self, config: GeoIpConfig) -> None:
        self.enabled = config.enabled
        self.cache_size = max(0, config.cache_size)
        self.unknown = GeoLocation(
            country_code=config.unknown_country_code,
            country_name=config.unknown_country_name,
            source="unknown",
        )
        self._cache: OrderedDict[str, GeoLocation] = OrderedDict()
        self._ranges_v4: list[CountryRange] = []
        self._ranges_v6: list[CountryRange] = []
        self._starts_v4: list[int] = []
        self._starts_v6: list[int] = []
        self.warning: str | None = None

        if self.enabled and config.database_path is not None:
            try:
                self.load_database(config.database_path)
            except OSError as exc:
                self.warning = f"GeoIP database could not be loaded: {exc}"

    def load_database(self, path: Path) -> None:
        if not path.exists():
            self.warning = (
                f"GeoIP database {path} was not found; public IP countries will be unknown."
            )
            return

        ranges: list[CountryRange] = []
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for line_number, row in enumerate(reader, start=2):
                try:
                    parsed = self._parse_row(row)
                except ValueError as exc:
                    self.warning = f"Skipped invalid GeoIP row {line_number}: {exc}"
                    continue
                ranges.append(parsed)

        self._ranges_v4 = sorted(
            (item for item in ranges if item.version == 4),
            key=lambda item: item.start,
        )
        self._ranges_v6 = sorted(
            (item for item in ranges if item.version == 6),
            key=lambda item: item.start,
        )
        self._starts_v4 = [item.start for item in self._ranges_v4]
        self._starts_v6 = [item.start for item in self._ranges_v6]

    def lookup(self, ip_text: str | None) -> GeoLocation:
        if not self.enabled or not ip_text:
            return self.unknown

        ip_text = ip_text.strip()
        cached = self._cache.get(ip_text)
        if cached is not None:
            self._cache.move_to_end(ip_text)
            return cached

        location = self._lookup_uncached(ip_text)
        if self.cache_size > 0:
            self._cache[ip_text] = location
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
        return location

    def enrich_event(self, event: Event) -> Event:
        if not self.enabled:
            return event

        attrs = dict(event.attributes)
        changed = False
        for prefix in ("remote", "local"):
            key = f"{prefix}_ip"
            ip_text = attrs.get(key)
            if not isinstance(ip_text, str) or not ip_text:
                continue
            location = self.lookup(ip_text)
            attrs[f"{prefix}_country_code"] = location.country_code
            attrs[f"{prefix}_country"] = location.country_name
            attrs[f"{prefix}_geo_source"] = location.source
            changed = True

        if not changed:
            return event
        return Event(
            kind=event.kind,
            timestamp=event.timestamp,
            source=event.source,
            attributes=attrs,
        )

    def _lookup_uncached(self, ip_text: str) -> GeoLocation:
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return self.unknown

        database_match = self._lookup_database(ip)
        if database_match is not None:
            return database_match

        if ip.is_loopback:
            return GeoLocation("LO", "Loopback", "special")
        if ip.is_link_local:
            return GeoLocation("LL", "Link-local network", "special")
        if ip.is_private:
            return GeoLocation("PR", "Private network", "special")
        if ip.is_multicast:
            return GeoLocation("MC", "Multicast", "special")
        if ip.is_reserved:
            return GeoLocation("RS", "Reserved network", "special")
        if ip.is_unspecified:
            return GeoLocation("UN", "Unspecified address", "special")
        return self.unknown

    def _lookup_database(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> GeoLocation | None:
        value = int(ip)
        ranges = self._ranges_v4 if ip.version == 4 else self._ranges_v6
        starts = self._starts_v4 if ip.version == 4 else self._starts_v6
        index = bisect_right(starts, value) - 1
        if index < 0:
            return None
        candidate = ranges[index]
        if candidate.start <= value <= candidate.end:
            return GeoLocation(candidate.country_code, candidate.country_name, "database")
        return None

    def _parse_row(self, row: dict[str, str]) -> CountryRange:
        country_code = (row.get("country_code") or "").strip().upper() or "ZZ"
        country_name = (row.get("country_name") or "").strip() or "Unknown"
        network_text = (row.get("network") or "").strip()
        if network_text:
            network = ipaddress.ip_network(network_text, strict=False)
            return CountryRange(
                start=int(network.network_address),
                end=int(network.broadcast_address),
                version=network.version,
                country_code=country_code,
                country_name=country_name,
            )

        start_text = (row.get("start_ip") or "").strip()
        end_text = (row.get("end_ip") or "").strip()
        if not start_text or not end_text:
            raise ValueError("expected either network or start_ip/end_ip")

        start = ipaddress.ip_address(start_text)
        end = ipaddress.ip_address(end_text)
        if start.version != end.version:
            raise ValueError("start_ip and end_ip must use the same IP version")
        if int(start) > int(end):
            raise ValueError("start_ip must be less than or equal to end_ip")
        return CountryRange(
            start=int(start),
            end=int(end),
            version=start.version,
            country_code=country_code,
            country_name=country_name,
        )


def build_geoip_resolver(config: GeoIpConfig) -> GeoIpResolver:
    return GeoIpResolver(config)
