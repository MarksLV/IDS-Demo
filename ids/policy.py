from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .config import PolicyConfig
from .models import Event


@dataclass(frozen=True)
class PolicyDecision:
    status: str
    reason: str = ""


class SecurityPolicy:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def apply(self, event: Event) -> Event:
        decision = self.evaluate(event)
        if decision.status == "normal":
            return event
        attrs = dict(event.attributes)
        attrs["policy_status"] = decision.status
        attrs["policy_reason"] = decision.reason
        return Event(
            kind=event.kind,
            timestamp=event.timestamp,
            source=event.source,
            attributes=attrs,
        )

    def evaluate(self, event: Event) -> PolicyDecision:
        block_reason = self._match_blocklist(event)
        if block_reason:
            return PolicyDecision("blocklisted", block_reason)
        allow_reason = self._match_allowlist(event)
        if allow_reason:
            return PolicyDecision("allowlisted", allow_reason)
        return PolicyDecision("normal")

    def _match_blocklist(self, event: Event) -> str:
        attrs = event.attributes
        remote_ip = str(attrs.get("remote_ip") or "").strip().lower()
        country_code = str(attrs.get("remote_country_code") or "").strip().upper()
        country = str(attrs.get("remote_country") or "").strip().upper()
        image_name = _event_process_name(attrs)
        if remote_ip and _ip_matches(remote_ip, self.config.blocklist_ips):
            return f"remote IP {remote_ip} is blocklisted"
        if country_code and country_code in self.config.blocklist_countries:
            return f"country code {country_code} is blocklisted"
        if country and country in self.config.blocklist_countries:
            return f"country {country} is blocklisted"
        if image_name and image_name in self.config.blocklist_process_names:
            return f"process {image_name} is blocklisted"
        return ""

    def _match_allowlist(self, event: Event) -> str:
        attrs = event.attributes
        remote_ip = str(attrs.get("remote_ip") or "").strip().lower()
        country_code = str(attrs.get("remote_country_code") or "").strip().upper()
        country = str(attrs.get("remote_country") or "").strip().upper()
        image_name = _event_process_name(attrs)
        if remote_ip and _ip_matches(remote_ip, self.config.allowlist_ips):
            return f"remote IP {remote_ip} is allowlisted"
        if country_code and country_code in self.config.allowlist_countries:
            return f"country code {country_code} is allowlisted"
        if country and country in self.config.allowlist_countries:
            return f"country {country} is allowlisted"
        if image_name and image_name in self.config.allowlist_process_names:
            return f"process {image_name} is allowlisted"
        return ""


def _event_process_name(attrs: dict[str, object]) -> str:
    return str(attrs.get("image_name") or attrs.get("process_name") or "").strip().lower()


def _ip_matches(ip_text: str, entries: tuple[str, ...]) -> bool:
    if not entries:
        return False
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return ip_text in entries
    for entry in entries:
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            if ip_text == entry:
                return True
    return False
