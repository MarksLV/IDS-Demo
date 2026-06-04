from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from typing import Iterable

from .process_details import get_process_details


BROWSER_PROCESS_NAMES = {
    "chrome",
    "chrome.exe",
    "msedge",
    "msedge.exe",
    "firefox",
    "firefox.exe",
    "brave",
    "brave.exe",
    "brave-browser",
    "opera",
    "opera.exe",
    "vivaldi",
    "vivaldi.exe",
}

DEVTOOLS_PORTS = (9222, 9223, 9224, 9225)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def is_browser_process_name(value: object) -> bool:
    name = str(value or "").strip().lower()
    if not name:
        return False
    short_name = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return short_name in BROWSER_PROCESS_NAMES


def extract_urls_from_command_line(command_line: str) -> list[str]:
    return list(dict.fromkeys(match.rstrip("),.;") for match in URL_RE.findall(command_line)))


def browser_context_lines_for_process(
    pid: int,
    process_name: str,
    timeout_seconds: float = 0.8,
    devtools_ports: Iterable[int] = DEVTOOLS_PORTS,
) -> list[str]:
    if not is_browser_process_name(process_name):
        return []

    lines: list[str] = []
    try:
        details = get_process_details(pid, timeout_seconds)
    except Exception as exc:
        details = {}
        lines.append(_process_lookup_error_message(exc))
    command_line = str(details.get("command_line") or "")
    command_line_urls = extract_urls_from_command_line(command_line)
    for url in command_line_urls[:5]:
        lines.append(f"Command line URL: {url}")

    tabs = list_debug_tabs(devtools_ports, timeout_seconds=0.15)
    for tab in tabs[:10]:
        label = f"{tab['title']} - {tab['url']}" if tab.get("title") else str(tab["url"])
        lines.append(f"Open DevTools tab: {label}")

    if lines:
        return lines
    return [
        "No live page URL was exposed for this browser process.",
        "Browsers usually hide tab URLs unless launched with remote debugging, such as --remote-debugging-port=9222.",
    ]


def _process_lookup_error_message(exc: Exception) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        return (
            "Process details lookup timed out. Increase process detail timeout in Settings "
            "or enable browser remote debugging for live tab URLs."
        )
    if isinstance(exc, PermissionError):
        return "Process details lookup was denied by Windows permissions."
    return "Process details lookup failed; Windows may have blocked access to this process."


def list_debug_tabs(
    ports: Iterable[int] = DEVTOOLS_PORTS,
    timeout_seconds: float = 0.15,
) -> list[dict[str, str]]:
    tabs: list[dict[str, str]] = []
    for port in ports:
        request = urllib.request.Request(
            f"http://127.0.0.1:{int(port)}/json/list",
            headers={"User-Agent": "IntrusionDetectionSystem/1.0"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                payload = response.read(256 * 1024).decode("utf-8", errors="replace")
            data = json.loads(payload)
        except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            if not url.startswith(("http://", "https://")):
                continue
            tabs.append(
                {
                    "title": str(item.get("title") or ""),
                    "url": url,
                    "port": str(port),
                }
            )
    return tabs
