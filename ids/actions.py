from __future__ import annotations

import csv
import ctypes
import html
import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .engine import RuntimeSnapshot
from .models import Alert
from .process_details import get_process_details


def is_running_as_admin() -> bool:
    if platform.system().lower() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid is not None and geteuid() == 0)


def can_manage_windows_firewall() -> bool:
    return platform.system().lower() == "windows" and is_running_as_admin()


def block_ip_windows_firewall(ip: str) -> tuple[bool, str]:
    if platform.system().lower() != "windows":
        return False, "Windows firewall blocking is only available on Windows."
    if not is_running_as_admin():
        return False, "Administrator rights are required to change Windows Firewall rules."
    rule_name = f"IDS Block {ip}"
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    if completed.returncode == 0:
        return True, completed.stdout.strip() or f"Firewall rule added for {ip}."
    return False, completed.stderr.strip() or completed.stdout.strip() or "netsh failed."


def unblock_ip_windows_firewall(ip: str) -> tuple[bool, str]:
    if platform.system().lower() != "windows":
        return False, "Windows firewall unblocking is only available on Windows."
    if not is_running_as_admin():
        return False, "Administrator rights are required to change Windows Firewall rules."
    rule_name = f"IDS Block {ip}"
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        f"name={rule_name}",
        "dir=in",
        f"remoteip={ip}",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    if completed.returncode == 0:
        return True, completed.stdout.strip() or f"Firewall rule removed for {ip}."
    return False, completed.stderr.strip() or completed.stdout.strip() or "netsh failed."

def export_report(snapshot: RuntimeSnapshot, path: Path, format_name: str) -> None:
    format_name = format_name.lower()
    if format_name == "html":
        _export_html(snapshot, path)
    elif format_name == "csv":
        _export_csv(snapshot.recent_alerts, path)
    else:
        _export_text(snapshot, path)


def _export_text(snapshot: RuntimeSnapshot, path: Path) -> None:
    lines = [
        "Intrusion Detection System Report",
        f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Events processed: {snapshot.total_events}",
        f"Alerts raised: {snapshot.total_alerts}",
        "",
        "Alerts",
    ]
    for alert in reversed(snapshot.recent_alerts):
        lines.extend(
            [
                f"- {alert.timestamp.astimezone().strftime('%Y-%m-%d %H:%M:%S')} {alert.severity.name} {alert.title}",
                f"  {alert.description}",
                f"  Action: {alert.recommended_action}",
            ]
        )
    lines.extend(["", "Top Risk Hosts"])
    for host in snapshot.risk_hosts:
        lines.append(f"- {host.ip}: score={host.score}, events={host.events}, alerts={host.alerts}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _export_html(snapshot: RuntimeSnapshot, path: Path) -> None:
    alert_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(alert.timestamp.astimezone().strftime('%Y-%m-%d %H:%M:%S'))}</td>"
        f"<td>{html.escape(alert.severity.name)}</td>"
        f"<td>{html.escape(alert.title)}</td>"
        f"<td>{html.escape(alert.description)}</td>"
        f"<td>{html.escape(alert.recommended_action)}</td>"
        "</tr>"
        for alert in reversed(snapshot.recent_alerts)
    )
    risk_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(host.ip)}</td>"
        f"<td>{host.score}</td>"
        f"<td>{host.events}</td>"
        f"<td>{host.alerts}</td>"
        "</tr>"
        for host in snapshot.risk_hosts
    )
    body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>IDS Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #18202f; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
    th, td {{ border: 1px solid #d8dee9; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
  </style>
</head>
<body>
  <h1>Intrusion Detection System Report</h1>
  <p>Generated: {html.escape(datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S'))}</p>
  <p>Events processed: {snapshot.total_events} | Alerts raised: {snapshot.total_alerts}</p>
  <h2>Alerts</h2>
  <table><thead><tr><th>Time</th><th>Severity</th><th>Title</th><th>Description</th><th>Recommended Action</th></tr></thead><tbody>{alert_rows}</tbody></table>
  <h2>Top Risk Hosts</h2>
  <table><thead><tr><th>IP</th><th>Score</th><th>Events</th><th>Alerts</th></tr></thead><tbody>{risk_rows}</tbody></table>
</body>
</html>
"""
    path.write_text(body, encoding="utf-8")


def _export_csv(alerts: Iterable[Alert], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["time", "severity", "rule", "title", "description", "recommended_action"])
        for alert in reversed(tuple(alerts)):
            writer.writerow(
                [
                    alert.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                    alert.severity.name,
                    alert.rule_id,
                    alert.title,
                    alert.description,
                    alert.recommended_action,
                ]
            )


def selected_process_details(pid: int, timeout_seconds: float = 2.5) -> dict[str, object]:
    return get_process_details(pid, timeout_seconds)
