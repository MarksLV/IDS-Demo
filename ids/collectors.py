from __future__ import annotations

import csv
import json
import os
import platform
import re
import subprocess
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from io import StringIO
from pathlib import Path
from typing import Any, Iterable

from .config import AuthConfig, NetworkConfig, ProcessConfig
from .models import Event, parse_timestamp, utc_now
from .process_details import get_process_details


_SS_PID_PATTERN = re.compile(r"\bpid=(?P<pid>\d+)\b")


@dataclass(frozen=True)
class NetworkConnection:
    protocol: str
    local_ip: str
    local_port: int | None
    remote_ip: str
    remote_port: int | None
    state: str
    pid: int | None
    process_name: str | None = None

    @property
    def key(self) -> tuple[Any, ...]:
        return (
            self.protocol,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
            self.state,
            self.pid,
        )

    def to_event(self, source: str) -> Event:
        return Event(
            kind="network_connection",
            source=source,
            attributes={
                "protocol": self.protocol,
                "local_ip": self.local_ip,
                "local_port": self.local_port,
                "remote_ip": self.remote_ip,
                "remote_port": self.remote_port,
                "state": self.state,
                "pid": self.pid,
                "process_name": self.process_name,
            },
        )


class Collector:
    name = "collector"

    def __init__(self, interval_seconds: float) -> None:
        self.interval_seconds = max(0.2, interval_seconds)
        self.next_due_monotonic = 0.0
        self.warning: str | None = None
        self.enabled = True

    def due(self, now_monotonic: float) -> bool:
        return self.enabled and now_monotonic >= self.next_due_monotonic

    def mark_polled(self, now_monotonic: float) -> None:
        self.next_due_monotonic = now_monotonic + self.interval_seconds

    def poll(self) -> list[Event]:
        raise NotImplementedError


def parse_endpoint(endpoint: str) -> tuple[str, int | None]:
    endpoint = endpoint.strip()
    if endpoint in {"*", "*:*"}:
        return "*", None
    if endpoint.startswith("["):
        match = re.match(r"^\[(?P<host>.*)]:(?P<port>[^:]+)$", endpoint)
        if match:
            return match.group("host"), _parse_port(match.group("port"))
        return endpoint.strip("[]"), None
    if ":" not in endpoint:
        return endpoint, None
    host, port_text = endpoint.rsplit(":", 1)
    return host or "*", _parse_port(port_text)


def _parse_port(value: str) -> int | None:
    if value.isdigit():
        return int(value)
    return None


def parse_netstat_output(text: str) -> list[NetworkConnection]:
    connections: list[NetworkConnection] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith(("TCP", "UDP", "tcp", "udp")):
            continue
        parts = line.split()
        protocol = parts[0].upper()
        try:
            if len(parts) >= 6 and _looks_like_unix_netstat(parts):
                connection = _parse_unix_netstat_parts(protocol, parts)
                if connection is not None:
                    connections.append(connection)
                continue
            if protocol == "TCP" and len(parts) >= 5:
                local_ip, local_port = parse_endpoint(parts[1])
                remote_ip, remote_port = parse_endpoint(parts[2])
                state = parts[3].upper()
                pid = _safe_int(parts[4])
            elif protocol == "UDP" and len(parts) >= 4:
                local_ip, local_port = parse_endpoint(parts[1])
                remote_ip, remote_port = parse_endpoint(parts[2])
                state = "UDP"
                pid = _safe_int(parts[3])
            else:
                continue
        except (IndexError, ValueError):
            continue
        connections.append(
            NetworkConnection(
                protocol=protocol,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=pid,
            )
        )
    return connections


def parse_ss_output(text: str) -> list[NetworkConnection]:
    connections: list[NetworkConnection] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Netid"):
            continue
        if not line.startswith(("tcp", "udp", "TCP", "UDP")):
            continue
        parts = line.split()
        if len(parts) < 6:
            continue

        protocol = parts[0].upper()
        state = parts[1].upper()
        local_ip, local_port = parse_endpoint(parts[4])
        remote_ip, remote_port = parse_endpoint(parts[5])
        connections.append(
            NetworkConnection(
                protocol=protocol,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                pid=_parse_ss_pid(line),
            )
        )
    return connections


def _looks_like_unix_netstat(parts: list[str]) -> bool:
    return len(parts) >= 5 and parts[1].isdigit() and parts[2].isdigit()


def _parse_unix_netstat_parts(protocol: str, parts: list[str]) -> NetworkConnection | None:
    local_ip, local_port = parse_endpoint(parts[3])
    remote_ip, remote_port = parse_endpoint(parts[4])
    state = "UDP" if protocol == "UDP" else ""
    pid = None

    if protocol == "TCP":
        if len(parts) < 6:
            return None
        state = parts[5].upper()
        if len(parts) >= 7:
            pid = _parse_pid_program(parts[6])
    elif len(parts) >= 6:
        maybe_pid = _parse_pid_program(parts[5])
        if maybe_pid is None and len(parts) >= 7:
            state = parts[5].upper()
            maybe_pid = _parse_pid_program(parts[6])
        pid = maybe_pid

    return NetworkConnection(
        protocol=protocol,
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        state=state,
        pid=pid,
    )


def _parse_pid_program(value: str) -> int | None:
    pid_text = value.split("/", 1)[0]
    return _safe_int(pid_text)


def _parse_ss_pid(line: str) -> int | None:
    match = _SS_PID_PATTERN.search(line)
    if match is None:
        return None
    return _safe_int(match.group("pid"))


def _safe_int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def enrich_connection_process_names(
    connections: Iterable[NetworkConnection],
    names_by_pid: dict[int, str],
) -> list[NetworkConnection]:
    enriched: list[NetworkConnection] = []
    for connection in connections:
        process_name = connection.process_name
        if not process_name and connection.pid == 0:
            process_name = "System / kernel"
        elif not process_name and connection.pid is not None:
            process_name = names_by_pid.get(connection.pid)
        enriched.append(replace(connection, process_name=process_name))
    return enriched


def process_names_by_pid_snapshot() -> dict[int, str]:
    if platform.system().lower() == "windows":
        completed = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return {
            pid: row["image_name"]
            for row in parse_tasklist_output(completed.stdout)
            if (pid := _safe_int(row.get("pid", ""))) is not None
            and row.get("image_name")
        }

    completed = subprocess.run(
        ["ps", "-eo", "pid=,comm="],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    names: dict[int, str] = {}
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        pid_text, _, image_name = stripped.partition(" ")
        pid = _safe_int(pid_text.strip())
        if pid is not None and image_name.strip():
            names[pid] = image_name.strip()
    return names


class NetworkConnectionCollector(Collector):
    name = "network"

    def __init__(self, config: NetworkConfig) -> None:
        super().__init__(config.poll_interval_seconds)
        self.baseline_existing_on_start = config.baseline_existing_on_start
        self.max_seen_connections = config.max_seen_connections
        self._seen: OrderedDict[tuple[Any, ...], None] = OrderedDict()
        self._first_poll = True
        self._process_names_by_pid: dict[int, str] = {}
        self._process_names_expires_at = 0.0

    def poll(self) -> list[Event]:
        try:
            snapshot = self._snapshot()
        except (OSError, subprocess.SubprocessError) as exc:
            self.warning = f"Network collector failed: {exc}"
            return []

        events: list[Event] = []
        for connection in snapshot:
            key = connection.key
            if key in self._seen:
                self._seen.move_to_end(key)
                continue
            self._seen[key] = None
            if not (self._first_poll and self.baseline_existing_on_start):
                events.append(connection.to_event(self.name))

        while len(self._seen) > self.max_seen_connections:
            self._seen.popitem(last=False)

        self._first_poll = False
        return events

    def _snapshot(self) -> list[NetworkConnection]:
        system = platform.system().lower()
        if system == "windows":
            command = ["netstat", "-ano"]
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            return self._with_process_names(parse_netstat_output(completed.stdout))

        ss_error = ""
        try:
            ss = subprocess.run(
                ["ss", "-H", "-tunapn"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if ss.returncode == 0 and ss.stdout.strip():
                return self._with_process_names(parse_ss_output(ss.stdout))
            ss_error = ss.stderr.strip()
        except OSError as exc:
            ss_error = str(exc)

        netstat = subprocess.run(
            ["netstat", "-tunapn"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if netstat.returncode != 0:
            raise subprocess.SubprocessError(
                netstat.stderr.strip() or ss_error or "network snapshot command failed"
            )
        return self._with_process_names(parse_netstat_output(netstat.stdout))

    def _with_process_names(self, connections: list[NetworkConnection]) -> list[NetworkConnection]:
        if not connections:
            return []
        return enrich_connection_process_names(connections, self._cached_process_names_by_pid())

    def _cached_process_names_by_pid(self) -> dict[int, str]:
        now = time.monotonic()
        if now < self._process_names_expires_at:
            return self._process_names_by_pid
        try:
            self._process_names_by_pid = process_names_by_pid_snapshot()
        except (OSError, subprocess.SubprocessError):
            self._process_names_by_pid = {}
        self._process_names_expires_at = now + 5.0
        return self._process_names_by_pid


def parse_tasklist_output(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    reader = csv.reader(StringIO(text))
    for row in reader:
        if len(row) < 5:
            continue
        rows.append(
            {
                "image_name": row[0],
                "pid": row[1],
                "session_name": row[2],
                "session_number": row[3],
                "memory": row[4],
            }
        )
    return rows


def parse_posix_process_output(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 6)
        if len(parts) < 7:
            continue
        rows.append(
            {
                "pid": parts[0],
                "start_time": " ".join(parts[1:6]),
                "image_name": parts[6],
                "session_name": "",
                "memory": "",
            }
        )
    return rows


class ProcessCollector(Collector):
    name = "process"

    def __init__(self, config: ProcessConfig) -> None:
        super().__init__(config.poll_interval_seconds)
        self.baseline_existing_on_start = config.baseline_existing_on_start
        self.max_seen_processes = config.max_seen_processes
        self.detail_lookup_enabled = config.detail_lookup_enabled
        self.detail_lookup_timeout_seconds = config.detail_lookup_timeout_seconds
        self._seen: OrderedDict[tuple[int, str, str], None] = OrderedDict()
        self._first_poll = True

    def poll(self) -> list[Event]:
        try:
            snapshot = self._snapshot()
        except (OSError, subprocess.SubprocessError) as exc:
            self.warning = f"Process collector failed: {exc}"
            return []

        events: list[Event] = []
        active_keys: set[tuple[int, str, str]] = set()
        for process in snapshot:
            pid = _safe_int(process.get("pid", ""))
            if pid is None:
                continue
            image_name = process.get("image_name", "")
            key = self._process_key(pid, process)
            active_keys.add(key)
            if key in self._seen:
                self._seen.move_to_end(key)
                continue
            self._seen[key] = None
            if not (self._first_poll and self.baseline_existing_on_start):
                details = {}
                if self.detail_lookup_enabled:
                    details = get_process_details(pid, self.detail_lookup_timeout_seconds)
                events.append(
                    Event(
                        kind="process_start",
                        source=self.name,
                        attributes={
                            "pid": pid,
                            "image_name": image_name,
                            "session_name": process.get("session_name"),
                            "memory": process.get("memory"),
                            "start_time": process.get("start_time"),
                            **details,
                        },
                    )
                )

        for key in tuple(self._seen):
            if key not in active_keys:
                del self._seen[key]

        while len(self._seen) > self.max_seen_processes:
            self._seen.popitem(last=False)

        self._first_poll = False
        return events

    def _process_key(self, pid: int, process: dict[str, str]) -> tuple[int, str, str]:
        image_name = process.get("image_name", "").strip().lower()
        start_time = process.get("start_time", "").strip()
        return pid, image_name, start_time

    def _snapshot(self) -> list[dict[str, str]]:
        if platform.system().lower() == "windows":
            completed = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            return parse_tasklist_output(completed.stdout)

        completed = subprocess.run(
            ["ps", "-eo", "pid=,lstart=,comm="],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if completed.returncode == 0:
            rows = parse_posix_process_output(completed.stdout)
            if rows:
                return rows

        completed = subprocess.run(
            ["ps", "-eo", "pid=,comm="],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        rows = []
        for line in completed.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            pid, _, image_name = stripped.partition(" ")
            rows.append(
                {
                    "pid": pid.strip(),
                    "image_name": image_name.strip(),
                    "session_name": "",
                    "memory": "",
                    "start_time": "",
                }
            )
        return rows


class LogFileCollector(Collector):
    name = "logfile"

    def __init__(self, config: AuthConfig) -> None:
        super().__init__(config.log_poll_interval_seconds)
        self.paths = [Path(path) for path in config.log_files]
        self.baseline_existing_on_start = config.baseline_existing_on_start
        self._offsets: dict[Path, int] = {}
        self._first_poll = True

    def poll(self) -> list[Event]:
        events: list[Event] = []
        for path in self.paths:
            if not path.exists() or not path.is_file():
                continue
            try:
                events.extend(self._read_new_lines(path))
            except OSError as exc:
                self.warning = f"Could not read log file {path}: {exc}"
        self._first_poll = False
        return events

    def _read_new_lines(self, path: Path) -> list[Event]:
        current_size = path.stat().st_size
        if path not in self._offsets:
            self._offsets[path] = current_size if self.baseline_existing_on_start else 0
        elif current_size < self._offsets[path]:
            self._offsets[path] = 0

        with path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._offsets[path])
            lines = handle.readlines(1024 * 128)
            self._offsets[path] = handle.tell()

        return [
            Event(
                kind="log_line",
                source=self.name,
                attributes={"path": str(path), "line": line.rstrip("\r\n")},
            )
            for line in lines
            if line.strip()
        ]


class WindowsEventLogCollector(Collector):
    name = "windows_event_log"

    def __init__(self, config: AuthConfig) -> None:
        super().__init__(config.windows_event_log_interval_seconds)
        self.max_events = config.windows_event_log_max_events
        self.baseline_existing_on_start = config.baseline_existing_on_start
        self._last_record_id: int | None = None
        self._first_poll = True

    def poll(self) -> list[Event]:
        if platform.system().lower() != "windows":
            self.enabled = False
            return []
        try:
            records = self._read_failed_logons()
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
            self.warning = f"Windows event log collector disabled: {exc}"
            self.enabled = False
            return []

        records.sort(key=lambda record: int(record.get("RecordId") or 0))
        events: list[Event] = []
        for record in records:
            record_id = _safe_int(str(record.get("RecordId", "")))
            if record_id is None:
                continue
            if self._last_record_id is not None and record_id <= self._last_record_id:
                continue
            self._last_record_id = record_id
            if self._first_poll and self.baseline_existing_on_start:
                continue
            events.append(self._record_to_event(record))

        self._first_poll = False
        return events

    def _read_failed_logons(self) -> list[dict[str, Any]]:
        script = (
            "$ErrorActionPreference='Stop';"
            f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} -MaxEvents {self.max_events} | "
            "Select-Object TimeCreated,Id,RecordId,ProviderName,Message | "
            "ConvertTo-Json -Depth 3 -Compress"
        )
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        if completed.returncode != 0:
            raise subprocess.SubprocessError(completed.stderr.strip() or "Get-WinEvent failed")
        payload = completed.stdout.strip()
        if not payload:
            return []
        data = json.loads(payload)
        if isinstance(data, dict):
            return [data]
        return list(data)

    def _record_to_event(self, record: dict[str, Any]) -> Event:
        message = str(record.get("Message") or "")
        username = _regex_first(message, r"Account Name:\s+([^\r\n]+)")
        remote_ip = _regex_first(message, r"Source Network Address:\s+([^\r\n]+)")
        return Event(
            kind="auth_failure",
            source=self.name,
            timestamp=parse_timestamp(str(record.get("TimeCreated"))) if record.get("TimeCreated") else utc_now(),
            attributes={
                "event_id": record.get("Id"),
                "record_id": record.get("RecordId"),
                "provider": record.get("ProviderName"),
                "username": username.strip() if username else None,
                "remote_ip": remote_ip.strip() if remote_ip else None,
                "message": message,
            },
        )


def _regex_first(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return None
    return match.group(1)


def build_collectors(
    network: NetworkConfig,
    process: ProcessConfig,
    auth: AuthConfig,
) -> list[Collector]:
    collectors: list[Collector] = []
    if network.enabled:
        collectors.append(NetworkConnectionCollector(network))
    if process.enabled:
        collectors.append(ProcessCollector(process))
    if auth.log_files:
        collectors.append(LogFileCollector(auth))
    if auth.windows_event_log_enabled:
        collectors.append(WindowsEventLogCollector(auth))
    return collectors
