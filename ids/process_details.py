from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from pathlib import Path
from typing import Any


def get_process_details(pid: int, timeout_seconds: float = 2.5) -> dict[str, Any]:
    if platform.system().lower() == "windows":
        return _get_windows_process_details(pid, timeout_seconds)
    return _get_posix_process_details(pid, timeout_seconds)


def _get_windows_process_details(pid: int, timeout_seconds: float) -> dict[str, Any]:
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$p=Get-CimInstance Win32_Process -Filter \"ProcessId={int(pid)}\";"
        "if ($null -eq $p) { '{}' } else {"
        "$owner=$p | Invoke-CimMethod -MethodName GetOwner;"
        "[PSCustomObject]@{"
        "pid=$p.ProcessId;"
        "parent_pid=$p.ParentProcessId;"
        "image_name=$p.Name;"
        "path=$p.ExecutablePath;"
        "command_line=$p.CommandLine;"
        "user=($owner.Domain + '\\' + $owner.User);"
        "creation_date=$p.CreationDate"
        "} | ConvertTo-Json -Compress -Depth 3"
        "}"
    )
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        return {}
    try:
        details = json.loads(completed.stdout.strip())
    except json.JSONDecodeError:
        return {}
    if not isinstance(details, dict):
        return {}
    return _with_file_hash(details)


def _get_posix_process_details(pid: int, timeout_seconds: float) -> dict[str, Any]:
    completed = subprocess.run(
        ["ps", "-p", str(int(pid)), "-o", "pid=,ppid=,user=,comm=,args="],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    line = completed.stdout.strip()
    if completed.returncode != 0 or not line:
        return {}
    parts = line.split(None, 4)
    if len(parts) < 4:
        return {}
    details: dict[str, Any] = {
        "pid": _safe_int(parts[0]),
        "parent_pid": _safe_int(parts[1]),
        "user": parts[2],
        "image_name": parts[3],
        "command_line": parts[4] if len(parts) > 4 else "",
    }
    return details


def _with_file_hash(details: dict[str, Any]) -> dict[str, Any]:
    path = details.get("path")
    if not isinstance(path, str) or not path:
        return details
    try:
        file_path = Path(path)
        if file_path.exists() and file_path.is_file() and file_path.stat().st_size <= 256 * 1024 * 1024:
            digest = hashlib.sha256()
            with file_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            details["sha256"] = digest.hexdigest()
    except OSError:
        pass
    return details


def _safe_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
