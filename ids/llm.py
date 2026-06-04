from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import LlmConfig


_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
_SUSPICIOUS_PORTS = {21, 23, 2323, 3389, 4444, 5555, 5900, 6667, 6697, 31337}
_COMMON_REMOTE_SERVICE_PORTS = {53, 80, 123, 443, 853, 993, 995, 8080, 8443}
_SUSPICIOUS_PROCESS_NAMES = {
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
}
TRIAGE_SYSTEM_PROMPT = (
    "You are a local intrusion-detection triage assistant. Use only the supplied "
    "JSON and local triage context. Do not invent facts, IP addresses, ports, or "
    "process names. Start with a verdict, not a generic summary. Your first line "
    "must be exactly: Threat rating: <Likely benign|Low|Medium|High|Critical> "
    "(<0-10>/10) - <one sentence>. This is the only numeric rating in the answer. "
    "Then return sections named Evidence, Why this is probably okay, What would "
    "make it suspicious, Recommended next actions, and Confidence. Confidence "
    "must be High, Medium, or Low with a short reason; do not include a confidence "
    "score, percentage, or second x/10 value. If the event is TIME_WAIT, explain "
    "that TIME_WAIT is normal TCP cleanup and is not evidence by itself that the "
    "remote side initiated the connection. If a local port is ephemeral and the "
    "remote port is a common service port, treat it as likely outbound client "
    "traffic unless other evidence contradicts it. If PID is 0, say live process "
    "details are usually unavailable or not useful; do not make checking PID 0 "
    "the primary recommendation. Use the local threat rating as a guardrail unless "
    "the raw evidence clearly contradicts it."
)


@dataclass(frozen=True)
class LlmServerStatus:
    online: bool
    message: str
    models: tuple[str, ...] = ()
    loaded_models: tuple[str, ...] = ()
    model_available: bool = False
    loaded: bool = False


def analyze_security_payload(
    config: LlmConfig,
    item_type: str,
    payload: dict[str, Any],
) -> str:
    if not config.enabled:
        raise RuntimeError("LM Studio analysis is disabled in settings.")

    triage_context = build_triage_context(item_type, payload)
    request_payload = {
        "model": config.model,
        "system_prompt": TRIAGE_SYSTEM_PROMPT,
        "input": (
            f"Analyze this IDS {item_type}.\n\n"
            f"Local deterministic triage context:\n"
            f"{json.dumps(triage_context, indent=2, sort_keys=True, default=str)}\n\n"
            f"Raw IDS payload:\n"
            f"{json.dumps(payload, indent=2, sort_keys=True, default=str)}"
        ),
        "temperature": config.temperature,
        "max_output_tokens": config.max_tokens,
        "reasoning": "off",
        "stream": False,
        "store": False,
    }
    try:
        data = _post_chat_request(config, request_payload)
    except urllib.error.HTTPError as exc:
        body = exc.read(8192).decode("utf-8", errors="replace")
        detail = body.strip() or f"HTTP {exc.code}"
        if _reasoning_param_rejected(detail):
            request_payload.pop("reasoning", None)
            try:
                data = _post_chat_request(config, request_payload)
            except urllib.error.HTTPError as retry_exc:
                retry_body = retry_exc.read(8192).decode("utf-8", errors="replace")
                retry_detail = retry_body.strip() or f"HTTP {retry_exc.code}"
                raise RuntimeError(f"LM Studio request failed: {retry_detail}") from retry_exc
            except (OSError, TimeoutError, json.JSONDecodeError) as retry_exc:
                raise RuntimeError(f"LM Studio request failed: {retry_exc}") from retry_exc
        else:
            raise RuntimeError(f"LM Studio request failed: {detail}") from exc
    except (OSError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"LM Studio request failed: {exc}") from exc

    content = _extract_chat_content(data)
    if not content:
        if _has_reasoning_output(data):
            raise RuntimeError(
                "LM Studio generated reasoning tokens but no final answer. "
                "This usually happens with reasoning models when the output token limit is too low. "
                "Raise LM Studio max tokens in Settings or choose a non-reasoning/instruct model."
            )
        raise RuntimeError("LM Studio returned an empty response.")
    visible_content = _strip_thinking(content).strip()
    if not visible_content:
        raise RuntimeError(
            "LM Studio returned only a hidden thinking block and no final answer. "
            "Raise LM Studio max tokens in Settings or choose a non-reasoning/instruct model."
        )
    return visible_content


def _post_chat_request(config: LlmConfig, request_payload: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        config.url,
        data=json.dumps(request_payload).encode("utf-8"),
        headers=_headers(config),
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
        response_payload = response.read(1024 * 1024).decode("utf-8", errors="replace")
    data = json.loads(response_payload)
    if not isinstance(data, dict):
        raise RuntimeError("LM Studio returned an unexpected response shape.")
    return data


def _reasoning_param_rejected(detail: str) -> bool:
    try:
        payload = json.loads(detail)
    except json.JSONDecodeError:
        payload = {}
    error = payload.get("error") if isinstance(payload, dict) else {}
    if isinstance(error, dict) and error.get("param") == "reasoning":
        return True
    lowered = detail.lower()
    return "reasoning" in lowered and "invalid" in lowered


def build_triage_context(item_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    attrs = _payload_attributes(payload)
    rule_id = str(payload.get("rule_id") or "")
    severity = str(payload.get("severity") or "").lower()
    kind = str(payload.get("kind") or attrs.get("kind") or _first_event_kind(payload) or item_type)

    score = _base_score(item_type, rule_id, severity)
    notes: list[str] = []
    benign_signals: list[str] = []
    concern_signals: list[str] = []

    if attrs.get("policy_status") == "blocklisted" or rule_id == "blocklist_match":
        score += 4
        concern_signals.append("Blocklist policy matched.")

    process_names = _payload_process_names(payload, attrs)
    if process_names:
        notes.append(f"Likely owning process/application(s): {', '.join(process_names[:8])}.")

    suspicious_processes = [
        process_name
        for process_name in process_names
        if process_name.lower() in _SUSPICIOUS_PROCESS_NAMES
    ]
    if suspicious_processes or rule_id == "suspicious_process":
        score += 5
        observed = ", ".join(suspicious_processes) if suspicious_processes else rule_id
        concern_signals.append(f"Suspicious process name observed: {observed}.")

    if kind == "network_connection" or _has_network_attrs(attrs):
        network = _network_context(attrs)
        notes.extend(network["notes"])
        benign_signals.extend(network["benign_signals"])
        concern_signals.extend(network["concern_signals"])
        score += int(network["score_delta"])

    if rule_id == "port_scan":
        score += 4
        concern_signals.append("IDS rule indicates multiple local ports touched by the same actor.")
    elif rule_id == "brute_force":
        score += 4
        concern_signals.append("IDS rule indicates repeated authentication failures.")
    elif rule_id == "connection_burst":
        score += 2
        concern_signals.append("IDS rule indicates an unusual connection burst.")

    score = max(0, min(10, score))
    rating = _rating(score)
    if not concern_signals:
        concern_signals.append("No strong malicious indicator was present in the supplied payload.")
    if not benign_signals:
        benign_signals.append("No strong benign indicator was present in the supplied payload.")

    return {
        "item_type": item_type,
        "kind": kind,
        "rating": rating,
        "score_0_to_10": score,
        "likely_verdict": _verdict(score),
        "benign_signals": benign_signals,
        "concern_signals": concern_signals,
        "notes_for_model": notes,
        "analysis_instructions": [
            "Lead with whether this is probably okay, suspicious, or bad.",
            "Do not inflate routine cloud/CDN/OS-service traffic without supporting evidence.",
            "Recommend escalation only when the evidence supports it.",
        ],
    }


def check_lm_studio_server(config: LlmConfig, timeout_seconds: float = 1.0) -> LlmServerStatus:
    request = urllib.request.Request(
        models_url(config.url),
        headers=_headers(config),
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = response.read(512 * 1024).decode("utf-8", errors="replace")
        data = json.loads(payload)
    except urllib.error.HTTPError as exc:
        message = f"HTTP {exc.code}"
        if exc.code in {401, 403}:
            message = "authentication required or token rejected"
        return LlmServerStatus(False, message)
    except (OSError, TimeoutError) as exc:
        return LlmServerStatus(False, str(exc) or exc.__class__.__name__)
    except json.JSONDecodeError as exc:
        return LlmServerStatus(False, f"invalid JSON response: {exc}")

    models = data.get("models")
    if not isinstance(models, list):
        return LlmServerStatus(False, "models endpoint returned an unexpected shape")

    model_names: list[str] = []
    loaded_model_names: list[str] = []
    model_available = False
    loaded = False
    wanted = config.model.strip().lower()
    for model in models:
        if not isinstance(model, dict):
            continue
        names = [
            str(model.get("key") or ""),
            str(model.get("display_name") or ""),
            str(model.get("selected_variant") or ""),
        ]
        for variant in model.get("variants") or []:
            names.append(str(variant))
        public_name = next((name for name in names if name), "")
        if public_name:
            model_names.append(public_name)
            if model.get("loaded_instances"):
                loaded_model_names.append(public_name)
        normalized_names = {name.lower() for name in names if name}
        if wanted and wanted in normalized_names:
            model_available = True
            loaded = bool(model.get("loaded_instances"))

    if not model_names:
        return LlmServerStatus(True, "server online; no local models found")
    if loaded_model_names:
        loaded_text = f"{len(loaded_model_names)} loaded"
    else:
        loaded_text = "no loaded models"
    if model_available:
        message = "server online; configured model is loaded" if loaded else "server online; configured model is available"
    else:
        message = "server online; configured model was not listed"
    return LlmServerStatus(
        True,
        f"{message}; {loaded_text}",
        tuple(dict.fromkeys(model_names)),
        tuple(dict.fromkeys(loaded_model_names)),
        model_available,
        loaded,
    )


def models_url(chat_url: str) -> str:
    parsed = urllib.parse.urlparse(chat_url)
    if parsed.path.endswith("/api/v1/chat"):
        path = parsed.path[: -len("/chat")] + "/models"
    else:
        path = "/api/v1/models"
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, path, "", "", "")
    )


def _extract_chat_content(data: dict[str, Any]) -> str:
    output = data.get("output")
    if isinstance(output, list):
        content_parts = [
            _content_text(item.get("content"))
            for item in output
            if isinstance(item, dict)
            and item.get("type") == "message"
            and _content_text(item.get("content"))
        ]
        if content_parts:
            return "\n".join(content_parts)

    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if isinstance(message, dict):
        content = _content_text(message.get("content"))
        if content:
            return content
    text = first.get("text")
    return _content_text(text)


def _content_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    parts: list[str] = []
    for item in value:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            text = item.get("text") or item.get("content")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts)


def _has_reasoning_output(data: dict[str, Any]) -> bool:
    output = data.get("output")
    if isinstance(output, list):
        return any(isinstance(item, dict) and item.get("type") == "reasoning" for item in output)
    return False


def _strip_thinking(text: str) -> str:
    return _THINK_BLOCK_RE.sub("", text)


def _payload_attributes(payload: dict[str, Any]) -> dict[str, Any]:
    attrs = payload.get("attributes")
    if isinstance(attrs, dict):
        return dict(attrs)
    events = payload.get("events")
    if isinstance(events, list) and events:
        first = events[0]
        if isinstance(first, dict) and isinstance(first.get("attributes"), dict):
            return dict(first["attributes"])
    return {}


def _first_event_kind(payload: dict[str, Any]) -> str:
    events = payload.get("events")
    if isinstance(events, list) and events:
        first = events[0]
        if isinstance(first, dict):
            return str(first.get("kind") or "")
    return ""


def _payload_process_names(payload: dict[str, Any], attrs: dict[str, Any]) -> list[str]:
    names: list[str] = []
    _append_process_names(names, attrs)
    events = payload.get("events")
    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict) and isinstance(event.get("attributes"), dict):
                _append_process_names(names, event["attributes"])
    return list(dict.fromkeys(name for name in names if name))


def _append_process_names(names: list[str], attrs: dict[str, Any]) -> None:
    for key in ("process_name", "image_name"):
        value = attrs.get(key)
        if isinstance(value, str) and value.strip():
            names.append(value.strip())
    processes = attrs.get("processes")
    if isinstance(processes, list):
        for value in processes:
            if isinstance(value, str) and value.strip():
                names.append(_strip_pid_suffix(value.strip()))


def _strip_pid_suffix(value: str) -> str:
    return re.sub(r"\s+\(\d+\)$", "", value).strip()


def _base_score(item_type: str, rule_id: str, severity: str) -> int:
    if item_type == "risk host":
        return 4
    severity_scores = {
        "info": 1,
        "low": 2,
        "medium": 4,
        "high": 7,
        "critical": 9,
    }
    if severity in severity_scores:
        return severity_scores[severity]
    if rule_id:
        return 3
    return 1


def _network_context(attrs: dict[str, Any]) -> dict[str, Any]:
    local_port = _as_int(attrs.get("local_port"))
    remote_port = _as_int(attrs.get("remote_port"))
    pid = _as_int(attrs.get("pid"))
    state = str(attrs.get("state") or "").upper()
    remote_ip = str(attrs.get("remote_ip") or "")
    local_ip = str(attrs.get("local_ip") or "")
    remote_org = " ".join(
        str(attrs.get(key) or "")
        for key in ("remote_organization", "remote_isp", "remote_domain", "remote_asn")
    ).lower()
    direction = _connection_direction(local_port, remote_port)
    notes: list[str] = [f"Connection direction heuristic: {direction}."]
    benign_signals: list[str] = []
    concern_signals: list[str] = []
    score_delta = 0

    if state == "TIME_WAIT":
        benign_signals.append("TIME_WAIT is normal TCP connection cleanup after a session ends.")
        notes.append("Do not treat TIME_WAIT as proof of remote initiation.")
        score_delta -= 1

    if direction == "likely outbound client connection":
        benign_signals.append("Local ephemeral port paired with a common remote service port suggests outbound client traffic.")
        score_delta -= 1
    elif direction == "possibly inbound to local service":
        concern_signals.append("Remote host appears to connect to a local service port.")
        score_delta += 2

    if pid == 0:
        notes.append("PID 0 usually means no useful live user-process lookup is available for this event.")
        benign_signals.append("PID 0 alone is not evidence of malware.")

    if local_port in _SUSPICIOUS_PORTS or remote_port in _SUSPICIOUS_PORTS:
        concern_signals.append("Connection uses a port from the IDS suspicious-port list.")
        score_delta += 3

    remote_class = _ip_class(remote_ip)
    if remote_class:
        notes.append(f"Remote IP classification: {remote_class}.")
    if remote_class == "public/global" and any(name in remote_org for name in ("microsoft", "azure", "office")):
        benign_signals.append("Remote enrichment points to Microsoft/Azure/Office infrastructure; this is often normal.")
        score_delta -= 1
    elif remote_class == "public/global":
        notes.append("Public remote IP is not automatically bad; judge it with rule, process, volume, and reputation evidence.")

    local_class = _ip_class(local_ip)
    if local_ip and not local_class:
        notes.append(f"Local IP value appears invalid or unparsable: {local_ip!r}. Do not silently correct it.")

    return {
        "notes": notes,
        "benign_signals": benign_signals,
        "concern_signals": concern_signals,
        "score_delta": score_delta,
    }


def _has_network_attrs(attrs: dict[str, Any]) -> bool:
    return any(key in attrs for key in ("local_ip", "local_port", "remote_ip", "remote_port", "state"))


def _connection_direction(local_port: int | None, remote_port: int | None) -> str:
    if local_port is None or remote_port is None:
        return "unknown"
    if _is_ephemeral(local_port) and remote_port in _COMMON_REMOTE_SERVICE_PORTS:
        return "likely outbound client connection"
    if local_port < 49152 and _is_ephemeral(remote_port):
        return "possibly inbound to local service"
    if _is_ephemeral(local_port) and remote_port < 49152:
        return "likely outbound client connection"
    return "unknown"


def _is_ephemeral(port: int) -> bool:
    return 49152 <= port <= 65535


def _ip_class(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_global:
        return "public/global"
    if ip.is_reserved:
        return "reserved"
    return "special"


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rating(score: int) -> str:
    if score <= 1:
        return "Likely benign"
    if score <= 3:
        return "Low"
    if score <= 5:
        return "Medium"
    if score <= 8:
        return "High"
    return "Critical"


def _verdict(score: int) -> str:
    if score <= 1:
        return "probably okay"
    if score <= 3:
        return "low concern; verify if unexpected or frequent"
    if score <= 5:
        return "suspicious enough to review"
    if score <= 8:
        return "likely security-relevant"
    return "treat as urgent"


def _headers(config: LlmConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.api_token:
        headers["Authorization"] = f"Bearer {config.api_token}"
    return headers
