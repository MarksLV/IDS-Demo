from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone

from .config import AppConfig, load_config
from .engine import IntrusionDetectionSystem, RuntimeSnapshot, load_events_jsonl
from .models import Alert, Severity


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command or "monitor"

    try:
        config = load_config(getattr(args, "config", None) or "config/default.json")
    except Exception as exc:
        print(f"Could not load configuration: {exc}", file=sys.stderr)
        return 2

    if command == "monitor":
        return run_monitor(config, args)
    if command == "replay":
        return run_replay(config, args)
    if command == "gui":
        from .gui import run_gui

        return run_gui(config, getattr(args, "config", None) or "config/default.json")
    if command == "show-config":
        print(json.dumps(config.raw, indent=2, sort_keys=True))
        return 0

    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids",
        description="Lightweight host-based intrusion detection system.",
    )
    add_config_argument(parser)
    add_monitor_arguments(parser)
    subparsers = parser.add_subparsers(dest="command")

    monitor = subparsers.add_parser("monitor", help="Monitor this host.")
    add_config_argument(monitor)
    add_monitor_arguments(monitor)

    replay = subparsers.add_parser("replay", help="Replay JSONL events through the rules.")
    add_config_argument(replay)
    replay.add_argument("path", help="Path to a JSONL event file.")
    replay.add_argument("--json", action="store_true", help="Print full alert JSON.")
    replay.add_argument(
        "--write-logs",
        action="store_true",
        help="Append replay events and alerts to the configured output logs.",
    )

    gui = subparsers.add_parser("gui", help="Open the desktop GUI.")
    add_config_argument(gui)

    show_config = subparsers.add_parser("show-config", help="Print the resolved configuration.")
    add_config_argument(show_config)
    return parser


def add_config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--config",
        default=argparse.SUPPRESS,
        help="Path to a JSON configuration file.",
    )


def add_monitor_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--duration", type=float, default=None, help="Stop after this many seconds.")
    parser.add_argument("--no-dashboard", action="store_true", help="Print alerts instead of drawing a dashboard.")


def run_monitor(config: AppConfig, args: argparse.Namespace) -> int:
    ids = IntrusionDetectionSystem(config)
    dashboard_enabled = config.dashboard.enabled and not args.no_dashboard
    started = time.monotonic()
    next_draw = 0.0

    try:
        while True:
            alerts = ids.tick()
            if dashboard_enabled:
                now = time.monotonic()
                if now >= next_draw:
                    draw_dashboard(ids.snapshot())
                    next_draw = now + config.dashboard.refresh_seconds
            else:
                for alert in alerts:
                    print(format_alert(alert))
            if args.duration is not None and time.monotonic() - started >= args.duration:
                if dashboard_enabled:
                    draw_dashboard(ids.snapshot())
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        if dashboard_enabled:
            draw_dashboard(ids.snapshot())
        print("\nMonitoring stopped.")
    finally:
        ids.close()
    return 0


def run_replay(config: AppConfig, args: argparse.Namespace) -> int:
    write_logs = getattr(args, "write_logs", False)
    replay_config = config if write_logs else _without_replay_side_effects(config)
    ids = IntrusionDetectionSystem(replay_config, load_history=write_logs)
    try:
        events = load_events_jsonl(args.path)
        alerts = ids.replay(events)
        if args.json:
            for alert in alerts:
                print(json.dumps(alert.to_dict(), sort_keys=True))
        else:
            for alert in alerts:
                print(format_alert(alert))
            print(f"\nReplayed {len(events)} events and produced {len(alerts)} alerts.")
        return 0
    finally:
        ids.close()


def _without_replay_side_effects(config: AppConfig) -> AppConfig:
    output = replace(config.output, events_path=None, alerts_path=None)
    ip_intelligence = replace(config.ip_intelligence, enabled=False)
    raw = json.loads(json.dumps(config.raw))
    raw.setdefault("output", {})
    raw["output"]["events_path"] = None
    raw["output"]["alerts_path"] = None
    raw.setdefault("ip_intelligence", {})
    raw["ip_intelligence"]["enabled"] = False
    return replace(config, output=output, ip_intelligence=ip_intelligence, raw=raw)


def draw_dashboard(snapshot: RuntimeSnapshot) -> None:
    clear_screen()
    runtime_seconds = int((datetime.now(timezone.utc) - snapshot.started_at).total_seconds())
    print("Intrusion Detection System")
    print("=" * 72)
    print(f"Runtime: {runtime_seconds}s")
    print(f"Collectors: {', '.join(snapshot.collectors) if snapshot.collectors else 'none'}")
    print(f"Events processed: {snapshot.total_events}")
    print(f"Alerts raised: {snapshot.total_alerts}")
    if snapshot.warnings:
        print("\nWarnings:")
        for warning in snapshot.warnings[-3:]:
            print(f"  - {warning}")
    print("\nRecent alerts:")
    if not snapshot.recent_alerts:
        print("  No alerts yet.")
    else:
        for alert in reversed(snapshot.recent_alerts[-10:]):
            print("  " + format_alert(alert))
    print("\nRecent events:")
    if not snapshot.recent_events:
        print("  Waiting for new activity...")
    else:
        for event in reversed(snapshot.recent_events[-8:]):
            attrs = event.attributes
            if event.kind == "network_connection":
                remote = format_ip_with_country(attrs, "remote")
                detail = (
                    f"{remote}:{attrs.get('remote_port')} -> "
                    f"{attrs.get('local_ip')}:{attrs.get('local_port')} "
                    f"{attrs.get('state')}"
                )
            elif event.kind == "process_start":
                detail = f"{attrs.get('image_name')} pid={attrs.get('pid')}"
            else:
                detail = str(attrs)[:100]
            print(f"  {event.timestamp.strftime('%H:%M:%S')} {event.kind}: {detail}")
    print("\nPress Ctrl+C to stop.")


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def format_alert(alert: Alert) -> str:
    stamp = alert.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    return f"[{stamp}] {alert.severity.name:<8} {alert.title}: {alert.description}"


def format_ip_with_country(attrs: dict[str, object], prefix: str) -> str:
    ip = str(attrs.get(f"{prefix}_ip") or "unknown")
    country = attrs.get(f"{prefix}_country")
    country_code = attrs.get(f"{prefix}_country_code")
    if not country or country == "Unknown":
        return ip
    if country_code and country_code not in {"ZZ", "UN"}:
        return f"{ip} ({country_code})"
    return f"{ip} ({country})"


if __name__ == "__main__":
    raise SystemExit(main())
