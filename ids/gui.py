from __future__ import annotations

import ctypes
import platform
import queue
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

from .actions import (
    block_ip_windows_firewall,
    can_manage_windows_firewall,
    export_report,
    is_running_as_admin,
    selected_process_details,
    unblock_ip_windows_firewall,
)
from .app_icons import executable_icon_data
from .browser_context import browser_context_lines_for_process, is_browser_process_name
from .process_details import get_process_details
from .config import AppConfig, load_config, save_config
from .engine import IntrusionDetectionSystem, RuntimeSnapshot, load_events_jsonl
from .ip_intel import IpIntelligence
from .llm import LlmServerStatus, analyze_security_payload, check_lm_studio_server
from .models import Alert, Event, Severity
from .policy import SecurityPolicy
from .ui_formatters import (
    _as_pid,
    _detail_lines,
    alert_origin,
    alert_row,
    country_label,
    country_label_from_info,
    event_detail,
    event_item_id,
    event_row,
    event_signature,
    format_duration,
    format_flag,
    format_optional,
    format_timestamp,
    ip_info_lines,
    local_label,
    process_label,
    split_csv,
    with_country,
)


LIGHT_COLORS = {
    "bg": "#eef3f8",
    "chrome": "#f7f9fc",
    "titlebar": "#f7f9fc",
    "titlebar_text": "#111827",
    "titlebar_muted": "#64748b",
    "control_hover": "#e5edf6",
    "close_hover": "#dc2626",
    "close_hover_text": "#ffffff",
    "panel": "#ffffff",
    "panel_alt": "#f5f8fb",
    "surface": "#ffffff",
    "surface_high": "#f8fafc",
    "border": "#d5dee9",
    "border_soft": "#e7edf4",
    "text": "#111827",
    "muted": "#64748b",
    "accent": "#3867f4",
    "accent_hover": "#2850d8",
    "accent_soft": "#e6eeff",
    "teal": "#0f8a83",
    "teal_hover": "#0d716c",
    "teal_soft": "#dff7f4",
    "amber": "#c47b0a",
    "amber_soft": "#fff4d6",
    "danger": "#dc2626",
    "danger_hover": "#b91c1c",
    "danger_soft": "#ffe5e7",
    "critical_text": "#991b1b",
    "high_text": "#9a3412",
    "high_soft": "#ffedd5",
    "medium_text": "#b45309",
    "selection": "#dbe8ff",
    "disabled": "#94a3b8",
}

NIGHT_COLORS = {
    "bg": "#0c0714",
    "chrome": "#120b1f",
    "titlebar": "#10091c",
    "titlebar_text": "#f5f3ff",
    "titlebar_muted": "#a89ac4",
    "control_hover": "#211633",
    "close_hover": "#e54868",
    "close_hover_text": "#ffffff",
    "panel": "#151022",
    "panel_alt": "#1b132c",
    "surface": "#171225",
    "surface_high": "#211833",
    "border": "#352449",
    "border_soft": "#271b3a",
    "text": "#f4f0ff",
    "muted": "#b3a7c8",
    "accent": "#8b5cf6",
    "accent_hover": "#7c3aed",
    "accent_soft": "#2a1c46",
    "teal": "#14b8a6",
    "teal_hover": "#0d9488",
    "teal_soft": "#123c3c",
    "amber": "#f59e0b",
    "amber_soft": "#3f2b12",
    "danger": "#f43f5e",
    "danger_hover": "#e11d48",
    "danger_soft": "#3b1020",
    "critical_text": "#fecaca",
    "high_text": "#fed7aa",
    "high_soft": "#431407",
    "medium_text": "#fde68a",
    "selection": "#3b2167",
    "disabled": "#6f6381",
}

COLORS = dict(LIGHT_COLORS)

FONT = "Segoe UI"


def _colors_for_theme(theme: str) -> dict[str, str]:
    return NIGHT_COLORS if theme == "night" else LIGHT_COLORS


def _theme_label(theme: str) -> str:
    return "Night" if theme == "night" else "Light"


def _theme_from_label(label: str) -> str:
    return "night" if label.strip().lower() == "night" else "light"


def _hex_to_rgb(color: str) -> tuple[int, int, int]:
    value = color.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def _rgb_to_hex(red: int, green: int, blue: int) -> str:
    return f"#{red:02x}{green:02x}{blue:02x}"


def _mix_color(start: str, end: str, amount: float) -> str:
    start_rgb = _hex_to_rgb(start)
    end_rgb = _hex_to_rgb(end)
    mixed = tuple(
        round(start_value + (end_value - start_value) * amount)
        for start_value, end_value in zip(start_rgb, end_rgb)
    )
    return _rgb_to_hex(*mixed)


def _mix_theme_colors(start: dict[str, str], end: dict[str, str], amount: float) -> dict[str, str]:
    return {
        key: _mix_color(start[key], end[key], amount)
        for key in start
        if key in end and start[key].startswith("#") and end[key].startswith("#")
    }


class MonitorWorker:
    def __init__(self, config: AppConfig) -> None:
        self.ids = IntrusionDetectionSystem(config)
        self.stop_event = threading.Event()
        self.errors: queue.SimpleQueue[str] = queue.SimpleQueue()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.running:
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="IDSMonitor", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def shutdown(self) -> None:
        self.stop()
        if self.thread is not None:
            self.thread.join(timeout=0.5)
        self.ids.close()

    @property
    def running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def snapshot(self) -> RuntimeSnapshot:
        return self.ids.snapshot()

    def replay_file(self, path: str | Path) -> int:
        events = load_events_jsonl(path)
        self.ids.replay(events)
        return len(events)

    def discard_oldest_events(self, count: int) -> int:
        return self.ids.discard_oldest_events(count)

    def discard_oldest_alerts(self, count: int) -> int:
        return self.ids.discard_oldest_alerts(count)

    def clear_events(self) -> int:
        return self.ids.clear_events()

    def clear_alerts(self) -> int:
        return self.ids.clear_alerts()

    def reset_summary(self) -> None:
        self.ids.reset_summary()

    def pop_errors(self) -> list[str]:
        errors: list[str] = []
        while True:
            try:
                errors.append(self.errors.get_nowait())
            except queue.Empty:
                return errors

    def _run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.ids.tick()
            except Exception as exc:  # pragma: no cover - protects GUI runtime.
                self.errors.put(str(exc))
                self.stop_event.set()
                break
            self.stop_event.wait(0.2)


class ToolTip:
    def __init__(self, widget: tk.Widget, text: str, delay_ms: int = 450) -> None:
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self.enabled = True
        self._after_id: str | None = None
        self._window: tk.Toplevel | None = None
        widget.bind("<Enter>", self._schedule)
        widget.bind("<Leave>", self._hide)
        widget.bind("<ButtonPress>", self._hide)

    def _schedule(self, _event: tk.Event) -> None:
        if not self.enabled or not self.text:
            return
        self._cancel()
        self._after_id = self.widget.after(self.delay_ms, self._show)

    def _show(self) -> None:
        self._after_id = None
        if not self.enabled or not self.text or self._window is not None:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self._window = tk.Toplevel(self.widget)
        self._window.wm_overrideredirect(True)
        self._window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self._window,
            text=self.text,
            padx=10,
            pady=7,
            relief=tk.SOLID,
            borderwidth=1,
            background=COLORS["panel"],
            foreground=COLORS["text"],
            highlightbackground=COLORS["border"],
            font=(FONT, 9),
        )
        label.pack()

    def _hide(self, _event: tk.Event | None = None) -> None:
        self._cancel()
        if self._window is not None:
            self._window.destroy()
            self._window = None

    def _cancel(self) -> None:
        if self._after_id is not None:
            self.widget.after_cancel(self._after_id)
            self._after_id = None

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled
        if not enabled:
            self._hide()


class IntrusionDetectionGui:
    def __init__(self, root: tk.Tk, config: AppConfig, config_path: str) -> None:
        self.root = root
        self.config = config
        self.config_path = config_path
        COLORS.clear()
        COLORS.update(_colors_for_theme(config.ui.theme))
        self.worker = MonitorWorker(config)
        self.is_admin = is_running_as_admin()
        self.can_manage_firewall = can_manage_windows_firewall()
        self.alerts_by_id: dict[str, Alert] = {}
        self.events_by_item: dict[str, Event] = {}
        self.ip_info_by_ip: dict[str, IpIntelligence] = {}
        self.last_event_total = -1
        self.last_alert_total = -1
        self.last_ip_intelligence_version = -1
        self.last_risk_signature = ""
        self.last_warning_text = ""
        self.alert_detail_item_id = ""
        self.event_detail_item_id = ""
        self.refreshing_alert_tree = False
        self.refreshing_event_tree = False
        self.llm_server_status: LlmServerStatus | None = None
        self.llm_status_results: queue.SimpleQueue[LlmServerStatus] = queue.SimpleQueue()
        self.llm_status_checking = False
        self.last_llm_status_check = 0.0
        self.browser_context_results: queue.SimpleQueue[tuple[int, tuple[str, ...]]] = queue.SimpleQueue()
        self.browser_context_cache: dict[int, tuple[float, tuple[str, ...]]] = {}
        self.browser_context_pending: set[int] = set()
        self.app_icon_images: dict[str, tk.PhotoImage] = {}
        self.app_icon_results: queue.SimpleQueue[tuple[str, str | None]] = queue.SimpleQueue()
        self.app_icon_pending: set[str] = set()
        self.app_icon_failed: set[str] = set()
        self.nav_buttons: dict[str, tk.Button] = {}
        self.tab_frames: dict[str, ttk.Frame] = {}
        self.lm_analyze_buttons: list[ttk.Button] = []
        self.lm_analyze_tooltips: list[ToolTip] = []
        self.process_detail_buttons: list[ttk.Button] = []
        self.process_detail_tooltips: list[ToolTip] = []
        self.current_tab = "summary"
        self.theme_transition_after_id: str | None = None
        self.theme_transition_running = False
        self.chart_resize_after_id: str | None = None
        self.pending_resize_geometry = ""
        self.resize_after_id: str | None = None
        self._drag_offset_x = 0
        self._drag_offset_y = 0
        self._resize_start: tuple[int, int, int, int] | None = None
        self.maximized = False

        self.root.withdraw()
        self.root.title("Intrusion Detection System")
        self.root.geometry("1360x860")
        self.root.minsize(1120, 720)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.overrideredirect(True)
        self.root.bind("<Map>", self._restore_borderless_after_minimize)
        self.root.bind("<Alt-F4>", lambda _event: self.close())

        self._create_variables()
        self._configure_style()
        self._build_layout()
        self._show_ready_window()
        self.worker.start()
        self._schedule_update()

    def _create_variables(self) -> None:
        self.status_var = tk.StringVar(value="Running")
        self.runtime_var = tk.StringVar(value="0s")
        self.events_var = tk.StringVar(value="0")
        self.alerts_var = tk.StringVar(value="0")
        self.collectors_var = tk.StringVar(value="none")
        self.geoip_var = tk.StringVar(value=self._geoip_status())
        self.ip_intel_var = tk.StringVar(value=self._ip_intelligence_status())
        self.ip_api_rate_var = tk.StringVar(value=self._ip_api_rate_status())
        self.process_details_var = tk.StringVar(value=self._process_details_status())
        self.events_path_var = tk.StringVar(value=str(self.config.output.events_path or "disabled"))
        self.alerts_path_var = tk.StringVar(value=str(self.config.output.alerts_path or "disabled"))
        self.admin_var = tk.StringVar(value="administrator" if self.is_admin else "standard user")
        self.llm_var = tk.StringVar(value=self._llm_status())
        self.theme_var = tk.StringVar(value=_theme_label(self.config.ui.theme))
        self.event_wipe_var = tk.StringVar(value="100")
        self.alert_wipe_var = tk.StringVar(value="25")

    def _configure_style(self) -> None:
        self.root.configure(background=COLORS["bg"])
        self.root.option_add("*Font", f"{{{FONT}}} 10")
        self.root.option_add("*TCombobox*Listbox.background", COLORS["panel_alt"])
        self.root.option_add("*TCombobox*Listbox.foreground", COLORS["text"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", COLORS["selection"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", COLORS["text"])
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self.style = style

        style.configure(".", font=(FONT, 10), background=COLORS["bg"], foreground=COLORS["text"], borderwidth=0)
        style.configure("App.TFrame", background=COLORS["bg"])
        style.configure("Chrome.TFrame", background=COLORS["chrome"])
        style.configure("Header.TFrame", background=COLORS["chrome"])
        style.configure("Tab.TFrame", background=COLORS["surface"])
        style.configure("PanelBody.TFrame", background=COLORS["surface"])
        style.configure("PanelHeader.TFrame", background=COLORS["surface"])
        style.configure(
            "Panel.TFrame",
            background=COLORS["surface"],
            bordercolor=COLORS["border_soft"],
            lightcolor=COLORS["border_soft"],
            darkcolor=COLORS["border_soft"],
            borderwidth=1,
            relief=tk.SOLID,
        )
        style.configure(
            "Metric.TFrame",
            background=COLORS["surface"],
            bordercolor=COLORS["border_soft"],
            lightcolor=COLORS["border_soft"],
            darkcolor=COLORS["border_soft"],
            borderwidth=1,
            relief=tk.SOLID,
        )
        style.configure("TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=(FONT, 10))
        style.configure("Title.TLabel", background=COLORS["chrome"], foreground=COLORS["text"], font=(FONT, 20, "bold"))
        style.configure("Subtitle.TLabel", background=COLORS["chrome"], foreground=COLORS["muted"], font=(FONT, 9))
        style.configure("Status.TLabel", background=COLORS["panel"], foreground=COLORS["text"], font=(FONT, 10, "bold"))
        style.configure("MetricName.TLabel", background=COLORS["surface"], foreground=COLORS["muted"], font=(FONT, 9, "bold"))
        style.configure("DisabledMetricName.TLabel", background=COLORS["surface"], foreground=COLORS["disabled"], font=(FONT, 9, "bold"))
        style.configure("MetricValue.TLabel", background=COLORS["surface"], foreground=COLORS["text"], font=(FONT, 17, "bold"))
        style.configure("Muted.TLabel", background=COLORS["panel"], foreground=COLORS["muted"])
        style.configure("PanelTitle.TLabel", background=COLORS["surface"], foreground=COLORS["text"], font=(FONT, 10, "bold"))

        style.configure(
            "Panel.TLabelframe",
            background=COLORS["surface"],
            bordercolor=COLORS["border_soft"],
            lightcolor=COLORS["border_soft"],
            darkcolor=COLORS["border_soft"],
            borderwidth=1,
            relief=tk.SOLID,
        )
        style.configure(
            "Panel.TLabelframe.Label",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            font=(FONT, 10, "bold"),
        )

        style.configure(
            "TButton",
            background=COLORS["panel_alt"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border_soft"],
            lightcolor=COLORS["border_soft"],
            darkcolor=COLORS["border_soft"],
            focusthickness=1,
            focuscolor=COLORS["accent"],
            padding=(13, 8),
            relief=tk.FLAT,
            font=(FONT, 9, "bold"),
        )
        style.map(
            "TButton",
            background=[("active", COLORS["accent_soft"]), ("disabled", COLORS["panel_alt"])],
            foreground=[("disabled", COLORS["disabled"])],
        )
        style.configure("Primary.TButton", background=COLORS["accent"], foreground="#ffffff", bordercolor=COLORS["accent"])
        style.map(
            "Primary.TButton",
            background=[("active", COLORS["accent_hover"]), ("disabled", COLORS["panel_alt"])],
            foreground=[("disabled", COLORS["disabled"])],
        )
        style.configure("Danger.TButton", background=COLORS["danger"], foreground="#ffffff", bordercolor=COLORS["danger"])
        style.map(
            "Danger.TButton",
            background=[("active", COLORS["danger_hover"]), ("disabled", COLORS["panel_alt"])],
            foreground=[("disabled", COLORS["disabled"])],
        )
        style.configure("Accent.TButton", background=COLORS["teal"], foreground="#ffffff", bordercolor=COLORS["teal"])
        style.map(
            "Accent.TButton",
            background=[("active", COLORS["teal_hover"]), ("disabled", COLORS["panel_alt"])],
            foreground=[("disabled", COLORS["disabled"])],
        )

        style.configure(
            "TEntry",
            fieldbackground=COLORS["panel"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["border"],
            darkcolor=COLORS["border"],
            padding=(9, 6),
        )
        style.map(
            "TEntry",
            fieldbackground=[("disabled", COLORS["panel"])],
            foreground=[("disabled", COLORS["disabled"])],
            bordercolor=[("focus", COLORS["accent"])],
        )
        style.configure(
            "TCombobox",
            fieldbackground=COLORS["panel"],
            background=COLORS["panel_alt"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["border"],
            darkcolor=COLORS["border"],
            arrowcolor=COLORS["muted"],
            padding=(6, 4),
        )
        style.map(
            "TCombobox",
            background=[("disabled", COLORS["panel_alt"]), ("active", COLORS["surface_high"]), ("readonly", COLORS["panel_alt"])],
            fieldbackground=[("disabled", COLORS["panel"]), ("readonly", COLORS["panel"])],
            foreground=[("disabled", COLORS["disabled"]), ("readonly", COLORS["text"])],
            selectbackground=[("disabled", COLORS["panel"]), ("readonly", COLORS["selection"])],
            selectforeground=[("disabled", COLORS["disabled"]), ("readonly", COLORS["text"])],
            arrowcolor=[("disabled", COLORS["disabled"]), ("active", COLORS["text"]), ("readonly", COLORS["muted"])],
        )
        style.configure(
            "TCheckbutton",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            focuscolor=COLORS["accent"],
            padding=(0, 4),
        )
        style.map(
            "TCheckbutton",
            background=[("active", COLORS["surface_high"]), ("selected", COLORS["surface"])],
            foreground=[("active", COLORS["text"]), ("disabled", COLORS["disabled"])],
        )

        style.configure(
            "Vertical.TScrollbar",
            background=COLORS["panel_alt"],
            troughcolor=COLORS["surface"],
            bordercolor=COLORS["border_soft"],
            lightcolor=COLORS["border_soft"],
            darkcolor=COLORS["border_soft"],
            arrowcolor=COLORS["muted"],
            width=12,
            relief=tk.FLAT,
        )
        style.map(
            "Vertical.TScrollbar",
            background=[("active", COLORS["accent_soft"])],
            arrowcolor=[("active", COLORS["text"])],
        )

        style.configure(
            "Treeview",
            background=COLORS["panel"],
            fieldbackground=COLORS["panel"],
            foreground=COLORS["text"],
            bordercolor=COLORS["panel"],
            lightcolor=COLORS["panel"],
            darkcolor=COLORS["panel"],
            focuscolor=COLORS["panel"],
            borderwidth=0,
            relief=tk.FLAT,
            rowheight=31,
            font=(FONT, 9),
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["panel_alt"],
            foreground=COLORS["muted"],
            bordercolor=COLORS["panel_alt"],
            lightcolor=COLORS["panel_alt"],
            darkcolor=COLORS["panel_alt"],
            borderwidth=0,
            relief=tk.FLAT,
            padding=(8, 7),
            font=(FONT, 9, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", COLORS["selection"])],
            foreground=[("selected", COLORS["text"])],
            bordercolor=[("focus", COLORS["panel"]), ("!focus", COLORS["panel"])],
            lightcolor=[("focus", COLORS["panel"]), ("!focus", COLORS["panel"])],
            darkcolor=[("focus", COLORS["panel"]), ("!focus", COLORS["panel"])],
        )
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    def _build_layout(self) -> None:
        self.shell_frame = tk.Frame(
            self.root,
            background=COLORS["chrome"],
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )
        self.shell_frame.pack(fill=tk.BOTH, expand=True)
        self._build_title_bar(self.shell_frame)

        container = ttk.Frame(self.shell_frame, padding=(16, 10, 16, 16), style="Chrome.TFrame")
        container.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(container, style="Header.TFrame")
        top.pack(fill=tk.X, pady=(0, 6))

        title_area = ttk.Frame(top, style="Header.TFrame")
        title_area.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(title_area, text="Security Overview", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            title_area,
            text=f"Config: {self.config_path}",
            style="Subtitle.TLabel",
        ).pack(anchor=tk.W, pady=(2, 0))

        controls = ttk.Frame(top, style="Header.TFrame")
        controls.pack(side=tk.RIGHT)
        self.theme_button = tk.Button(
            controls,
            command=self.toggle_theme,
            width=3,
            height=1,
            borderwidth=0,
            relief=tk.FLAT,
            cursor="hand2",
            font=(FONT, 13, "bold"),
        )
        self.theme_button.pack(side=tk.LEFT, padx=(0, 8))
        self.theme_tooltip = ToolTip(self.theme_button, "")
        self._refresh_theme_button()
        self.start_button = ttk.Button(controls, text="Pause", command=self.toggle_monitor, style="Primary.TButton")
        self.start_button.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(controls, text="Replay Sample", command=self.replay_sample).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(controls, text="Load Replay...", command=self.load_replay).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(controls, text="Export Report", command=self.export_current_report, style="Accent.TButton").pack(side=tk.LEFT)

        metrics = ttk.Frame(container, style="App.TFrame")
        metrics.pack(fill=tk.X, pady=(14, 12))
        self._add_metric(metrics, "Status", self.status_var, 0)
        self._add_metric(metrics, "Runtime", self.runtime_var, 1)
        self._add_metric(metrics, "Events", self.events_var, 2)
        self._add_metric(metrics, "Alerts", self.alerts_var, 3)
        self._add_metric(metrics, "Collectors", self.collectors_var, 4, weight=2)
        self._add_metric(metrics, "GeoIP", self.geoip_var, 5, weight=2)
        self._add_metric(metrics, "IP API", self.ip_intel_var, 6, weight=2)

        self._build_navigation(container)

        content = ttk.Frame(container, style="Chrome.TFrame")
        content.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        summary_tab = ttk.Frame(content, padding=12, style="Tab.TFrame")
        alerts_tab = ttk.Frame(content, padding=12, style="Tab.TFrame")
        events_tab = ttk.Frame(content, padding=12, style="Tab.TFrame")
        system_tab = ttk.Frame(content, padding=12, style="Tab.TFrame")
        settings_tab = ttk.Frame(content, padding=12, style="Tab.TFrame")
        self.tab_frames = {
            "summary": summary_tab,
            "alerts": alerts_tab,
            "events": events_tab,
            "system": system_tab,
            "settings": settings_tab,
        }
        self._build_summary_tab(summary_tab)
        self._build_alerts_tab(alerts_tab)
        self._build_events_tab(events_tab)
        self._build_system_tab(system_tab)
        self._build_settings_tab(settings_tab)
        self._select_tab("summary")
        self._build_resize_grip(self.shell_frame)

    def _show_ready_window(self) -> None:
        self.root.update_idletasks()
        self._configure_windows_taskbar_entry()
        self.root.deiconify()

    def _build_navigation(self, parent: ttk.Frame) -> None:
        self.nav_frame = tk.Frame(parent, background=COLORS["chrome"])
        self.nav_frame.pack(fill=tk.X, pady=(0, 2))
        tabs = (
            ("summary", "Summary"),
            ("alerts", "Alerts"),
            ("events", "Events"),
            ("system", "System"),
            ("settings", "Settings"),
        )
        for key, label in tabs:
            button = tk.Button(
                self.nav_frame,
                text=label,
                command=lambda name=key: self._select_tab(name),
                borderwidth=0,
                relief=tk.FLAT,
                padx=18,
                pady=8,
                font=(FONT, 9, "bold"),
                cursor="hand2",
            )
            button.pack(side=tk.LEFT, padx=(0, 8))
            button.bind("<Enter>", lambda _event, name=key: self._set_nav_hover(name, True))
            button.bind("<Leave>", lambda _event, name=key: self._set_nav_hover(name, False))
            self.nav_buttons[key] = button
        self._refresh_nav_buttons()

    def _select_tab(self, name: str) -> None:
        if name not in self.tab_frames:
            return
        for key, frame in self.tab_frames.items():
            if key == name:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()
        self.current_tab = name
        self._refresh_nav_buttons()

    def _set_nav_hover(self, name: str, hovering: bool) -> None:
        if name == self.current_tab:
            return
        button = self.nav_buttons.get(name)
        if button is None:
            return
        button.configure(
            background=COLORS["surface_high"] if hovering else COLORS["chrome"],
            foreground=COLORS["text"] if hovering else COLORS["muted"],
        )

    def _refresh_nav_buttons(self) -> None:
        for key, button in self.nav_buttons.items():
            selected = key == self.current_tab
            button.configure(
                background=COLORS["accent_soft"] if selected else COLORS["chrome"],
                foreground=COLORS["accent"] if selected else COLORS["muted"],
                activebackground=COLORS["surface_high"],
                activeforeground=COLORS["text"],
            )

    def _refresh_theme_button(self) -> None:
        button = getattr(self, "theme_button", None)
        if button is None:
            return
        is_night = self.config.ui.theme == "night"
        button.configure(
            text="☾" if is_night else "☀",
            background=COLORS["accent_soft"],
            foreground=COLORS["accent"],
            activebackground=COLORS["surface_high"],
            activeforeground=COLORS["text"],
            disabledforeground=COLORS["disabled"],
            state=tk.DISABLED if self.theme_transition_running else tk.NORMAL,
        )
        tooltip = getattr(self, "theme_tooltip", None)
        if tooltip is not None:
            tooltip.text = "Switch to light mode" if is_night else "Switch to night mode"

    def _build_title_bar(self, parent: tk.Widget) -> None:
        self.title_bar = tk.Frame(parent, background=COLORS["titlebar"], height=42)
        self.titlebar_color_widgets: list[tk.Widget] = [self.title_bar]
        self.title_bar.pack(fill=tk.X)
        self.title_bar.pack_propagate(False)
        self.title_bar.bind("<ButtonPress-1>", self._start_window_drag)
        self.title_bar.bind("<B1-Motion>", self._drag_window)
        self.title_bar.bind("<Double-Button-1>", lambda _event: self._toggle_maximize())

        brand = tk.Frame(self.title_bar, background=COLORS["titlebar"])
        self.titlebar_color_widgets.append(brand)
        brand.pack(side=tk.LEFT, fill=tk.Y, padx=(14, 0))
        brand.bind("<ButtonPress-1>", self._start_window_drag)
        brand.bind("<B1-Motion>", self._drag_window)
        brand.bind("<Double-Button-1>", lambda _event: self._toggle_maximize())

        self.brand_mark = tk.Canvas(
            brand,
            width=24,
            height=24,
            background=COLORS["titlebar"],
            highlightthickness=0,
        )
        self.brand_mark.pack(side=tk.LEFT, pady=9)
        self._draw_brand_mark()

        title_stack = tk.Frame(brand, background=COLORS["titlebar"])
        self.titlebar_color_widgets.append(title_stack)
        title_stack.pack(side=tk.LEFT, padx=(9, 0), pady=(5, 0))
        self.window_title_label = tk.Label(
            title_stack,
            text="Intrusion Detection System",
            background=COLORS["titlebar"],
            foreground=COLORS["titlebar_text"],
            font=(FONT, 10, "bold"),
        )
        self.window_title_label.pack(anchor=tk.W)
        self.window_subtitle_label = tk.Label(
            title_stack,
            text="Host monitor",
            background=COLORS["titlebar"],
            foreground=COLORS["titlebar_muted"],
            font=(FONT, 8),
        )
        self.window_subtitle_label.pack(anchor=tk.W)
        for widget in (title_stack, self.window_title_label, self.window_subtitle_label):
            widget.bind("<ButtonPress-1>", self._start_window_drag)
            widget.bind("<B1-Motion>", self._drag_window)
            widget.bind("<Double-Button-1>", lambda _event: self._toggle_maximize())

        self.window_controls = tk.Frame(self.title_bar, background=COLORS["titlebar"])
        self.titlebar_color_widgets.append(self.window_controls)
        self.window_controls.pack(side=tk.RIGHT, fill=tk.Y)
        self.minimize_button = self._titlebar_button("_", self._minimize_window)
        self.maximize_button = self._titlebar_button("[]", self._toggle_maximize)
        self.close_button = self._titlebar_button("X", self.close, close=True)

    def _titlebar_button(self, text: str, command: object, close: bool = False) -> tk.Button:
        button = tk.Button(
            self.window_controls,
            text=text,
            command=command,
            width=5,
            height=1,
            background=COLORS["titlebar"],
            foreground=COLORS["titlebar_text"],
            activebackground=COLORS["close_hover"] if close else COLORS["control_hover"],
            activeforeground=COLORS["close_hover_text"] if close else COLORS["titlebar_text"],
            borderwidth=0,
            relief=tk.FLAT,
            font=(FONT, 10, "bold"),
        )
        button.pack(side=tk.LEFT, fill=tk.Y)
        button.bind("<Enter>", lambda _event: button.configure(background=COLORS["close_hover"] if close else COLORS["control_hover"], foreground=COLORS["close_hover_text"] if close else COLORS["titlebar_text"]))
        button.bind("<Leave>", lambda _event: button.configure(background=COLORS["titlebar"], foreground=COLORS["titlebar_text"]))
        return button

    def _draw_brand_mark(self) -> None:
        if not hasattr(self, "brand_mark"):
            return
        self.brand_mark.delete("all")
        self.brand_mark.create_oval(2, 2, 22, 22, fill=COLORS["accent_soft"], outline=COLORS["border"])
        self.brand_mark.create_polygon(12, 5, 18, 8, 17, 16, 12, 20, 7, 16, 6, 8, fill=COLORS["accent"], outline="")

    def _build_resize_grip(self, parent: tk.Widget) -> None:
        self.resize_grip = tk.Frame(parent, width=16, height=16, cursor="size_nw_se", background=COLORS["chrome"])
        self.resize_grip.place(relx=1.0, rely=1.0, anchor=tk.SE)
        self.resize_grip.bind("<ButtonPress-1>", self._start_resize)
        self.resize_grip.bind("<B1-Motion>", self._resize_window)
        self.resize_grip.bind("<ButtonRelease-1>", self._finish_resize)

    def _add_metric(
        self,
        parent: ttk.Frame,
        name: str,
        variable: tk.StringVar,
        column: int,
        weight: int = 1,
    ) -> None:
        parent.columnconfigure(column, weight=weight, uniform="metrics")
        frame = ttk.Frame(parent, padding=(12, 10), style="Metric.TFrame")
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 8))
        ttk.Label(frame, text=name, style="MetricName.TLabel").pack(anchor=tk.W)
        ttk.Label(frame, textvariable=variable, style="MetricValue.TLabel").pack(anchor=tk.W)

    def _start_window_drag(self, event: tk.Event) -> None:
        if self.maximized:
            return
        self._drag_offset_x = event.x_root - self.root.winfo_x()
        self._drag_offset_y = event.y_root - self.root.winfo_y()

    def _drag_window(self, event: tk.Event) -> None:
        if self.maximized:
            return
        x = event.x_root - self._drag_offset_x
        y = event.y_root - self._drag_offset_y
        self.root.geometry(f"+{x}+{y}")

    def _minimize_window(self) -> None:
        self.root.overrideredirect(False)
        self.root.iconify()

    def _restore_borderless_after_minimize(self, _event: tk.Event | None = None) -> None:
        if self.root.state() == "normal":
            self.root.after(10, self._restore_borderless_window)

    def _restore_borderless_window(self) -> None:
        self.root.overrideredirect(True)
        self.root.update_idletasks()
        self._configure_windows_taskbar_entry()

    def _configure_windows_taskbar_entry(self) -> None:
        if platform.system().lower() != "windows":
            return
        try:
            user32 = ctypes.windll.user32
            window_id = self.root.winfo_id()
            wrapper_id = user32.GetParent(window_id) or window_id
            extended_style = user32.GetWindowLongW(wrapper_id, -20)
            extended_style = (extended_style & ~0x00000080) | 0x00040000
            user32.SetWindowLongW(wrapper_id, -20, extended_style)
            user32.SetWindowPos(wrapper_id, 0, 0, 0, 0, 0x0027)
        except (AttributeError, OSError, tk.TclError):
            return

    def _toggle_maximize(self) -> None:
        if self.maximized:
            self.root.state("normal")
            self.maximized = False
            self.maximize_button.configure(text="[]")
            return
        self.root.state("zoomed")
        self.maximized = True
        self.maximize_button.configure(text="<>")

    def _start_resize(self, event: tk.Event) -> None:
        if self.maximized:
            return
        self._resize_start = (
            event.x_root,
            event.y_root,
            self.root.winfo_width(),
            self.root.winfo_height(),
        )

    def _resize_window(self, event: tk.Event) -> None:
        if self.maximized or self._resize_start is None:
            return
        start_x, start_y, start_width, start_height = self._resize_start
        min_width, min_height = 1120, 720
        width = max(min_width, start_width + event.x_root - start_x)
        height = max(min_height, start_height + event.y_root - start_y)
        self.pending_resize_geometry = f"{width}x{height}"
        if self.resize_after_id is None:
            self.resize_after_id = self.root.after(16, self._apply_pending_resize)

    def _apply_pending_resize(self) -> None:
        self.resize_after_id = None
        if self.pending_resize_geometry:
            self.root.geometry(self.pending_resize_geometry)
            self.pending_resize_geometry = ""

    def _finish_resize(self, _event: tk.Event | None = None) -> None:
        if self.resize_after_id is not None:
            self.root.after_cancel(self.resize_after_id)
            self.resize_after_id = None
        self._apply_pending_resize()
        self._resize_start = None
        self._schedule_chart_redraw()

    def _make_panel(
        self,
        parent: tk.Widget,
        title: str,
        padding: int | tuple[int, int, int, int] = 10,
    ) -> tuple[ttk.Frame, ttk.Frame]:
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=(0, 0, 0, 0))
        header = ttk.Frame(panel, style="PanelHeader.TFrame", padding=(12, 10, 12, 0))
        header.pack(fill=tk.X)
        ttk.Label(header, text=title, style="PanelTitle.TLabel").pack(side=tk.LEFT, anchor=tk.W)
        body = ttk.Frame(panel, style="PanelBody.TFrame", padding=padding)
        body.pack(fill=tk.BOTH, expand=True)
        return panel, body

    def _build_summary_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=2)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(0, weight=2)
        parent.rowconfigure(1, weight=1)

        risk_panel, risk_frame = self._make_panel(parent, "Top Risk Hosts")
        risk_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        risk_frame.rowconfigure(0, weight=1)
        risk_frame.columnconfigure(0, weight=1)
        self.risk_tree = ttk.Treeview(
            risk_frame,
            columns=("ip", "score", "events", "alerts", "country", "ports", "reasons"),
            show="headings",
            selectmode="browse",
        )
        self._setup_tree(
            self.risk_tree,
            {
                "ip": ("IP", 150),
                "score": ("Risk", 70),
                "events": ("Events", 70),
                "alerts": ("Alerts", 70),
                "country": ("Nation", 170),
                "ports": ("Ports", 150),
                "reasons": ("Reasons", 320),
            },
        )
        self.risk_tree.grid(row=0, column=0, sticky="nsew")
        self._add_scrollbar(risk_frame, self.risk_tree, 0)

        chart_panel, chart_frame = self._make_panel(parent, "Activity Charts")
        chart_panel.grid(row=0, column=1, sticky="nsew")
        chart_frame.rowconfigure(0, weight=1)
        chart_frame.columnconfigure(0, weight=1)
        self.chart_canvas = tk.Canvas(
            chart_frame,
            background=COLORS["panel"],
            highlightthickness=1,
            highlightbackground=COLORS["border"],
            bd=0,
        )
        self.chart_canvas.grid(row=0, column=0, sticky="nsew")
        self.chart_canvas.bind("<Configure>", lambda _event: self._schedule_chart_redraw())

        action_panel, action_frame = self._make_panel(parent, "Quick Actions")
        action_panel.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        for column in range(6):
            action_frame.columnconfigure(column, weight=1)
        self.block_ip_button = ttk.Button(action_frame, text="Block Selected IP", command=self.block_selected_ip, style="Danger.TButton")
        self.block_ip_button.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.unblock_ip_button = ttk.Button(action_frame, text="Unblock Selected IP", command=self.unblock_selected_ip)
        self.unblock_ip_button.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        process_detail_button = ttk.Button(action_frame, text="Show Process Details", command=self.show_selected_process_details)
        process_detail_button.grid(row=0, column=2, sticky="ew", padx=(0, 8))
        self._register_process_detail_button(process_detail_button)
        analyze_button = ttk.Button(action_frame, text="Analyze Risk Host", command=self.analyze_selected_with_lm_studio, style="Accent.TButton")
        analyze_button.grid(row=0, column=3, sticky="ew", padx=(0, 8))
        self._register_lm_analyze_button(analyze_button)
        ttk.Button(action_frame, text="Reset Summary", command=self.reset_summary_action).grid(row=0, column=4, sticky="ew", padx=(0, 8))
        ttk.Button(action_frame, text="Export Report", command=self.export_current_report, style="Accent.TButton").grid(row=0, column=5, sticky="ew")
        self._configure_firewall_buttons()

    def _build_alerts_tab(self, parent: ttk.Frame) -> None:
        parent.rowconfigure(0, weight=4)
        parent.rowconfigure(1, weight=0)
        parent.rowconfigure(2, weight=1)
        parent.columnconfigure(0, weight=1)

        alerts_panel, alerts_body = self._make_panel(parent, "Alerts")
        alerts_panel.grid(row=0, column=0, sticky="nsew")
        alerts_body.rowconfigure(0, weight=1)
        alerts_body.columnconfigure(0, weight=1)
        columns = ("time", "severity", "origin", "rule", "title", "description")
        self.alerts_tree = ttk.Treeview(alerts_body, columns=columns, show="headings", selectmode="browse")
        self._setup_tree(
            self.alerts_tree,
            {
                "time": ("Time", 135),
                "severity": ("Severity", 90),
                "origin": ("Origin", 190),
                "rule": ("Rule", 140),
                "title": ("Title", 190),
                "description": ("Description", 420),
            },
        )
        self._configure_alert_tree_tags()
        self.alerts_tree.bind("<<TreeviewSelect>>", self.show_alert_details)
        self.alerts_tree.grid(row=0, column=0, sticky="nsew")
        self._add_scrollbar(alerts_body, self.alerts_tree, 0)

        alert_actions = ttk.Frame(parent, style="Tab.TFrame")
        alert_actions.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        analyze_button = ttk.Button(alert_actions, text="Analyze Alert", command=self.analyze_selected_with_lm_studio, style="Accent.TButton")
        analyze_button.pack(side=tk.LEFT)
        self._register_lm_analyze_button(analyze_button)
        ttk.Label(alert_actions, text="Wipe oldest", style="MetricName.TLabel").pack(side=tk.LEFT, padx=(18, 6))
        ttk.Entry(alert_actions, textvariable=self.alert_wipe_var, width=7).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(alert_actions, text="Wipe Alerts", command=self.wipe_oldest_alerts).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(alert_actions, text="Wipe All Alerts", command=self.wipe_all_alerts, style="Danger.TButton").pack(side=tk.LEFT)

        detail_panel, detail_frame = self._make_panel(parent, "Selected Alert")
        detail_panel.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        detail_frame.rowconfigure(0, weight=1)
        detail_frame.columnconfigure(0, weight=1)
        self.alert_detail = self._make_text_area(detail_frame, height=6)
        self.alert_detail.configure(state=tk.DISABLED)

    def _build_events_tab(self, parent: ttk.Frame) -> None:
        parent.rowconfigure(0, weight=3)
        parent.rowconfigure(1, weight=0)
        parent.rowconfigure(2, weight=1)
        parent.columnconfigure(0, weight=1)

        events_panel, events_body = self._make_panel(parent, "Events")
        events_panel.grid(row=0, column=0, sticky="nsew")
        events_body.rowconfigure(0, weight=1)
        events_body.columnconfigure(0, weight=1)
        columns = ("time", "kind", "remote", "country", "local", "app", "source", "detail")
        self.events_tree = ttk.Treeview(events_body, columns=columns, show="tree headings", selectmode="browse")
        self._setup_tree(
            self.events_tree,
            {
                "time": ("Time", 135),
                "kind": ("Kind", 150),
                "remote": ("Remote IP", 150),
                "country": ("Nation", 150),
                "local": ("Local", 190),
                "app": ("App", 170),
                "source": ("Source", 110),
                "detail": ("Detail", 360),
            },
        )
        self.events_tree.heading("#0", text="")
        self.events_tree.column("#0", width=30, minwidth=30, stretch=False)
        self.events_tree.bind("<<TreeviewSelect>>", self.show_event_ip_details)
        self.events_tree.grid(row=0, column=0, sticky="nsew")
        self._add_scrollbar(events_body, self.events_tree, 0)

        event_actions = ttk.Frame(parent, style="Tab.TFrame")
        event_actions.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        process_detail_button = ttk.Button(event_actions, text="Show Process Details", command=self.show_selected_process_details)
        process_detail_button.pack(side=tk.LEFT, padx=(0, 8))
        self._register_process_detail_button(process_detail_button)
        analyze_button = ttk.Button(event_actions, text="Analyze Selected", command=self.analyze_selected_with_lm_studio, style="Accent.TButton")
        analyze_button.pack(side=tk.LEFT)
        self._register_lm_analyze_button(analyze_button)
        ttk.Label(event_actions, text="Wipe oldest", style="MetricName.TLabel").pack(side=tk.LEFT, padx=(18, 6))
        ttk.Entry(event_actions, textvariable=self.event_wipe_var, width=7).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(event_actions, text="Wipe Events", command=self.wipe_oldest_events).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(event_actions, text="Wipe All Events", command=self.wipe_all_events, style="Danger.TButton").pack(side=tk.LEFT)

        detail_panel, detail_frame = self._make_panel(parent, "Selected Event Details")
        detail_panel.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        detail_frame.rowconfigure(0, weight=1)
        detail_frame.columnconfigure(0, weight=1)
        self.ip_detail = self._make_text_area(detail_frame, height=7)
        self.ip_detail.configure(state=tk.DISABLED)

    def _build_system_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)
        rows = [
            ("Event log", self.events_path_var),
            ("Alert log", self.alerts_path_var),
            ("Network polling", tk.StringVar(value=f"{self.config.network.poll_interval_seconds}s")),
            ("Process polling", tk.StringVar(value=f"{self.config.process.poll_interval_seconds}s")),
            ("Windows Event Log", tk.StringVar(value="enabled" if self.config.auth.windows_event_log_enabled else "disabled")),
            ("GeoIP database", tk.StringVar(value=str(self.config.geoip.database_path or "disabled"))),
            ("Process detail collection", self.process_details_var),
            ("IP intelligence API", self.ip_intel_var),
            ("IP API rate", self.ip_api_rate_var),
            ("Local LLM analysis", self.llm_var),
            ("Privilege level", self.admin_var),
            ("Theme", self.theme_var),
        ]
        for row_index, (label, variable) in enumerate(rows):
            ttk.Label(parent, text=label, style="MetricName.TLabel").grid(
                row=row_index,
                column=0,
                sticky=tk.W,
                pady=4,
                padx=(0, 12),
            )
            ttk.Label(parent, textvariable=variable).grid(row=row_index, column=1, sticky=tk.W, pady=4)

        warning_frame = ttk.LabelFrame(parent, text="Warnings", padding=10, style="Panel.TLabelframe")
        warning_frame.grid(row=len(rows), column=0, columnspan=2, sticky="nsew", pady=(14, 0))
        parent.rowconfigure(len(rows), weight=1)
        warning_frame.rowconfigure(0, weight=1)
        warning_frame.columnconfigure(0, weight=1)
        self.warning_text = self._make_text_area(warning_frame, height=8)
        self.warning_text.configure(state=tk.DISABLED)

        system_actions = ttk.Frame(parent, style="Tab.TFrame")
        system_actions.grid(
            row=len(rows) + 1,
            column=0,
            columnspan=2,
            sticky=tk.W,
            pady=(10, 0),
        )
        self.refresh_lm_status_button = ttk.Button(
            system_actions,
            text="Refresh LM Studio Status",
            command=self.refresh_lm_studio_status,
            style="Accent.TButton",
        )
        self.refresh_lm_status_button.pack(side=tk.LEFT, padx=(0, 8))
        self.refresh_lm_status_tooltip = ToolTip(
            self.refresh_lm_status_button,
            "Enable LM Studio analysis in Settings to refresh its status.",
        )

    def _build_settings_tab(self, parent: ttk.Frame) -> None:
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        canvas = tk.Canvas(parent, highlightthickness=0, background=COLORS["surface"])
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        content = ttk.Frame(canvas, style="Tab.TFrame")
        window_id = canvas.create_window((0, 0), window=content, anchor="nw")

        def update_scroll_region(_event: tk.Event) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def fit_content_width(event: tk.Event) -> None:
            canvas.itemconfigure(window_id, width=event.width)

        def scroll_with_wheel(event: tk.Event) -> str:
            if event.delta:
                canvas.yview_scroll(int(-event.delta / 120), "units")
            return "break"

        content.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", fit_content_width)
        canvas.bind("<MouseWheel>", scroll_with_wheel)
        content.bind("<MouseWheel>", scroll_with_wheel)

        parent = content
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(9, weight=1)
        raw = self.config.raw
        fields = [
            ("Suspicious ports", "ports", ",".join(str(port) for port in raw["detection"]["suspicious_ports"])),
            ("Suspicious processes", "processes", ",".join(raw["process"]["suspicious_process_names"])),
            ("Allowlist IPs/CIDRs", "allow_ips", ",".join(raw["policy"]["allowlist_ips"])),
            ("Blocklist IPs/CIDRs", "block_ips", ",".join(raw["policy"]["blocklist_ips"])),
            ("Allowlist countries", "allow_countries", ",".join(raw["policy"]["allowlist_countries"])),
            ("Blocklist countries", "block_countries", ",".join(raw["policy"]["blocklist_countries"])),
            ("Allowlist processes", "allow_processes", ",".join(raw["policy"]["allowlist_process_names"])),
            ("Blocklist processes", "block_processes", ",".join(raw["policy"]["blocklist_process_names"])),
            ("IP API URL", "ip_api_url", raw["ip_intelligence"]["url_template"]),
            ("Process detail timeout (seconds)", "process_detail_timeout", raw["process"]["detail_lookup_timeout_seconds"]),
            ("LM Studio URL", "llm_url", raw["llm"]["url"]),
            ("LM Studio model", "llm_model", raw["llm"]["model"]),
            ("LM Studio API token", "llm_api_token", raw["llm"].get("api_token", "")),
        ]
        self.settings_vars: dict[str, tk.StringVar] = {}
        self.process_detail_setting_labels: list[ttk.Label] = []
        self.process_detail_setting_controls: list[ttk.Widget] = []
        self.process_detail_setting_tooltips: list[ToolTip] = []
        self.ip_api_setting_labels: list[ttk.Label] = []
        self.ip_api_setting_controls: list[ttk.Widget] = []
        self.ip_api_setting_tooltips: list[ToolTip] = []
        self.lm_setting_labels: list[ttk.Label] = []
        self.lm_setting_controls: list[ttk.Widget] = []
        self.lm_setting_tooltips: list[ToolTip] = []
        process_detail_disabled_message = "Enable Collect process details in Options to modify this setting."
        ip_api_disabled_message = "Enable External IP API in Options to modify this setting."
        lm_disabled_message = "Enable LM Studio analysis in Options to modify this setting."
        for row, (label, key, value) in enumerate(fields):
            field_label = ttk.Label(parent, text=label, style="MetricName.TLabel")
            field_label.grid(row=row, column=0, sticky=tk.W, pady=4, padx=(0, 12))
            var = tk.StringVar(value=value)
            self.settings_vars[key] = var
            if key == "llm_model":
                self.llm_model_combo = ttk.Combobox(
                    parent,
                    textvariable=var,
                    values=self._lm_model_options(),
                    state="readonly",
                    postcommand=self.refresh_lm_studio_status,
                )
                self.llm_model_combo.grid(row=row, column=1, sticky="ew", pady=4)
                self.llm_model_combo.bind("<FocusIn>", lambda _event: self.refresh_lm_studio_status(), add="+")
                self.llm_model_combo.bind("<Button-1>", lambda _event: self.refresh_lm_studio_status(), add="+")
                field_control = self.llm_model_combo
            else:
                field_control = ttk.Entry(parent, textvariable=var)
                field_control.grid(row=row, column=1, sticky="ew", pady=4)
            if key == "process_detail_timeout":
                self.process_detail_setting_labels.append(field_label)
                self.process_detail_setting_controls.append(field_control)
                self.process_detail_setting_tooltips.extend(
                    (
                        ToolTip(field_label, process_detail_disabled_message),
                        ToolTip(field_control, process_detail_disabled_message),
                    )
                )
            elif key == "ip_api_url":
                self.ip_api_setting_labels.append(field_label)
                self.ip_api_setting_controls.append(field_control)
                self.ip_api_setting_tooltips.extend(
                    (
                        ToolTip(field_label, ip_api_disabled_message),
                        ToolTip(field_control, ip_api_disabled_message),
                    )
                )
            elif key.startswith("llm_"):
                self.lm_setting_labels.append(field_label)
                self.lm_setting_controls.append(field_control)
                self.lm_setting_tooltips.extend(
                    (
                        ToolTip(field_label, lm_disabled_message),
                        ToolTip(field_control, lm_disabled_message),
                    )
                )

        numeric_frame = ttk.LabelFrame(parent, text="Thresholds", padding=10, style="Panel.TLabelframe")
        numeric_frame.grid(row=len(fields), column=0, columnspan=2, sticky="ew", pady=(12, 8))
        for column in range(4):
            numeric_frame.columnconfigure(column, weight=1)
        numeric_fields = [
            ("Port scan ports", "port_scan_unique_ports", raw["detection"]["port_scan_unique_ports"]),
            ("Burst connections", "connection_burst_threshold", raw["detection"]["connection_burst_threshold"]),
            ("Brute force failures", "brute_force_threshold", raw["detection"]["brute_force_threshold"]),
            ("Process burst", "process_burst_threshold", raw["detection"]["process_burst_threshold"]),
        ]
        for index, (label, key, value) in enumerate(numeric_fields):
            ttk.Label(numeric_frame, text=label, style="MetricName.TLabel").grid(row=0, column=index, sticky=tk.W)
            var = tk.StringVar(value=str(value))
            self.settings_vars[key] = var
            ttk.Entry(numeric_frame, textvariable=var, width=10).grid(row=1, column=index, sticky="ew", padx=(0, 8))

        toggle_frame = ttk.LabelFrame(parent, text="Options", padding=10, style="Panel.TLabelframe")
        toggle_frame.grid(row=len(fields) + 1, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self.setting_bools = {
            "process_details": tk.BooleanVar(value=raw["process"]["detail_lookup_enabled"]),
            "ip_api_enabled": tk.BooleanVar(value=raw["ip_intelligence"]["enabled"]),
            "llm_enabled": tk.BooleanVar(value=raw["llm"]["enabled"]),
        }
        ttk.Checkbutton(
            toggle_frame,
            text="Collect process details",
            variable=self.setting_bools["process_details"],
            command=self._update_process_detail_controls_state,
        ).grid(row=0, column=0, sticky=tk.W, padx=(0, 18))
        ttk.Checkbutton(
            toggle_frame,
            text="External IP API",
            variable=self.setting_bools["ip_api_enabled"],
            command=self._update_ip_api_controls_state,
        ).grid(row=0, column=1, sticky=tk.W, padx=(0, 18))
        ttk.Checkbutton(
            toggle_frame,
            text="LM Studio analysis",
            variable=self.setting_bools["llm_enabled"],
            command=self._update_lm_controls_state,
        ).grid(row=0, column=2, sticky=tk.W, padx=(0, 18))

        policy_frame = ttk.LabelFrame(parent, text="Current Blocklists", padding=10, style="Panel.TLabelframe")
        policy_frame.grid(row=len(fields) + 2, column=0, columnspan=2, sticky="nsew", pady=(0, 8))
        for column in range(3):
            policy_frame.columnconfigure(column, weight=1)
        self.blocked_ip_list = self._make_policy_list(
            policy_frame,
            "Blocked IPs / CIDRs",
            0,
            self.remove_selected_blocked_ip,
            "Remove From IDS",
        )
        self.blocked_country_list = self._make_policy_list(
            policy_frame,
            "Blocked Countries",
            1,
            self.remove_selected_blocked_country,
            "Remove Country",
        )
        self.blocked_process_list = self._make_policy_list(
            policy_frame,
            "Blocked Processes",
            2,
            self.remove_selected_blocked_process,
            "Remove Process",
        )
        self._refresh_policy_lists()

        button_frame = ttk.Frame(parent, style="Tab.TFrame")
        button_frame.grid(row=len(fields) + 3, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        ttk.Button(button_frame, text="Save Settings", command=self.save_settings, style="Primary.TButton").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(button_frame, text="Save And Restart Monitor", command=self.save_and_restart, style="Accent.TButton").pack(side=tk.LEFT)
        self._bind_mousewheel_to_descendants(content, scroll_with_wheel)
        self._style_combobox_popdown(self.llm_model_combo)
        self._update_all_option_controls_state(reset_lm_probe=False)

    def _setting_option_enabled(self, key: str, configured: bool) -> bool:
        setting_bools = getattr(self, "setting_bools", None)
        if setting_bools is not None and key in setting_bools:
            return bool(setting_bools[key].get())
        return configured

    def _process_details_enabled(self) -> bool:
        return self._setting_option_enabled("process_details", self.config.process.detail_lookup_enabled)

    def _ip_api_enabled(self) -> bool:
        return self._setting_option_enabled("ip_api_enabled", self.config.ip_intelligence.enabled)

    def _lm_analysis_enabled(self) -> bool:
        return self._setting_option_enabled("llm_enabled", self.config.llm.enabled)

    def _register_lm_analyze_button(self, button: ttk.Button) -> None:
        self.lm_analyze_buttons.append(button)
        self.lm_analyze_tooltips.append(
            ToolTip(button, "Enable LM Studio analysis in Settings to analyze this item.")
        )

    def _register_process_detail_button(self, button: ttk.Button) -> None:
        self.process_detail_buttons.append(button)
        self.process_detail_tooltips.append(
            ToolTip(button, "Enable Collect process details in Settings to use this action.")
        )

    def _set_option_dependency_state(
        self,
        enabled: bool,
        labels: object,
        controls: object,
        tooltips: object,
        buttons: object = (),
        button_tooltips: object = (),
    ) -> None:
        widget_state = "!disabled" if enabled else "disabled"
        label_style = "MetricName.TLabel" if enabled else "DisabledMetricName.TLabel"
        for label in labels:
            label.configure(style=label_style)
        for control in controls:
            control.state([widget_state])
        for tooltip in tooltips:
            tooltip.set_enabled(not enabled)
        for button in buttons:
            button.state([widget_state])
        for tooltip in button_tooltips:
            tooltip.set_enabled(not enabled)

    def _update_process_detail_controls_state(self) -> None:
        self._set_option_dependency_state(
            self._process_details_enabled(),
            getattr(self, "process_detail_setting_labels", ()),
            getattr(self, "process_detail_setting_controls", ()),
            getattr(self, "process_detail_setting_tooltips", ()),
            getattr(self, "process_detail_buttons", ()),
            getattr(self, "process_detail_tooltips", ()),
        )
        variable = getattr(self, "process_details_var", None)
        if variable is not None:
            variable.set(self._process_details_status())

    def _update_ip_api_controls_state(self) -> None:
        self._set_option_dependency_state(
            self._ip_api_enabled(),
            getattr(self, "ip_api_setting_labels", ()),
            getattr(self, "ip_api_setting_controls", ()),
            getattr(self, "ip_api_setting_tooltips", ()),
        )
        status_variable = getattr(self, "ip_intel_var", None)
        if status_variable is not None:
            status_variable.set(self._ip_intelligence_status())
        rate_variable = getattr(self, "ip_api_rate_var", None)
        if rate_variable is not None:
            rate_variable.set(self._ip_api_rate_status())

    def _update_lm_controls_state(self, reset_probe: bool = True) -> None:
        enabled = self._lm_analysis_enabled()
        refresh_buttons = ()
        refresh_button = getattr(self, "refresh_lm_status_button", None)
        if refresh_button is not None:
            refresh_buttons = (refresh_button,)
        refresh_tooltips = ()
        refresh_tooltip = getattr(self, "refresh_lm_status_tooltip", None)
        if refresh_tooltip is not None:
            refresh_tooltips = (refresh_tooltip,)
        self._set_option_dependency_state(
            enabled,
            getattr(self, "lm_setting_labels", ()),
            getattr(self, "lm_setting_controls", ()),
            getattr(self, "lm_setting_tooltips", ()),
            (*refresh_buttons, *getattr(self, "lm_analyze_buttons", ())),
            (*refresh_tooltips, *getattr(self, "lm_analyze_tooltips", ())),
        )

        if reset_probe:
            self._reset_lm_status_probe()
        self.llm_var.set(self._llm_status())

    def _update_all_option_controls_state(self, reset_lm_probe: bool = True) -> None:
        self._update_process_detail_controls_state()
        self._update_ip_api_controls_state()
        self._update_lm_controls_state(reset_probe=reset_lm_probe)

    def _lm_model_options(self) -> tuple[str, ...]:
        configured = self.config.llm.model
        status = self.llm_server_status
        values: list[str] = []
        if status is not None:
            values.extend(status.loaded_models)
            values.extend(name for name in status.models if name not in values)
        if configured and configured not in values:
            values.insert(0, configured)
        return tuple(values)

    def _sync_lm_model_options(self) -> None:
        combo = getattr(self, "llm_model_combo", None)
        if combo is None or "llm_model" not in getattr(self, "settings_vars", {}):
            return
        values = self._lm_model_options()
        combo.configure(values=values)
        self._style_combobox_popdown(combo)
        current = self.settings_vars["llm_model"].get().strip()
        if not current and values:
            self.settings_vars["llm_model"].set(values[0])

    def _make_policy_list(
        self,
        parent: ttk.Frame,
        title: str,
        column: int,
        remove_command: object,
        button_text: str,
    ) -> tk.Listbox:
        frame = ttk.Frame(parent, style="Panel.TFrame", padding=8)
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 8))
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text=title, style="MetricName.TLabel").grid(row=0, column=0, sticky=tk.W)
        listbox = tk.Listbox(
            frame,
            height=6,
            exportselection=False,
            background=COLORS["panel"],
            foreground=COLORS["text"],
            selectbackground=COLORS["selection"],
            selectforeground=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["border"],
            highlightcolor=COLORS["accent"],
            relief=tk.FLAT,
            borderwidth=0,
            activestyle="none",
        )
        listbox.grid(row=1, column=0, sticky="nsew", pady=(4, 6))
        ttk.Button(frame, text=button_text, command=remove_command).grid(row=2, column=0, sticky="ew")
        return listbox

    def _configure_firewall_buttons(self) -> None:
        message = (
            "Run this program as administrator to block or unblock IPs in Windows Firewall."
        )
        if self.can_manage_firewall:
            return
        for button in (self.block_ip_button, self.unblock_ip_button):
            button.configure(state=tk.DISABLED)
            ToolTip(button, message)

    def _setup_tree(self, tree: ttk.Treeview, columns: dict[str, tuple[str, int]]) -> None:
        for column, (heading, width) in columns.items():
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=70, stretch=True)
        self._configure_tree_tags(tree)

    def _configure_tree_tags(self, tree: ttk.Treeview) -> None:
        tree.tag_configure("even", background=COLORS["panel"])
        tree.tag_configure("odd", background=COLORS["panel_alt"])

    def _configure_alert_tree_tags(self) -> None:
        if not hasattr(self, "alerts_tree"):
            return
        self._configure_tree_tags(self.alerts_tree)
        self.alerts_tree.tag_configure(
            "critical",
            foreground=COLORS["critical_text"],
            background=COLORS["danger_soft"],
        )
        self.alerts_tree.tag_configure(
            "high",
            foreground=COLORS["high_text"],
            background=COLORS["high_soft"],
        )
        self.alerts_tree.tag_configure(
            "medium",
            foreground=COLORS["medium_text"],
            background=COLORS["amber_soft"],
        )

    def _event_icon(self, event: Event) -> tk.PhotoImage:
        attrs = event.attributes
        process_name = str(attrs.get("process_name") or attrs.get("image_name") or event.kind)
        icon_key = self._event_icon_key(event)
        if icon_key:
            cached = self.app_icon_images.get(icon_key)
            if cached is not None:
                return cached
            self._schedule_app_icon_lookup(icon_key, event)

        if is_browser_process_name(process_name):
            key = "badge:browser"
            color = COLORS["teal"]
        elif process_name.lower() == "system / kernel":
            key = "badge:system"
            color = COLORS["muted"]
        elif event.kind == "process_start":
            key = "badge:process"
            color = COLORS["accent"]
        else:
            key = f"badge:{process_name.lower()}"
            color = self._badge_color(process_name)
        cached = self.app_icon_images.get(key)
        if cached is not None:
            return cached
        image = tk.PhotoImage(width=16, height=16)
        image.put(COLORS["border"], to=(0, 0, 16, 16))
        image.put(color, to=(2, 2, 14, 14))
        image.put(COLORS["panel"], to=(5, 5, 11, 11))
        image.put(color, to=(7, 7, 9, 9))
        self.app_icon_images[key] = image
        return image

    def _event_icon_key(self, event: Event) -> str:
        attrs = event.attributes
        path = attrs.get("path")
        if isinstance(path, str) and path:
            return f"path:{path}"
        pid = _as_pid(attrs.get("pid"))
        if pid is not None and pid > 0:
            return f"pid:{pid}"
        return ""

    def _schedule_app_icon_lookup(self, icon_key: str, event: Event) -> None:
        if icon_key in self.app_icon_pending or icon_key in self.app_icon_failed:
            return
        if len(self.app_icon_pending) >= 12:
            return
        self.app_icon_pending.add(icon_key)
        attrs = event.attributes
        path = attrs.get("path") if isinstance(attrs.get("path"), str) else ""
        pid = _as_pid(attrs.get("pid"))
        timeout_seconds = self.config.process.detail_lookup_timeout_seconds

        def worker() -> None:
            icon_path = path
            if not icon_path and pid is not None:
                try:
                    details = get_process_details(pid, timeout_seconds)
                    value = details.get("path")
                    icon_path = value if isinstance(value, str) else ""
                except Exception:
                    icon_path = ""
            image_data = executable_icon_data(icon_path, background=self._panel_rgb()) if icon_path else None
            self.app_icon_results.put((icon_key, image_data))

        threading.Thread(target=worker, name=f"AppIcon-{icon_key}", daemon=True).start()

    def _poll_app_icon_results(self) -> None:
        changed = False
        while True:
            try:
                icon_key, image_data = self.app_icon_results.get_nowait()
            except queue.Empty:
                break
            self.app_icon_pending.discard(icon_key)
            if image_data:
                try:
                    self.app_icon_images[icon_key] = tk.PhotoImage(data=image_data)
                    changed = True
                except tk.TclError:
                    self.app_icon_failed.add(icon_key)
            else:
                self.app_icon_failed.add(icon_key)
        if changed:
            self.last_event_total = -1
            self._render_events(self.worker.snapshot().recent_events)

    def _panel_rgb(self) -> tuple[int, int, int]:
        color = COLORS["panel"].lstrip("#")
        return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)

    def _badge_color(self, label: str) -> str:
        palette = [COLORS["accent"], COLORS["teal"], COLORS["amber"], COLORS["danger"]]
        index = sum(ord(char) for char in label) % len(palette)
        return palette[index]

    def _add_scrollbar(self, parent: ttk.Frame, tree: ttk.Treeview, row: int) -> None:
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=row, column=1, sticky="ns")

    def _bind_mousewheel_to_descendants(self, widget: tk.Widget, callback: object) -> None:
        try:
            widget.bind("<MouseWheel>", callback, add="+")
        except tk.TclError:
            return
        for child in widget.winfo_children():
            self._bind_mousewheel_to_descendants(child, callback)

    def _style_combobox_popdown(self, combo: ttk.Combobox) -> None:
        try:
            popdown = combo.tk.call("ttk::combobox::PopdownWindow", combo)
            listbox = f"{popdown}.f.l"
            combo.tk.call(listbox, "configure", "-background", COLORS["panel_alt"])
            combo.tk.call(listbox, "configure", "-foreground", COLORS["text"])
            combo.tk.call(listbox, "configure", "-selectbackground", COLORS["selection"])
            combo.tk.call(listbox, "configure", "-selectforeground", COLORS["text"])
            combo.tk.call(listbox, "configure", "-highlightthickness", "0")
            combo.tk.call(listbox, "configure", "-relief", "flat")
        except tk.TclError:
            pass

    def _make_text_area(self, parent: ttk.Frame, height: int) -> tk.Text:
        text_widget = tk.Text(
            parent,
            height=height,
            wrap=tk.WORD,
            background=COLORS["surface_high"],
            foreground=COLORS["text"],
            insertbackground=COLORS["accent"],
            selectbackground=COLORS["selection"],
            selectforeground=COLORS["text"],
            highlightthickness=1,
            highlightbackground=COLORS["border_soft"],
            highlightcolor=COLORS["accent"],
            relief=tk.FLAT,
            borderwidth=0,
            padx=10,
            pady=8,
            font=(FONT, 9),
            spacing1=2,
            spacing3=2,
        )
        text_widget.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")
        return text_widget

    def toggle_monitor(self) -> None:
        if self.worker.running:
            self.worker.stop()
        else:
            self.worker.start()
        self._update_status_button()

    def toggle_theme(self) -> None:
        if self.theme_transition_running:
            return
        theme = "light" if self.config.ui.theme == "night" else "night"
        self.change_theme(theme)

    def change_theme(self, theme: str | tk.Event | None = None) -> None:
        if isinstance(theme, str):
            next_theme = theme
        else:
            next_theme = _theme_from_label(self.theme_var.get())
        if next_theme not in {"light", "night"}:
            return
        theme = next_theme
        if theme == self.config.ui.theme:
            return
        previous_theme = self.config.ui.theme
        raw = dict(self.config.raw)
        raw["ui"] = dict(raw.get("ui", {}))
        raw["ui"]["theme"] = theme
        try:
            updated_config = AppConfig.from_mapping(raw)
            save_config(raw, self.config_path)
        except Exception as exc:
            self.theme_var.set(_theme_label(previous_theme))
            messagebox.showerror("Theme save failed", str(exc))
            return
        self.config = updated_config
        self.theme_var.set(_theme_label(theme))
        self._transition_theme(previous_theme, theme)

    def _apply_theme(self, theme: str) -> None:
        COLORS.clear()
        COLORS.update(_colors_for_theme(theme))
        self._apply_theme_colors(refresh_tables=True)

    def _transition_theme(self, previous_theme: str, theme: str) -> None:
        if self.theme_transition_after_id is not None:
            self.root.after_cancel(self.theme_transition_after_id)
            self.theme_transition_after_id = None
        start_colors = dict(COLORS) or dict(_colors_for_theme(previous_theme))
        target_colors = dict(_colors_for_theme(theme))
        steps = 10
        self.theme_transition_running = True
        self._refresh_theme_button()

        def animate(step: int) -> None:
            amount = step / steps
            eased = amount * amount * (3 - 2 * amount)
            COLORS.clear()
            COLORS.update(target_colors if step >= steps else _mix_theme_colors(start_colors, target_colors, eased))
            self._apply_theme_colors(refresh_tables=step >= steps)
            if step >= steps:
                self.theme_transition_after_id = None
                self.theme_transition_running = False
                self._refresh_theme_button()
                return
            self.theme_transition_after_id = self.root.after(18, lambda: animate(step + 1))

        animate(1)

    def _apply_theme_colors(self, refresh_tables: bool = True) -> None:
        self._configure_style()
        self._refresh_titlebar_colors()
        self._refresh_theme_button()
        self._refresh_nav_buttons()
        self._refresh_widget_colors(self.root)
        for tree_name in ("risk_tree", "events_tree"):
            tree = getattr(self, tree_name, None)
            if tree is not None:
                self._configure_tree_tags(tree)
        self._configure_alert_tree_tags()
        self._refresh_policy_lists()
        if hasattr(self, "chart_canvas"):
            self._draw_charts(self.worker.snapshot())
        if refresh_tables:
            self.app_icon_images.clear()
            self.last_event_total = -1
            self._render_events(self.worker.snapshot().recent_events)

    def _refresh_titlebar_colors(self) -> None:
        for widget in (
            *getattr(self, "titlebar_color_widgets", []),
            getattr(self, "brand_mark", None),
            getattr(self, "window_title_label", None),
            getattr(self, "window_subtitle_label", None),
        ):
            if widget is None:
                continue
            try:
                widget.configure(background=COLORS["titlebar"])
            except tk.TclError:
                pass
        if hasattr(self, "resize_grip"):
            self.resize_grip.configure(background=COLORS["chrome"])
        if hasattr(self, "window_title_label"):
            self.window_title_label.configure(foreground=COLORS["titlebar_text"])
        if hasattr(self, "window_subtitle_label"):
            self.window_subtitle_label.configure(foreground=COLORS["titlebar_muted"])
        for button in (
            getattr(self, "minimize_button", None),
            getattr(self, "maximize_button", None),
            getattr(self, "close_button", None),
        ):
            if button is not None:
                button.configure(background=COLORS["titlebar"], foreground=COLORS["titlebar_text"])
        self._draw_brand_mark()

    def _refresh_widget_colors(self, widget: tk.Widget) -> None:
        try:
            if isinstance(widget, (tk.Tk, tk.Toplevel)):
                widget.configure(background=COLORS["bg"])
            elif isinstance(widget, tk.Frame):
                if widget in getattr(self, "titlebar_color_widgets", []):
                    widget.configure(background=COLORS["titlebar"])
                elif widget is getattr(self, "nav_frame", None):
                    widget.configure(background=COLORS["chrome"])
                elif widget is getattr(self, "shell_frame", None):
                    widget.configure(background=COLORS["chrome"], highlightbackground=COLORS["border"])
                else:
                    widget.configure(background=COLORS["chrome"])
            elif isinstance(widget, tk.Label):
                if widget in {getattr(self, "window_title_label", None), getattr(self, "window_subtitle_label", None)}:
                    pass
                else:
                    widget.configure(background=COLORS["panel"], foreground=COLORS["text"])
            elif isinstance(widget, tk.Button):
                if widget in getattr(self, "nav_buttons", {}).values():
                    pass
                elif widget is getattr(self, "theme_button", None):
                    self._refresh_theme_button()
                else:
                    widget.configure(background=COLORS["titlebar"], foreground=COLORS["titlebar_text"])
            elif isinstance(widget, tk.Canvas):
                if widget is getattr(self, "brand_mark", None):
                    widget.configure(background=COLORS["titlebar"])
                else:
                    widget.configure(
                        background=COLORS["surface"],
                        highlightbackground=COLORS["border"],
                        highlightcolor=COLORS["accent"],
                    )
            elif isinstance(widget, tk.Text):
                widget.configure(
                    background=COLORS["surface_high"],
                    foreground=COLORS["text"],
                    insertbackground=COLORS["accent"],
                    selectbackground=COLORS["selection"],
                    selectforeground=COLORS["text"],
                    highlightbackground=COLORS["border_soft"],
                    highlightcolor=COLORS["accent"],
                )
            elif isinstance(widget, tk.Listbox):
                widget.configure(
                    background=COLORS["panel"],
                    foreground=COLORS["text"],
                    selectbackground=COLORS["selection"],
                    selectforeground=COLORS["text"],
                    highlightbackground=COLORS["border"],
                    highlightcolor=COLORS["accent"],
                )
            elif isinstance(widget, ttk.Combobox):
                self._style_combobox_popdown(widget)
        except tk.TclError:
            return
        for child in widget.winfo_children():
            self._refresh_widget_colors(child)

    def replay_sample(self) -> None:
        path = Path("data/sample_events.jsonl")
        self._replay_path(path)

    def load_replay(self) -> None:
        path = filedialog.askopenfilename(
            title="Load JSONL Replay",
            filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")],
        )
        if path:
            self._replay_path(Path(path))

    def export_current_report(self) -> None:
        path_text = filedialog.asksaveasfilename(
            title="Export IDS Report",
            defaultextension=".html",
            filetypes=[
                ("HTML report", "*.html"),
                ("Text report", "*.txt"),
                ("CSV alerts", "*.csv"),
            ],
        )
        if not path_text:
            return
        path = Path(path_text)
        suffix = path.suffix.lower().lstrip(".") or "html"
        try:
            export_report(self.worker.snapshot(), path, suffix)
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        messagebox.showinfo("Report exported", f"Report saved to {path}.")

    def block_selected_ip(self) -> None:
        ip_text = self._selected_ip()
        if not ip_text:
            messagebox.showwarning("No IP selected", "Select an alert, event, or risk host with a remote IP first.")
            return
        if not messagebox.askyesno(
            "Block IP",
            f"Add {ip_text} to the Windows firewall block list and local IDS blocklist?",
        ):
            return
        ok, message = block_ip_windows_firewall(ip_text)
        self._add_ip_to_config_blocklist(ip_text)
        if ok:
            messagebox.showinfo("IP blocked", message)
        else:
            messagebox.showwarning("Firewall action failed", f"{message}\n\nThe IP was still added to the IDS blocklist.")

    def unblock_selected_ip(self) -> None:
        ip_text = self._selected_blocked_ip() or self._selected_ip()
        if not ip_text:
            messagebox.showwarning("No IP selected", "Select a blocked IP or an IP from the alerts/events/risk tables first.")
            return
        self._unblock_ip(ip_text)

    def remove_selected_blocked_ip(self) -> None:
        ip_text = self._selected_blocked_ip()
        if not ip_text:
            messagebox.showwarning("No blocked IP selected", "Select an IP from the Current Blocklists section first.")
            return
        if self._remove_policy_value("blocklist_ips", ip_text):
            messagebox.showinfo("IP removed", f"{ip_text} was removed from the IDS blocklist.")

    def remove_selected_blocked_country(self) -> None:
        country = self._selected_list_value(self.blocked_country_list)
        if not country:
            messagebox.showwarning("No country selected", "Select a country from the Current Blocklists section first.")
            return
        if self._remove_policy_value("blocklist_countries", country):
            messagebox.showinfo("Country removed", f"{country} was removed from the IDS country blocklist.")

    def remove_selected_blocked_process(self) -> None:
        process = self._selected_list_value(self.blocked_process_list)
        if not process:
            messagebox.showwarning("No process selected", "Select a process from the Current Blocklists section first.")
            return
        if self._remove_policy_value("blocklist_process_names", process):
            messagebox.showinfo("Process removed", f"{process} was removed from the IDS process blocklist.")

    def _unblock_ip(self, ip_text: str) -> None:
        if not messagebox.askyesno(
            "Unblock IP",
            f"Remove {ip_text} from the local IDS blocklist and try to remove its Windows Firewall rule?",
        ):
            return
        removed = self._remove_policy_value("blocklist_ips", ip_text)
        ok, message = unblock_ip_windows_firewall(ip_text)
        if ok:
            messagebox.showinfo("IP unblocked", message)
        elif removed:
            messagebox.showwarning(
                "Firewall action failed",
                f"{message}\n\nThe IP was removed from the IDS blocklist.",
            )
        else:
            messagebox.showwarning("IP was not blocked", f"{ip_text} was not found in the IDS blocklist.")

    def show_selected_process_details(self) -> None:
        if not self._process_details_enabled():
            messagebox.showwarning(
                "Process details disabled",
                "Enable Collect process details in Settings to use this action.",
            )
            return
        selected = self._selected_process_context()
        if selected is None:
            messagebox.showwarning(
                "No process selected",
                "Select an event, alert, or risk host with a related process ID first.",
            )
            return
        pid, event = selected
        try:
            live_details = selected_process_details(pid, self.config.process.detail_lookup_timeout_seconds)
        except Exception as exc:
            messagebox.showerror("Process lookup failed", str(exc))
            return
        lines = [
            f"PID: {pid}",
            f"Event: {event.kind}",
            f"Source: {event.source}",
            f"Time: {format_timestamp(event.timestamp)}",
            "",
            "Captured event fields:",
            *_detail_lines(event.attributes),
            "",
            "Live process lookup:",
        ]
        if live_details:
            lines.extend(_detail_lines(live_details))
        else:
            lines.append("No live details found. The process may have already exited, or access may be restricted.")
        self._show_text_window(f"Process {pid}", "\n".join(lines))

    def analyze_selected_with_lm_studio(self) -> None:
        if not self._lm_analysis_enabled():
            messagebox.showwarning(
                "LM Studio disabled",
                "Enable LM Studio analysis in Settings and make sure the local LM Studio server is running.",
            )
            return
        if self.llm_server_status is not None and not self.llm_server_status.online:
            messagebox.showwarning(
                "LM Studio offline",
                f"LM Studio does not look reachable yet: {self.llm_server_status.message}",
            )
            return
        selected = self._selected_analysis_payload()
        if selected is None:
            messagebox.showwarning("Nothing selected", "Select an event, alert, or risk host first.")
            return

        item_type, payload = selected
        result_queue: queue.SimpleQueue[tuple[bool, str]] = queue.SimpleQueue()
        text_widget = self._show_text_window(
            "LM Studio Analysis",
            f"Analyzing selected {item_type} with {self.config.llm.model}...\n",
        )

        def worker() -> None:
            try:
                result = analyze_security_payload(self.config.llm, item_type, payload)
            except Exception as exc:
                result_queue.put((False, str(exc)))
            else:
                result_queue.put((True, result))

        threading.Thread(target=worker, name="LMStudioAnalysis", daemon=True).start()
        self._poll_analysis_result(result_queue, text_widget)

    def _poll_analysis_result(
        self,
        result_queue: queue.SimpleQueue[tuple[bool, str]],
        text_widget: tk.Text,
    ) -> None:
        try:
            ok, text = result_queue.get_nowait()
        except queue.Empty:
            self.root.after(150, lambda: self._poll_analysis_result(result_queue, text_widget))
            return
        if not text_widget.winfo_exists():
            return
        prefix = "" if ok else "Analysis failed:\n"
        self._replace_text(text_widget, prefix + text)

    def refresh_lm_studio_status(self) -> None:
        if not self._lm_analysis_enabled():
            self.llm_var.set("DISABLED")
            return
        self._reset_lm_status_probe()
        self._maybe_check_lm_studio(force=True)

    def _replay_path(self, path: Path) -> None:
        try:
            count = self.worker.replay_file(path)
        except Exception as exc:
            messagebox.showerror("Replay failed", str(exc))
            return
        self.last_event_total = -1
        self.last_alert_total = -1
        self._refresh_snapshot(self.worker.snapshot())
        messagebox.showinfo("Replay complete", f"Loaded {count} events from {path}.")

    def wipe_oldest_events(self) -> None:
        count = self._wipe_count(self.event_wipe_var, "events")
        if count is None:
            return
        total = self.worker.snapshot().total_events
        if count >= total and total > 0 and not messagebox.askyesno(
            "Wipe all events?",
            f"This will remove all {total} stored events. Continue?",
        ):
            return
        removed = self.worker.discard_oldest_events(count)
        self._after_wipe("events", removed)

    def wipe_oldest_alerts(self) -> None:
        count = self._wipe_count(self.alert_wipe_var, "alerts")
        if count is None:
            return
        total = self.worker.snapshot().total_alerts
        if count >= total and total > 0 and not messagebox.askyesno(
            "Wipe all alerts?",
            f"This will remove all {total} stored alerts. Continue?",
        ):
            return
        removed = self.worker.discard_oldest_alerts(count)
        self._after_wipe("alerts", removed)

    def wipe_all_events(self) -> None:
        if not messagebox.askyesno(
            "Wipe all events",
            "Remove all stored event history from the current view and configured event log?",
        ):
            return
        removed = self.worker.clear_events()
        self._after_wipe("events", removed)

    def wipe_all_alerts(self) -> None:
        if not messagebox.askyesno(
            "Wipe all alerts",
            "Remove all stored alert history from the current view and configured alert log?",
        ):
            return
        removed = self.worker.clear_alerts()
        self._after_wipe("alerts", removed)

    def reset_summary_action(self) -> None:
        if not messagebox.askyesno(
            "Reset summary",
            "Clear the current Top Risk Hosts and chart counters? Events and alerts will stay in their tabs.",
        ):
            return
        self.worker.reset_summary()
        self.last_risk_signature = ""
        self._render_summary(self.worker.snapshot())
        messagebox.showinfo("Summary reset", "Summary risk and chart counters were reset.")

    def _wipe_count(self, variable: tk.StringVar, item_name: str) -> int | None:
        text = variable.get().strip()
        if not text.isdigit() or int(text) <= 0:
            messagebox.showwarning("Invalid wipe count", f"Enter a positive number of {item_name} to wipe.")
            return None
        return int(text)

    def _after_wipe(self, item_name: str, removed: int) -> None:
        self.last_event_total = -1
        self.last_alert_total = -1
        self.last_risk_signature = ""
        self._refresh_snapshot(self.worker.snapshot())
        if item_name == "events" and not self.events_tree.selection():
            self.event_detail_item_id = ""
            self._replace_text(self.ip_detail, "Select an event to see its details.")
        if item_name == "alerts" and not self.alerts_tree.selection():
            self.alert_detail_item_id = ""
            self._replace_text(self.alert_detail, "Select an alert to see its details.")
        messagebox.showinfo("History updated", f"Removed {removed} {item_name}.")

    def save_settings(self) -> bool:
        try:
            updated = self._updated_raw_config()
            updated_config = AppConfig.from_mapping(updated)
            save_config(updated, self.config_path)
            self.config = updated_config
            self.worker.ids.policy = SecurityPolicy(self.config.policy)
            self._sync_policy_entries_from_config()
            self._refresh_policy_lists()
            self._update_all_option_controls_state()
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return False
        messagebox.showinfo("Settings saved", "Settings were saved. Restart the monitor to apply every change.")
        return True

    def save_and_restart(self) -> None:
        if not self.save_settings():
            return
        self.worker.shutdown()
        try:
            self.config = load_config(self.config_path)
            self.worker = MonitorWorker(self.config)
            self.worker.start()
        except Exception as exc:
            messagebox.showerror("Restart failed", str(exc))
            return
        self.last_event_total = -1
        self.last_alert_total = -1
        self.last_ip_intelligence_version = -1
        self.last_risk_signature = ""
        self._update_all_option_controls_state()
        self.geoip_var.set(self._geoip_status())
        self.events_path_var.set(str(self.config.output.events_path or "disabled"))
        self.alerts_path_var.set(str(self.config.output.alerts_path or "disabled"))
        messagebox.showinfo("Monitor restarted", "The monitor is now running with the saved settings.")

    def _reset_lm_status_probe(self) -> None:
        self.llm_server_status = None
        self.llm_status_checking = False
        self.last_llm_status_check = 0.0
        while True:
            try:
                self.llm_status_results.get_nowait()
            except queue.Empty:
                break

    def _updated_raw_config(self) -> dict[str, object]:
        raw = dict(self.config.raw)
        raw["detection"] = dict(raw["detection"])
        raw["process"] = dict(raw["process"])
        raw["policy"] = dict(raw["policy"])
        raw["ip_intelligence"] = dict(raw["ip_intelligence"])
        raw["llm"] = dict(raw["llm"])

        raw["detection"]["suspicious_ports"] = [
            int(item) for item in split_csv(self.settings_vars["ports"].get()) if item.isdigit()
        ]
        raw["process"]["suspicious_process_names"] = split_csv(self.settings_vars["processes"].get())
        raw["policy"]["allowlist_ips"] = split_csv(self.settings_vars["allow_ips"].get())
        raw["policy"]["blocklist_ips"] = split_csv(self.settings_vars["block_ips"].get())
        raw["policy"]["allowlist_countries"] = [item.upper() for item in split_csv(self.settings_vars["allow_countries"].get())]
        raw["policy"]["blocklist_countries"] = [item.upper() for item in split_csv(self.settings_vars["block_countries"].get())]
        raw["policy"]["allowlist_process_names"] = split_csv(self.settings_vars["allow_processes"].get())
        raw["policy"]["blocklist_process_names"] = split_csv(self.settings_vars["block_processes"].get())
        raw["ip_intelligence"]["url_template"] = self.settings_vars["ip_api_url"].get().strip()
        raw["process"]["detail_lookup_timeout_seconds"] = float(self.settings_vars["process_detail_timeout"].get())
        raw["llm"]["url"] = self.settings_vars["llm_url"].get().strip()
        raw["llm"]["model"] = self.settings_vars["llm_model"].get().strip()
        raw["llm"]["api_token"] = self.settings_vars["llm_api_token"].get().strip()

        for key in [
            "port_scan_unique_ports",
            "connection_burst_threshold",
            "brute_force_threshold",
            "process_burst_threshold",
        ]:
            raw["detection"][key] = int(self.settings_vars[key].get())

        raw["process"]["detail_lookup_enabled"] = bool(self.setting_bools["process_details"].get())
        raw["ip_intelligence"]["enabled"] = bool(self.setting_bools["ip_api_enabled"].get())
        raw["llm"]["enabled"] = bool(self.setting_bools["llm_enabled"].get())
        return raw

    def show_alert_details(self, _event: tk.Event) -> None:
        if self.refreshing_alert_tree:
            return
        selected = self.alerts_tree.selection()
        if not selected:
            return
        item_id = selected[0]
        alert = self.alerts_by_id.get(item_id)
        if alert is None:
            return
        preserve_scroll = item_id == self.alert_detail_item_id
        lines = [
            f"{alert.severity.name} - {alert.title}",
            alert.description,
            "",
            f"Rule: {alert.rule_id}",
            f"Origin: {alert_origin(alert, self.ip_info_by_ip)}",
            f"Detected: {alert.timestamp.astimezone().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"Recommended action: {alert.recommended_action}",
        ]
        if alert.attributes:
            lines.extend(["", "Alert fields:", *_detail_lines(alert.attributes)])
        info = self._alert_ip_info(alert)
        if info is not None:
            lines.extend(["", "IP intelligence:", *ip_info_lines(info)])
        browser_event = self._browser_event_from_alert(alert)
        if browser_event is not None:
            lines.extend(self._browser_context_lines_for_event(f"alert-{alert.id}", browser_event))
        self.alert_detail_item_id = item_id
        self._replace_text(self.alert_detail, "\n".join(lines), preserve_scroll)

    def show_event_ip_details(self, _event: tk.Event | None = None) -> None:
        if self.refreshing_event_tree:
            return
        selected = self.events_tree.selection()
        lines = ["Select an event to see its details."]
        item_id = selected[0] if selected else ""
        preserve_scroll = bool(item_id and item_id == self.event_detail_item_id)
        if selected:
            event = self.events_by_item.get(item_id)
            if event is not None:
                lines = [
                    f"Event: {event.kind}",
                    f"Source: {event.source}",
                    f"Time: {format_timestamp(event.timestamp)}",
                    "",
                    "Fields:",
                    *_detail_lines(event.attributes),
                ]
                ip_text = event.attributes.get("remote_ip")
                if isinstance(ip_text, str) and ip_text:
                    info = self.ip_info_by_ip.get(ip_text)
                    if info is None:
                        lines.extend(
                            [
                                "",
                                "IP intelligence:",
                                f"IP: {ip_text}",
                                "Lookup is queued or not available yet.",
                            ]
                        )
                    else:
                        lines.extend(["", "IP intelligence:", *ip_info_lines(info)])
                lines.extend(self._browser_context_lines_for_event(item_id, event))
        self.event_detail_item_id = item_id
        self._replace_text(self.ip_detail, "\n".join(lines), preserve_scroll)

    def _browser_event_from_alert(self, alert: Alert) -> Event | None:
        for event in alert.events:
            attrs = event.attributes
            process_name = attrs.get("process_name") or attrs.get("image_name")
            if _as_pid(attrs.get("pid")) is not None and is_browser_process_name(process_name):
                return event
        return None

    def _browser_context_lines_for_event(self, context_id: str, event: Event) -> list[str]:
        attrs = event.attributes
        process_name = str(attrs.get("process_name") or attrs.get("image_name") or "")
        pid = _as_pid(attrs.get("pid"))
        if pid is None or not is_browser_process_name(process_name):
            return []

        cached = self.browser_context_cache.get(pid)
        if cached is not None and time.monotonic() - cached[0] < 60.0:
            return ["", "Browser page context:", *cached[1]]

        if pid not in self.browser_context_pending:
            self.browser_context_pending.add(pid)
            timeout_seconds = self.config.process.detail_lookup_timeout_seconds

            def worker() -> None:
                try:
                    lines = browser_context_lines_for_process(pid, process_name, timeout_seconds)
                except Exception:
                    lines = ["Browser page context lookup failed. Windows may have blocked access to this process."]
                self.browser_context_results.put((pid, tuple(lines)))

            threading.Thread(
                target=worker,
                name=f"BrowserContext-{context_id}",
                daemon=True,
            ).start()

        return ["", "Browser page context:", "Checking browser page context..."]

    def _poll_browser_context_results(self) -> None:
        changed_pids: set[int] = set()
        while True:
            try:
                pid, lines = self.browser_context_results.get_nowait()
            except queue.Empty:
                break
            self.browser_context_pending.discard(pid)
            self.browser_context_cache[pid] = (time.monotonic(), lines)
            changed_pids.add(pid)

        if not changed_pids:
            return
        selected_event = self._selected_event()
        if selected_event is not None and _as_pid(selected_event.attributes.get("pid")) in changed_pids:
            self.show_event_ip_details(None)
        selected_alert = self._selected_alert()
        if selected_alert is not None:
            browser_event = self._browser_event_from_alert(selected_alert)
            if browser_event is not None and _as_pid(browser_event.attributes.get("pid")) in changed_pids:
                self.show_alert_details(None)

    def _schedule_update(self) -> None:
        for error in self.worker.pop_errors():
            messagebox.showerror("Monitor stopped", error)
        self._poll_browser_context_results()
        self._poll_app_icon_results()
        self._maybe_check_lm_studio()
        self._refresh_snapshot(self.worker.snapshot())
        self._update_status_button()
        self.root.after(500, self._schedule_update)

    def _maybe_check_lm_studio(self, force: bool = False) -> None:
        if not self._lm_analysis_enabled():
            while True:
                try:
                    self.llm_status_results.get_nowait()
                except queue.Empty:
                    break
            self.llm_server_status = None
            self.llm_status_checking = False
            self.llm_var.set("DISABLED")
            return

        while True:
            try:
                self.llm_server_status = self.llm_status_results.get_nowait()
                self.llm_status_checking = False
                self.llm_var.set(self._llm_status())
                self._sync_lm_model_options()
            except queue.Empty:
                break

        now = time.monotonic()
        interval = 60.0
        if self.llm_status_checking or (not force and now - self.last_llm_status_check < interval):
            return
        self.llm_status_checking = True
        self.last_llm_status_check = now
        config = self.config.llm

        def worker() -> None:
            status = check_lm_studio_server(config, timeout_seconds=1.0)
            self.llm_status_results.put(status)

        threading.Thread(target=worker, name="LMStudioStatus", daemon=True).start()
        self.llm_var.set(self._llm_status())

    def _refresh_snapshot(self, snapshot: RuntimeSnapshot) -> None:
        runtime_seconds = int((datetime.now(timezone.utc) - snapshot.started_at).total_seconds())
        self.runtime_var.set(format_duration(runtime_seconds))
        self.events_var.set(str(snapshot.total_events))
        self.alerts_var.set(str(snapshot.total_alerts))
        self.collectors_var.set(", ".join(snapshot.collectors) if snapshot.collectors else "none")
        self.status_var.set("Running" if self.worker.running else "Paused")
        self.ip_info_by_ip = {info.ip: info for info in snapshot.ip_intelligence}

        ip_changed = snapshot.ip_intelligence_version != self.last_ip_intelligence_version
        risk_signature = self._risk_signature(snapshot)
        if snapshot.total_alerts != self.last_alert_total or ip_changed:
            self._render_alerts(snapshot.recent_alerts)
            self.last_alert_total = snapshot.total_alerts
        if snapshot.total_events != self.last_event_total or ip_changed:
            self._render_events(snapshot.recent_events)
            self.last_event_total = snapshot.total_events
        if risk_signature != self.last_risk_signature:
            self._render_summary(snapshot)
            self.last_risk_signature = risk_signature
        if ip_changed:
            self.last_ip_intelligence_version = snapshot.ip_intelligence_version
            self.show_event_ip_details(None)
            self.show_alert_details(None)

        warning_text = "\n".join(snapshot.warnings) if snapshot.warnings else "No warnings."
        if warning_text != self.last_warning_text:
            self.warning_text.configure(state=tk.NORMAL)
            self.warning_text.delete("1.0", tk.END)
            self.warning_text.insert(tk.END, warning_text)
            self.warning_text.configure(state=tk.DISABLED)
            self.last_warning_text = warning_text

    def _render_alerts(self, alerts: tuple[Alert, ...]) -> None:
        selected = set(self.alerts_tree.selection())
        yview = self.alerts_tree.yview()
        self.alerts_by_id = {alert.id: alert for alert in alerts}
        self.refreshing_alert_tree = True
        try:
            children = self.alerts_tree.get_children()
            if children:
                self.alerts_tree.delete(*children)
            for alert in reversed(alerts):
                tag = alert.severity.name.lower()
                self.alerts_tree.insert(
                    "",
                    tk.END,
                    iid=alert.id,
                    values=alert_row(alert, self.ip_info_by_ip),
                    tags=(tag,),
                )
            restored = next((item_id for item_id in selected if item_id in self.alerts_by_id), "")
            if restored:
                self.alerts_tree.selection_set(restored)
                self.alerts_tree.focus(restored)
            if yview:
                self.alerts_tree.yview_moveto(yview[0])
        finally:
            self.refreshing_alert_tree = False

    def _render_events(self, events: tuple[Event, ...]) -> None:
        selected = set(self.events_tree.selection())
        yview = self.events_tree.yview()
        self.refreshing_event_tree = True
        try:
            children = self.events_tree.get_children()
            if children:
                self.events_tree.delete(*children)
            self.events_by_item = {}
            occurrence_counts: dict[str, int] = {}
            for index, event in enumerate(reversed(events)):
                signature = event_signature(event)
                occurrence_counts[signature] = occurrence_counts.get(signature, 0) + 1
                item_id = event_item_id(event, occurrence_counts[signature])
                self.events_by_item[item_id] = event
                self.events_tree.insert(
                "",
                tk.END,
                iid=item_id,
                image=self._event_icon(event),
                values=event_row(event, self.ip_info_by_ip),
                tags=("odd" if index % 2 else "even",),
            )
            restored = next((item_id for item_id in selected if item_id in self.events_by_item), "")
            if restored:
                self.events_tree.selection_set(restored)
                self.events_tree.focus(restored)
            if yview:
                self.events_tree.yview_moveto(yview[0])
        finally:
            self.refreshing_event_tree = False

    def _render_summary(self, snapshot: RuntimeSnapshot) -> None:
        children = self.risk_tree.get_children()
        if children:
            self.risk_tree.delete(*children)
        for index, host in enumerate(snapshot.risk_hosts):
            self.risk_tree.insert(
                "",
                tk.END,
                iid=f"risk-{host.ip}",
                values=host.to_row(),
                tags=("odd" if index % 2 else "even",),
            )
        self._draw_charts(snapshot)

    def _schedule_chart_redraw(self) -> None:
        if not hasattr(self, "chart_canvas"):
            return
        if self.chart_resize_after_id is not None:
            self.root.after_cancel(self.chart_resize_after_id)
        self.chart_resize_after_id = self.root.after(80, self._redraw_charts_after_resize)

    def _redraw_charts_after_resize(self) -> None:
        self.chart_resize_after_id = None
        if hasattr(self, "chart_canvas"):
            self._draw_charts(self.worker.snapshot())

    def _draw_charts(self, snapshot: RuntimeSnapshot) -> None:
        self.chart_canvas.delete("all")
        width = max(260, self.chart_canvas.winfo_width())
        y = 20
        y = self._draw_bar_group("Alert Severity", snapshot.stats.severity_counts, y, width)
        y = self._draw_bar_group("Top Countries", snapshot.stats.top_countries, y + 18, width)
        self._draw_bar_group("Top Ports", snapshot.stats.top_ports, y + 18, width)

    def _draw_bar_group(self, title: str, rows: tuple[tuple[str, int], ...], y: int, width: int) -> int:
        color = {
            "Alert Severity": COLORS["danger"],
            "Top Countries": COLORS["teal"],
            "Top Ports": COLORS["accent"],
        }.get(title, COLORS["accent"])
        title_font = tkfont.Font(family=FONT, size=10, weight="bold")
        label_font = tkfont.Font(family=FONT, size=9)
        value_font = tkfont.Font(family=FONT, size=9, weight="bold")
        self.chart_canvas.create_text(
            12,
            y,
            text=title,
            anchor="w",
            fill=COLORS["text"],
            font=title_font,
        )
        y += 20
        max_value = max((value for _, value in rows), default=1)
        label_width = max(78, min(150, int(width * 0.34)))
        bar_x = 12 + label_width + 12
        available_width = max(60, width - bar_x - 50)
        value_limit = width - 12
        for label, value in rows[:5]:
            bar_width = int(available_width * (value / max_value))
            label_text = self._fit_canvas_text(str(label), label_font, label_width)
            self.chart_canvas.create_text(12, y + 8, text=label_text, anchor="w", fill=COLORS["muted"], font=label_font)
            self.chart_canvas.create_rectangle(bar_x, y, bar_x + available_width, y + 16, fill=COLORS["panel_alt"], outline="")
            self.chart_canvas.create_rectangle(bar_x, y, bar_x + bar_width, y + 16, fill=color, outline="")
            value_x = min(bar_x + bar_width + 8, value_limit)
            value_anchor = "e" if value_x >= value_limit else "w"
            self.chart_canvas.create_text(value_x, y + 8, text=str(value), anchor=value_anchor, fill=COLORS["text"], font=value_font)
            y += 24
        if not rows:
            self.chart_canvas.create_text(12, y + 8, text="No data yet", anchor="w", fill=COLORS["muted"], font=label_font)
            y += 24
        return y

    def _fit_canvas_text(self, text: str, text_font: tkfont.Font, max_width: int) -> str:
        if text_font.measure(text) <= max_width:
            return text
        suffix = "..."
        trimmed = text
        while trimmed and text_font.measure(trimmed + suffix) > max_width:
            trimmed = trimmed[:-1]
        return (trimmed + suffix) if trimmed else suffix

    def _risk_signature(self, snapshot: RuntimeSnapshot) -> str:
        return "|".join(f"{host.ip}:{host.score}:{host.events}:{host.alerts}" for host in snapshot.risk_hosts[:20])

    def _update_status_button(self) -> None:
        self.start_button.configure(text="Pause" if self.worker.running else "Start")

    def _geoip_status(self) -> str:
        if not self.config.geoip.enabled:
            return "disabled"
        path = self.config.geoip.database_path
        return Path(path).name if path else "special ranges"

    def _ip_intelligence_status(self) -> str:
        if not self._ip_api_enabled():
            return "DISABLED"
        return self.config.ip_intelligence.provider

    def _ip_api_rate_status(self) -> str:
        if not self._ip_api_enabled():
            return "DISABLED"
        return f"{self.config.ip_intelligence.min_request_interval_seconds}s between requests"

    def _process_details_status(self) -> str:
        if not self._process_details_enabled():
            return "DISABLED"
        settings_vars = getattr(self, "settings_vars", {})
        timeout_var = settings_vars.get("process_detail_timeout")
        timeout = (
            str(timeout_var.get()).strip()
            if timeout_var is not None
            else str(self.config.process.detail_lookup_timeout_seconds)
        )
        return f"enabled; {timeout}s timeout"

    def _llm_status(self) -> str:
        if not self._lm_analysis_enabled():
            return "DISABLED"
        if self.llm_status_checking and self.llm_server_status is None:
            return "enabled; checking server"
        server = self.llm_server_status
        if server is not None:
            server_text = "online" if server.online else "offline"
            if server.online and server.model_available:
                model_text = "model loaded" if server.loaded else "model available"
            elif server.online:
                model_text = "model not listed"
            else:
                model_text = server.message
            if server.online and server.loaded_models:
                model_text = f"{model_text}; loaded: {', '.join(server.loaded_models[:3])}"
            return f"{server_text}; {model_text}"
        return f"enabled; {self.config.llm.model}"

    def _alert_ip_info(self, alert: Alert) -> IpIntelligence | None:
        ip_text = alert.attributes.get("remote_ip") or alert.attributes.get("actor")
        if not isinstance(ip_text, str):
            return None
        return self.ip_info_by_ip.get(ip_text)

    def _selected_event(self) -> Event | None:
        selected = self.events_tree.selection()
        if selected:
            return self.events_by_item.get(selected[0])
        return None

    def _selected_alert(self) -> Alert | None:
        selected = self.alerts_tree.selection()
        if not selected:
            return None
        return self.alerts_by_id.get(selected[0])

    def _selected_process_context(self) -> tuple[int, Event] | None:
        event = self._selected_event()
        if event is not None:
            pid = _as_pid(event.attributes.get("pid"))
            if pid is not None:
                return pid, event

        alert = self._selected_alert()
        if alert is not None:
            pid = _as_pid(alert.attributes.get("pid"))
            if pid is not None and alert.events:
                return pid, alert.events[0]
            for alert_event in alert.events:
                pid = _as_pid(alert_event.attributes.get("pid"))
                if pid is not None:
                    return pid, alert_event

        risk_ip = self._selected_risk_ip()
        if risk_ip:
            for risk_event in reversed(self.worker.snapshot().recent_events):
                attrs = risk_event.attributes
                if risk_ip not in {
                    str(attrs.get("remote_ip") or ""),
                    str(attrs.get("local_ip") or ""),
                    str(attrs.get("actor") or ""),
                }:
                    continue
                pid = _as_pid(attrs.get("pid"))
                if pid is not None:
                    return pid, risk_event
        return None

    def _selected_analysis_payload(self) -> tuple[str, dict[str, object]] | None:
        event = self._selected_event()
        if event is not None:
            return "event", event.to_dict()

        alert = self._selected_alert()
        if alert is not None:
            return "alert", alert.to_dict()

        selected_risk = self.risk_tree.selection()
        if selected_risk:
            item = self.risk_tree.item(selected_risk[0])
            values = item.get("values") or []
            if values:
                return (
                    "risk host",
                    {
                        "ip": values[0],
                        "score": values[1] if len(values) > 1 else "",
                        "events": values[2] if len(values) > 2 else "",
                        "alerts": values[3] if len(values) > 3 else "",
                        "country": values[4] if len(values) > 4 else "",
                        "ports": values[5] if len(values) > 5 else "",
                        "reasons": values[6] if len(values) > 6 else "",
                    },
                )
        return None

    def _selected_ip(self) -> str:
        selected_alert = self.alerts_tree.selection()
        if selected_alert:
            alert = self.alerts_by_id.get(selected_alert[0])
            if alert is not None:
                ip_text = alert.attributes.get("remote_ip") or alert.attributes.get("actor")
                if isinstance(ip_text, str) and ip_text:
                    return ip_text
        event = self._selected_event()
        if event is not None:
            ip_text = event.attributes.get("remote_ip")
            if isinstance(ip_text, str) and ip_text:
                return ip_text
        return self._selected_risk_ip()

    def _selected_risk_ip(self) -> str:
        selected_risk = self.risk_tree.selection()
        if selected_risk:
            item = self.risk_tree.item(selected_risk[0])
            values = item.get("values") or []
            if values:
                return str(values[0])
        return ""

    def _selected_blocked_ip(self) -> str:
        return self._selected_list_value(self.blocked_ip_list)

    def _selected_list_value(self, listbox: tk.Listbox) -> str:
        selected = listbox.curselection()
        if not selected:
            return ""
        value = str(listbox.get(selected[0]))
        return "" if value == "(empty)" else value

    def _add_ip_to_config_blocklist(self, ip_text: str) -> None:
        raw = dict(self.config.raw)
        raw["policy"] = dict(raw["policy"])
        blocklist = list(raw["policy"].get("blocklist_ips", []))
        if ip_text not in blocklist:
            blocklist.append(ip_text)
            raw["policy"]["blocklist_ips"] = blocklist
            save_config(raw, self.config_path)
            self.config = load_config(self.config_path)
            self.worker.ids.policy = SecurityPolicy(self.config.policy)
            if "block_ips" in getattr(self, "settings_vars", {}):
                self.settings_vars["block_ips"].set(",".join(blocklist))
            self._refresh_policy_lists()

    def _remove_policy_value(self, policy_key: str, value: str) -> bool:
        raw = dict(self.config.raw)
        raw["policy"] = dict(raw["policy"])
        current = [str(item) for item in raw["policy"].get(policy_key, [])]
        normalized_value = value.strip()
        next_values = [item for item in current if item.strip().lower() != normalized_value.lower()]
        if len(next_values) == len(current):
            return False
        raw["policy"][policy_key] = next_values
        save_config(raw, self.config_path)
        self.config = load_config(self.config_path)
        self.worker.ids.policy = SecurityPolicy(self.config.policy)
        self._sync_policy_entries_from_config()
        self._refresh_policy_lists()
        return True

    def _sync_policy_entries_from_config(self) -> None:
        if not hasattr(self, "settings_vars"):
            return
        policy = self.config.raw["policy"]
        mapping = {
            "allow_ips": "allowlist_ips",
            "block_ips": "blocklist_ips",
            "allow_countries": "allowlist_countries",
            "block_countries": "blocklist_countries",
            "allow_processes": "allowlist_process_names",
            "block_processes": "blocklist_process_names",
        }
        for var_name, policy_key in mapping.items():
            if var_name in self.settings_vars:
                self.settings_vars[var_name].set(",".join(policy.get(policy_key, [])))

    def _refresh_policy_lists(self) -> None:
        if not all(
            hasattr(self, name)
            for name in ("blocked_ip_list", "blocked_country_list", "blocked_process_list")
        ):
            return
        policy = self.config.raw.get("policy", {})
        self._fill_listbox(self.blocked_ip_list, policy.get("blocklist_ips", []))
        self._fill_listbox(self.blocked_country_list, policy.get("blocklist_countries", []))
        self._fill_listbox(self.blocked_process_list, policy.get("blocklist_process_names", []))

    def _fill_listbox(self, listbox: tk.Listbox, values: list[object]) -> None:
        listbox.delete(0, tk.END)
        if not values:
            listbox.insert(tk.END, "(empty)")
            listbox.itemconfig(0, foreground=COLORS["muted"])
            return
        for value in values:
            listbox.insert(tk.END, str(value))

    def _show_text_window(self, title: str, text: str) -> tk.Text:
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("760x420")
        window.configure(background=COLORS["bg"])
        frame = ttk.Frame(window, padding=12, style="App.TFrame")
        frame.pack(fill=tk.BOTH, expand=True)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text_widget = self._make_text_area(frame, height=16)
        text_widget.insert(tk.END, text)
        text_widget.configure(state=tk.DISABLED)
        return text_widget

    def _replace_text(
        self,
        text_widget: tk.Text,
        text: str,
        preserve_scroll: bool = False,
    ) -> None:
        yview = text_widget.yview() if preserve_scroll else None
        text_widget.configure(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, text)
        if yview:
            text_widget.yview_moveto(yview[0])
        text_widget.configure(state=tk.DISABLED)

    def close(self) -> None:
        for after_id in (
            self.theme_transition_after_id,
            self.chart_resize_after_id,
            self.resize_after_id,
        ):
            if after_id is not None:
                try:
                    self.root.after_cancel(after_id)
                except tk.TclError:
                    pass
        self.worker.shutdown()
        self.root.destroy()


def run_gui(config: AppConfig, config_path: str = "config/default.json") -> int:
    root = tk.Tk()
    IntrusionDetectionGui(root, config, config_path)
    root.mainloop()
    return 0
