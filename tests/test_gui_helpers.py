from __future__ import annotations

import unittest
import urllib.error
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ids.config import AppConfig, DEFAULT_CONFIG
from ids.gui import IntrusionDetectionGui
from ids.llm import (
    TRIAGE_SYSTEM_PROMPT,
    _extract_chat_content,
    _has_reasoning_output,
    _reasoning_param_rejected,
    _strip_thinking,
    analyze_security_payload,
    build_triage_context,
    check_lm_studio_server,
    models_url,
)
from ids.models import Event
from ids.ui_formatters import event_item_id, event_row, event_signature, process_label


class GuiHelperTests(unittest.TestCase):
    def test_event_item_id_is_stable_for_same_event(self) -> None:
        event = Event(
            kind="network_connection",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            source="test",
            attributes={"remote_ip": "203.0.113.1", "pid": 123},
        )

        self.assertEqual(event_signature(event), event_signature(event))
        self.assertEqual(event_item_id(event, 1), event_item_id(event, 1))
        self.assertNotEqual(event_item_id(event, 1), event_item_id(event, 2))

    def test_event_row_shows_likely_app_owner(self) -> None:
        event = Event(
            kind="network_connection",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            source="network",
            attributes={
                "protocol": "TCP",
                "local_ip": "127.0.0.1",
                "local_port": 61385,
                "remote_ip": "127.0.0.1",
                "remote_port": 1234,
                "state": "TIME_WAIT",
                "pid": 123,
                "process_name": "python.exe",
            },
        )

        row = event_row(event)

        self.assertEqual(process_label(event), "python.exe (123)")
        self.assertEqual(row[5], "python.exe (123)")
        self.assertIn("app=python.exe", row[7])


class GuiLlmStateTests(unittest.TestCase):
    def test_disabled_option_locks_lm_controls_and_sets_disabled_status(self) -> None:
        gui = IntrusionDetectionGui.__new__(IntrusionDetectionGui)
        gui.setting_bools = {"llm_enabled": FakeVariable(False)}
        gui.config = SimpleNamespace(llm=SimpleNamespace(enabled=True, model="test-model"))
        gui.lm_setting_labels = [Mock(), Mock()]
        gui.lm_setting_controls = [Mock(), Mock()]
        gui.lm_setting_tooltips = [Mock(), Mock()]
        gui.refresh_lm_status_button = Mock()
        gui.refresh_lm_status_tooltip = Mock()
        gui.lm_analyze_buttons = [Mock(), Mock(), Mock()]
        gui.lm_analyze_tooltips = [Mock(), Mock(), Mock()]
        gui.llm_var = FakeVariable("")
        gui.settings_vars = {
            "llm_url": FakeVariable("http://127.0.0.1:1234/api/v1/chat"),
            "llm_model": FakeVariable("test-model"),
            "llm_api_token": FakeVariable("test-token"),
        }
        gui._reset_lm_status_probe = Mock()

        gui._update_lm_controls_state()

        for label in gui.lm_setting_labels:
            label.configure.assert_called_once_with(style="DisabledMetricName.TLabel")
            label.state.assert_not_called()
        for control in gui.lm_setting_controls:
            control.state.assert_called_once_with(["disabled"])
        for tooltip in gui.lm_setting_tooltips:
            tooltip.set_enabled.assert_called_once_with(True)
        gui.refresh_lm_status_button.state.assert_called_once_with(["disabled"])
        gui.refresh_lm_status_tooltip.set_enabled.assert_called_once_with(True)
        for button in gui.lm_analyze_buttons:
            button.state.assert_called_once_with(["disabled"])
        for tooltip in gui.lm_analyze_tooltips:
            tooltip.set_enabled.assert_called_once_with(True)
        gui._reset_lm_status_probe.assert_called_once_with()
        self.assertEqual(gui.llm_var.get(), "DISABLED")
        self.assertEqual(gui.settings_vars["llm_model"].get(), "test-model")
        self.assertEqual(gui.settings_vars["llm_api_token"].get(), "test-token")

    def test_disabled_refresh_does_not_probe_lm_studio(self) -> None:
        gui = IntrusionDetectionGui.__new__(IntrusionDetectionGui)
        gui.setting_bools = {"llm_enabled": FakeVariable(False)}
        gui.config = SimpleNamespace(llm=SimpleNamespace(enabled=True))
        gui.llm_var = FakeVariable("")
        gui._reset_lm_status_probe = Mock()
        gui._maybe_check_lm_studio = Mock()

        gui.refresh_lm_studio_status()

        gui._reset_lm_status_probe.assert_not_called()
        gui._maybe_check_lm_studio.assert_not_called()
        self.assertEqual(gui.llm_var.get(), "DISABLED")


class GuiOptionDependencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gui = IntrusionDetectionGui.__new__(IntrusionDetectionGui)
        self.gui.config = SimpleNamespace(
            process=SimpleNamespace(
                detail_lookup_enabled=True,
                detail_lookup_timeout_seconds=2.5,
            ),
            ip_intelligence=SimpleNamespace(
                enabled=True,
                provider="ipwho.is",
                min_request_interval_seconds=1.1,
            ),
        )
        self.gui.setting_bools = {
            "process_details": FakeVariable(False),
            "ip_api_enabled": FakeVariable(False),
        }
        self.gui.settings_vars = {
            "process_detail_timeout": FakeVariable("4.0"),
            "ip_api_url": FakeVariable("https://ipwho.is/{ip}"),
        }

    def test_disabled_options_lock_related_controls_and_actions(self) -> None:
        self.gui.process_detail_setting_labels = [Mock()]
        self.gui.process_detail_setting_controls = [Mock()]
        self.gui.process_detail_setting_tooltips = [Mock()]
        self.gui.process_detail_buttons = [Mock(), Mock()]
        self.gui.process_detail_tooltips = [Mock(), Mock()]
        self.gui.ip_api_setting_labels = [Mock()]
        self.gui.ip_api_setting_controls = [Mock()]
        self.gui.ip_api_setting_tooltips = [Mock()]
        self.gui.process_details_var = FakeVariable("")
        self.gui.ip_intel_var = FakeVariable("")
        self.gui.ip_api_rate_var = FakeVariable("")

        self.gui._update_process_detail_controls_state()
        self.gui._update_ip_api_controls_state()

        self.gui.process_detail_setting_labels[0].configure.assert_called_once_with(
            style="DisabledMetricName.TLabel"
        )
        for button in self.gui.process_detail_buttons:
            button.state.assert_called_once_with(["disabled"])
        self.gui.ip_api_setting_labels[0].configure.assert_called_once_with(
            style="DisabledMetricName.TLabel"
        )
        self.assertEqual(self.gui.process_details_var.get(), "DISABLED")
        self.assertEqual(self.gui.ip_intel_var.get(), "DISABLED")
        self.assertEqual(self.gui.ip_api_rate_var.get(), "DISABLED")
        self.assertEqual(self.gui.settings_vars["process_detail_timeout"].get(), "4.0")
        self.assertEqual(self.gui.settings_vars["ip_api_url"].get(), "https://ipwho.is/{ip}")

    def test_process_detail_action_is_guarded_when_disabled(self) -> None:
        self.gui._selected_process_context = Mock()

        with patch("ids.gui.messagebox.showwarning") as showwarning:
            self.gui.show_selected_process_details()

        self.gui._selected_process_context.assert_not_called()
        showwarning.assert_called_once()


class GuiWindowBehaviorTests(unittest.TestCase):
    def test_windows_taskbar_entry_uses_normal_app_window_style(self) -> None:
        gui = IntrusionDetectionGui.__new__(IntrusionDetectionGui)
        gui.root = Mock()
        gui.root.winfo_id.return_value = 123
        user32 = Mock()
        user32.GetParent.return_value = 456
        user32.GetWindowLongW.return_value = 0x00000080

        with (
            patch("ids.gui.platform.system", return_value="Windows"),
            patch("ids.gui.ctypes.windll", SimpleNamespace(user32=user32), create=True),
        ):
            gui._configure_windows_taskbar_entry()

        user32.SetWindowLongW.assert_called_once_with(456, -20, 0x00040000)
        user32.SetWindowPos.assert_called_once_with(456, 0, 0, 0, 0, 0x0027)


class LlmHelperTests(unittest.TestCase):
    def test_strip_thinking_removes_deepseek_think_block(self) -> None:
        text = "<think>private scratch</think>\nSummary: inspect the process."

        self.assertEqual(_strip_thinking(text).strip(), "Summary: inspect the process.")

    def test_triage_prompt_separates_threat_rating_from_confidence(self) -> None:
        self.assertIn("Threat rating:", TRIAGE_SYSTEM_PROMPT)
        self.assertIn("only numeric rating", TRIAGE_SYSTEM_PROMPT)
        self.assertIn("do not include a confidence score", TRIAGE_SYSTEM_PROMPT)

    def test_extract_native_chat_output(self) -> None:
        data = {
            "output": [
                {"type": "reasoning", "content": "internal"},
                {"type": "message", "content": "Summary: suspicious process."},
            ]
        }

        self.assertEqual(_extract_chat_content(data), "Summary: suspicious process.")

    def test_extract_native_chat_output_with_content_parts(self) -> None:
        data = {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "text", "text": "Threat rating: Low."},
                        {"type": "text", "text": "Evidence: routine browser traffic."},
                    ],
                }
            ]
        }

        self.assertEqual(
            _extract_chat_content(data),
            "Threat rating: Low.\nEvidence: routine browser traffic.",
        )

    def test_reasoning_only_output_is_detected(self) -> None:
        data = {"output": [{"type": "reasoning", "content": "internal"}]}

        self.assertTrue(_has_reasoning_output(data))
        self.assertEqual(_extract_chat_content(data), "")

    def test_reasoning_param_rejection_is_detected(self) -> None:
        detail = {
            "error": {
                "message": "Model does not expose reasoning configuration.",
                "param": "reasoning",
                "code": "invalid_value",
            }
        }

        import json

        self.assertTrue(_reasoning_param_rejected(json.dumps(detail)))

    def test_analysis_retries_without_reasoning_when_model_rejects_it(self) -> None:
        data = DEFAULT_CONFIG.copy()
        data["llm"] = dict(DEFAULT_CONFIG["llm"])
        data["llm"]["enabled"] = True
        config = AppConfig.from_mapping(data).llm
        requests: list[dict[str, object]] = []

        def fake_urlopen(request, timeout: float):
            import json

            requests.append(json.loads(request.data.decode("utf-8")))
            if len(requests) == 1:
                raise urllib.error.HTTPError(
                    request.full_url,
                    400,
                    "Bad Request",
                    {},
                    FakeErrorBody(
                        {
                            "error": {
                                "message": "Model does not expose reasoning configuration.",
                                "type": "invalid_request",
                                "param": "reasoning",
                                "code": "invalid_value",
                            }
                        }
                    ),
                )
            return FakeResponse(
                {"output": [{"type": "message", "content": "Threat rating: Low (1/10) - okay."}]}
            )

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = analyze_security_payload(config, "event", {"kind": "process_start"})

        self.assertIn("Threat rating: Low", result)
        self.assertEqual(requests[0]["reasoning"], "off")
        self.assertNotIn("reasoning", requests[1])

    def test_models_url_uses_native_v1_path(self) -> None:
        self.assertEqual(
            models_url("http://127.0.0.1:1234/api/v1/chat"),
            "http://127.0.0.1:1234/api/v1/models",
        )

    def test_lm_studio_status_detects_configured_model(self) -> None:
        config = AppConfig.from_mapping(DEFAULT_CONFIG).llm
        body = {
            "models": [
                {
                    "type": "llm",
                    "key": "deepseek-r1-0528-qwen3-8b",
                    "display_name": "DeepSeek R1",
                    "loaded_instances": [{"id": "deepseek-r1-0528-qwen3-8b"}],
                }
            ]
        }

        with patch("urllib.request.urlopen", return_value=FakeResponse(body)):
            status = check_lm_studio_server(config)

        self.assertTrue(status.online)
        self.assertTrue(status.model_available)
        self.assertTrue(status.loaded)
        self.assertEqual(status.loaded_models, ("deepseek-r1-0528-qwen3-8b",))

    def test_triage_context_marks_routine_microsoft_time_wait_as_low_risk(self) -> None:
        context = build_triage_context(
            "event",
            {
                "kind": "network_connection",
                "attributes": {
                    "protocol": "TCP",
                    "local_ip": "10.12.3.42",
                    "local_port": 60620,
                    "remote_ip": "40.79.141.152",
                    "remote_port": 443,
                    "state": "TIME_WAIT",
                    "pid": 0,
                    "remote_organization": "Microsoft Corporation",
                },
            },
        )

        self.assertLessEqual(context["score_0_to_10"], 1)
        self.assertEqual(context["likely_verdict"], "probably okay")
        self.assertTrue(
            any("TIME_WAIT" in signal for signal in context["benign_signals"])
        )
        self.assertTrue(
            any("PID 0" in note for note in context["notes_for_model"])
        )

    def test_triage_context_marks_suspicious_process_high(self) -> None:
        context = build_triage_context(
            "event",
            {
                "kind": "process_start",
                "attributes": {"image_name": "mimikatz.exe", "pid": 123},
            },
        )

        self.assertGreaterEqual(context["score_0_to_10"], 6)
        self.assertIn(context["rating"], {"High", "Critical"})

    def test_triage_context_includes_likely_network_process_owner(self) -> None:
        context = build_triage_context(
            "event",
            {
                "kind": "network_connection",
                "attributes": {
                    "local_ip": "10.0.0.5",
                    "local_port": 51514,
                    "remote_ip": "93.184.216.34",
                    "remote_port": 443,
                    "state": "ESTABLISHED",
                    "pid": 123,
                    "process_name": "msedge.exe",
                },
            },
        )

        self.assertTrue(
            any("msedge.exe" in note for note in context["notes_for_model"])
        )


class FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        import json

        return json.dumps(self.payload).encode("utf-8")


class FakeVariable:
    def __init__(self, value: object) -> None:
        self.value = value

    def get(self) -> object:
        return self.value

    def set(self, value: object) -> None:
        self.value = value


class FakeErrorBody:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def read(self, _limit: int = -1) -> bytes:
        import json

        return json.dumps(self.payload).encode("utf-8")

    def close(self) -> None:
        return None


if __name__ == "__main__":
    unittest.main()
