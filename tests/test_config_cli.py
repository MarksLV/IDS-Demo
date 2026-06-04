from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import shutil
import uuid
import unittest
from pathlib import Path

from ids.cli import run_replay
from ids.config import AppConfig, DEFAULT_CONFIG, load_config


class ConfigValidationTests(unittest.TestCase):
    def test_builtin_default_config_keeps_external_services_opt_in(self) -> None:
        config = load_config(None)

        self.assertFalse(config.ip_intelligence.enabled)
        self.assertFalse(config.llm.enabled)
        self.assertEqual(config.llm.api_token, "")

    def test_builtin_default_config_does_not_contain_api_token(self) -> None:
        raw = json.dumps(DEFAULT_CONFIG)

        self.assertNotIn("sk-", raw)

    def test_builtin_default_config_has_light_theme(self) -> None:
        config = load_config(None)

        self.assertEqual(config.ui.theme, "light")

    def test_unknown_theme_is_rejected(self) -> None:
        data = copy.deepcopy(DEFAULT_CONFIG)
        data["ui"]["theme"] = "blue"

        with self.assertRaisesRegex(ValueError, "ui.theme"):
            AppConfig.from_mapping(data)

    def test_string_false_is_parsed_as_false(self) -> None:
        data = copy.deepcopy(DEFAULT_CONFIG)
        data["ip_intelligence"]["enabled"] = "false"

        config = AppConfig.from_mapping(data)

        self.assertFalse(config.ip_intelligence.enabled)

    def test_negative_threshold_is_rejected(self) -> None:
        data = copy.deepcopy(DEFAULT_CONFIG)
        data["detection"]["brute_force_threshold"] = -1

        with self.assertRaisesRegex(ValueError, "detection.brute_force_threshold"):
            AppConfig.from_mapping(data)

    def test_unknown_config_key_is_rejected(self) -> None:
        with _temporary_workspace_dir() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(
                json.dumps({"network": {"poll_intervals_seconds": 2}}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "Unknown configuration key"):
                load_config(path)

    def test_legacy_notifications_config_is_ignored(self) -> None:
        with _temporary_workspace_dir() as temp_dir:
            path = Path(temp_dir) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "notifications": {
                            "enabled": True,
                            "min_severity": "high",
                            "sound": True,
                            "flash_window": True,
                        }
                    }
                ),
                encoding="utf-8",
            )

            config = load_config(path)

            self.assertNotIn("notifications", config.raw)
            self.assertFalse(hasattr(config, "notifications"))

    def test_lm_studio_url_must_be_local(self) -> None:
        data = copy.deepcopy(DEFAULT_CONFIG)
        data["llm"]["url"] = "https://example.com/v1/chat/completions"

        with self.assertRaisesRegex(ValueError, "llm.url"):
            AppConfig.from_mapping(data)


class ReplayTests(unittest.TestCase):
    def test_replay_does_not_write_logs_by_default(self) -> None:
        with _temporary_workspace_dir() as temp_dir:
            root = Path(temp_dir)
            events_path = root / "events.jsonl"
            alerts_path = root / "alerts.jsonl"
            replay_input = root / "input.jsonl"
            replay_input.write_text(
                json.dumps(
                    {
                        "kind": "process_start",
                        "timestamp": "2026-01-01T12:03:00+00:00",
                        "source": "test",
                        "attributes": {"pid": 4440, "image_name": "mimikatz.exe"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            data = copy.deepcopy(DEFAULT_CONFIG)
            data["output"]["events_path"] = str(events_path)
            data["output"]["alerts_path"] = str(alerts_path)
            config = AppConfig.from_mapping(data)
            args = argparse.Namespace(
                path=str(replay_input),
                json=False,
                write_logs=False,
            )

            with contextlib.redirect_stdout(io.StringIO()):
                result = run_replay(config, args)

            self.assertEqual(result, 0)
            self.assertFalse(events_path.exists())
            self.assertFalse(alerts_path.exists())


@contextlib.contextmanager
def _temporary_workspace_dir():
    root = Path.cwd() / ".test_tmp"
    root.mkdir(exist_ok=True)
    path = root / uuid.uuid4().hex
    path.mkdir()
    try:
        yield str(path)
    finally:
        shutil.rmtree(path, ignore_errors=True)
        try:
            root.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
