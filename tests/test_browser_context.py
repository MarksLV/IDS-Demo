from __future__ import annotations

import unittest
import subprocess
from unittest.mock import patch

from ids.browser_context import (
    browser_context_lines_for_process,
    extract_urls_from_command_line,
    is_browser_process_name,
)


class BrowserContextTests(unittest.TestCase):
    def test_browser_process_names_match_common_browsers(self) -> None:
        self.assertTrue(is_browser_process_name("chrome.exe"))
        self.assertTrue(is_browser_process_name(r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
        self.assertTrue(is_browser_process_name("msedge"))
        self.assertFalse(is_browser_process_name("python.exe"))

    def test_extract_urls_from_command_line(self) -> None:
        command_line = (
            r'"C:\Program Files\Google\Chrome\Application\chrome.exe" '
            "--app=https://example.com/dashboard "
            '"https://openai.com/docs"'
        )

        self.assertEqual(
            extract_urls_from_command_line(command_line),
            ["https://example.com/dashboard", "https://openai.com/docs"],
        )

    def test_browser_context_returns_failure_line_instead_of_hanging(self) -> None:
        timeout = subprocess.TimeoutExpired(["powershell"], timeout=0.01)
        with patch("ids.browser_context.get_process_details", side_effect=timeout):
            lines = browser_context_lines_for_process(123, "chrome.exe", timeout_seconds=0.01, devtools_ports=())

        self.assertTrue(any("timed out" in line for line in lines))
        self.assertFalse(any("powershell" in line.lower() for line in lines))


if __name__ == "__main__":
    unittest.main()
