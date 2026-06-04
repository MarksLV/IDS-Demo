from __future__ import annotations

import unittest

from ids.collectors import (
    NetworkConnection,
    ProcessCollector,
    enrich_connection_process_names,
    parse_netstat_output,
    parse_posix_process_output,
    parse_ss_output,
)
from ids.config import ProcessConfig


class NetworkParsingTests(unittest.TestCase):
    def test_parse_windows_netstat_tcp(self) -> None:
        text = "  TCP    127.0.0.1:49707    93.184.216.34:443    ESTABLISHED    123\r\n"

        [connection] = parse_netstat_output(text)

        self.assertEqual(connection.protocol, "TCP")
        self.assertEqual(connection.local_ip, "127.0.0.1")
        self.assertEqual(connection.local_port, 49707)
        self.assertEqual(connection.remote_ip, "93.184.216.34")
        self.assertEqual(connection.remote_port, 443)
        self.assertEqual(connection.state, "ESTABLISHED")
        self.assertEqual(connection.pid, 123)

    def test_parse_unix_netstat_tcp(self) -> None:
        text = "tcp 0 0 192.168.1.10:51514 93.184.216.34:443 ESTABLISHED 123/python\n"

        [connection] = parse_netstat_output(text)

        self.assertEqual(connection.protocol, "TCP")
        self.assertEqual(connection.local_ip, "192.168.1.10")
        self.assertEqual(connection.local_port, 51514)
        self.assertEqual(connection.remote_ip, "93.184.216.34")
        self.assertEqual(connection.remote_port, 443)
        self.assertEqual(connection.state, "ESTABLISHED")
        self.assertEqual(connection.pid, 123)

    def test_parse_ss_tcp(self) -> None:
        text = (
            'tcp ESTAB 0 0 192.168.1.10:51514 93.184.216.34:443 '
            'users:(("python",pid=123,fd=5))\n'
        )

        [connection] = parse_ss_output(text)

        self.assertEqual(connection.protocol, "TCP")
        self.assertEqual(connection.local_ip, "192.168.1.10")
        self.assertEqual(connection.local_port, 51514)
        self.assertEqual(connection.remote_ip, "93.184.216.34")
        self.assertEqual(connection.remote_port, 443)
        self.assertEqual(connection.state, "ESTAB")
        self.assertEqual(connection.pid, 123)

    def test_enrich_connection_process_names_from_pid(self) -> None:
        connection = NetworkConnection(
            protocol="TCP",
            local_ip="127.0.0.1",
            local_port=61385,
            remote_ip="127.0.0.1",
            remote_port=1234,
            state="TIME_WAIT",
            pid=123,
        )

        [enriched] = enrich_connection_process_names([connection], {123: "python.exe"})

        self.assertEqual(enriched.process_name, "python.exe")
        self.assertEqual(enriched.to_event("network").attributes["process_name"], "python.exe")

    def test_enrich_pid_zero_as_system_kernel(self) -> None:
        connection = NetworkConnection(
            protocol="TCP",
            local_ip="10.0.0.5",
            local_port=60620,
            remote_ip="40.79.141.152",
            remote_port=443,
            state="TIME_WAIT",
            pid=0,
        )

        [enriched] = enrich_connection_process_names([connection], {})

        self.assertEqual(enriched.process_name, "System / kernel")


class ProcessParsingTests(unittest.TestCase):
    def test_parse_posix_process_output_keeps_start_time(self) -> None:
        text = "123 Mon Jun  1 07:25:12 2026 python\n"

        [process] = parse_posix_process_output(text)

        self.assertEqual(process["pid"], "123")
        self.assertEqual(process["start_time"], "Mon Jun 1 07:25:12 2026")
        self.assertEqual(process["image_name"], "python")

    def test_process_collector_forgets_exited_pid_before_reuse(self) -> None:
        collector = FakeProcessCollector(
            [
                [_process("42", "python", "one")],
                [_process("42", "python", "one")],
                [],
                [_process("42", "python", "two")],
            ]
        )

        self.assertEqual(collector.poll(), [])
        self.assertEqual(collector.poll(), [])
        self.assertEqual(collector.poll(), [])
        events = collector.poll()

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].attributes["pid"], 42)
        self.assertEqual(events[0].attributes["image_name"], "python")
        self.assertEqual(events[0].attributes["start_time"], "two")


class FakeProcessCollector(ProcessCollector):
    def __init__(self, snapshots: list[list[dict[str, str]]]) -> None:
        super().__init__(
            ProcessConfig(
                enabled=True,
                poll_interval_seconds=0.2,
                baseline_existing_on_start=True,
                max_seen_processes=100,
                detail_lookup_enabled=False,
                detail_lookup_timeout_seconds=0.2,
                suspicious_process_names=(),
            )
        )
        self.snapshots = snapshots

    def _snapshot(self) -> list[dict[str, str]]:
        return self.snapshots.pop(0)


def _process(pid: str, image_name: str, start_time: str) -> dict[str, str]:
    return {
        "pid": pid,
        "image_name": image_name,
        "start_time": start_time,
        "session_name": "",
        "memory": "",
    }


if __name__ == "__main__":
    unittest.main()
