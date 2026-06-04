# Intrusion Detection System

A lightweight host-based intrusion detection system for Windows, macOS, and Linux. It monitors network connections, new processes, and optional authentication/log sources, then raises rule-based alerts for suspicious activity such as port scans, brute-force login attempts, dangerous ports, suspicious tools, and process bursts.

Network and authentication events are enriched with source-country metadata when a matching GeoIP range is available. Public IP addresses can optionally be looked up using the free `ipwho.is` API to show location, ISP, organization, ASN, domain, timezone, and proxy/VPN/Tor/hosting information.

The desktop interface provides tools for inspecting events, alerts, processes, and remote IPs. It can block selected IP addresses, export reports, replay captured events, and display detailed information about suspicious activity.

Optional local LM Studio integration allows a locally hosted LLM to analyze selected events, alerts, and risk hosts. It provides threat ratings, explanations, supporting evidence, and recommended actions without sending IDS data to a remote AI provider.

The project intentionally uses only the Python standard library, allowing it to run on a normal machine without a heavy installation process.

## Quick Start

Start the desktop interface by running:

~~~bash
python run_gui.py
~~~

## What It Detects

- **Port scans:** One remote host touches many local ports within a short period.
- **Connection bursts:** Sudden spikes of new connections from the same remote host.
- **Suspicious ports:** Common backdoor, remote-shell, Telnet, IRC, and administration ports.
- **Brute-force attempts:** Repeated failed authentication events or matching log lines.
- **Suspicious tools:** New processes such as `nmap.exe`, `netcat.exe`, `mimikatz.exe`, `psexec.exe`, and similar security-sensitive binaries.
- **Process bursts:** Unusually large numbers of new processes within a short period.
