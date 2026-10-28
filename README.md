# Stream-Based Network Traffic Analyzer & Threat Detector

Developed by **Rahaf Alshammari**

A production-ready, memory-efficient Network Traffic Analyzer built in Python using Scapy. Designed for security analysts and incident responders, this tool leverages stream-based processing to inspect large `.pcap` files, extract packet-level statistics, and automatically flag insecure protocols/ports (such as unencrypted Telnet traffic) without overloading memory.

---

## Key Features

- **Memory-Efficient Stream Processing:** Utilizes Scapy’s `PcapReader` to process packets iteratively, enabling seamless analysis of large datasets (`.pcap`) without high RAM consumption.
- **Automated Threat & Anomaly Detection:** Scans transport-layer headers for unencrypted or risky protocol ports (e.g., TCP Port 23 / Telnet) and triggers immediate security alerts.
- **Protocol Breakdown & Metrics:** Summarizes total packet counts and provides a statistical breakdown across IP protocols (`TCP`, `UDP`, and `Other`).
- **Clean CLI Output:** Displays real-time structured packet inspections with clear security status labeling.

---

## Technical Stack & Logic

- **Language:** Python 3
- **Core Library:** Scapy (`PcapReader`, `IP`, `TCP`, `UDP`)
- **Environment:** macOS / Linux / VS Code
- **Methodology:** 
  1. Opens network traffic files via streaming input (`PcapReader`).
  2. Evaluates network layer headers (`IP`) and transport layer ports (`TCP`/`UDP`).
  3. Evaluates port-level risks against security inspection rules.
  4. Generates real-time console reporting and comprehensive summary statistics.

---

## Getting Started

### Prerequisites

Ensure you have Python 3 and Scapy installed:

```bash
pip install scapy