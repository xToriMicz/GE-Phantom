# GE_Phantom

Packet-based bot for Granado Espada. Reverse-engineered from network traffic.

## Status: Phase 1 — Packet Capture & Protocol Discovery

### Goal
Auto Pick Item via packet interception (no process injection).

### Setup
```
pip install -r requirements.txt
```

Requires [Npcap](https://npcap.com/) installed on Windows.

### Usage
```bash
# Capture GE traffic (run as admin)
python -m src.sniffer.capture

# Analyze captured packets
python tools/analyze.py captures/session.json

# Live monitor
python tools/monitor.py
```
