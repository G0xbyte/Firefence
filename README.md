# 🔥 Firefence : CLI SEIM that run custom services

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Linux Only](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.linux.org)

**Firefence** is a python wrapper with ipset to act like a firewall you can start sniffer engine and services.

Here is the list of engine and their services.
- Packet sniffer:
DDOS Shield
Data Loss Prevention
- Log sniffer:
Fail2ban
Web IDS

You can edit everything in the config.toml

## 🛠️ Installation

### Prerequisites
* Linux (Kernel with Netlink & IPSet support)
* Python 3.8+
* Redis Server
* Root privileges (required for raw socket access)

### Setup
```bash
# Install system tools
sudo apt update && sudo apt install redis-server ipset iptables -y

# Create you venv
python3 -m venv firenv

# Start your venv
source ./firenv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
sudo ./firenv/bin/python3 firefence.py
```
## 🚀 How It Works

Firefence acts as a wrapper that orchestrates and manages the different security services available on the system.
It provides a single entry point to start, stop, and monitor each service.

### Available Commands

```bash
start <engine> # Starts an engine.
start <engine>.<service> # Starts a engine's service.

stop <engine> # Stop an engine.
stop <engine>.<service> # Stop a engine's service.

info # See active and inactive services

run <engine> cmd args # Run a command for an engine
run <engine>.<service> cmd args # Run a command for an engine's service.

```
## 🔌 Services Commands

### Sniffer
### ⚠️ ** TODO **
