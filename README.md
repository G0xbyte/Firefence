# 🔥 Firefence : CLI SEIM that run custom services

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Linux Only](https://img.shields.io/badge/Platform-Linux-orange.svg)](https://www.linux.org)

**Firefence** is a python wrapper that run services like a sniffer, ipfilter , anti ddos and more. It use **Scapy**, **Kernel Linux (IPSet)**.

Here is the list of services:
- Sniffer ✅
- Filter ✅
- No DDOS ✅
- No exfiltration ❌
- Fail2ban ❌
- IPS


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
<service> on # Starts a specific service.

<service> off # Stop a specific service.

status # See active and inactive services

# ⚠️ Services depend on each other, it will be detailed bellow
```
## 🔌 Services Commands

### Sniffer
The sniffer service will sniff eveything that is happening on the machine. It will create a socket so other services can acces the broadcast informations.
```bash
/
```
### Filter
#### ⚠️ **Sniffer** need to be started.
The filter service use 3 ipset: blacklist, whitelist and timeout so you can manage ip like you want.
```bash
filter log [on | off] # Enable or disable packet logging into the logfile

filter blacklist <IP> # Add an IP address to the blacklist

filter unblacklist <IP> # Remove an IP address from the blacklist

filter whitelist <IP> # Add an IP address to the whitelist

filter unwhitelist <IP> # Remove an IP address from the whitelist

filter timeout <IP> # Temporarily block an IP for 60 seconds

filter list # Display current blacklisted and whitelisted IPs (not working use 'sudo ipset list' instead)
```
### No DDOS
#### ⚠️ **Sniffer** & **Filter** need to be started.
The no ddos service will block ip that send to many request (adding them to the timemout ipset)
```bash
/
```

## ✨ Tips

#### For each service a logging system is implement to see what's happening I advice you to run `tail -f <logfile.log>` so you can track everything.