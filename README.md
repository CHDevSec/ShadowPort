# 🔍 ShadowPort - Advanced Network Reconnaissance & Port Scanning Tool

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/chdevsec/shadowport.svg)](https://github.com/chdevsec/shadowport/issues)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/chdevsec/shadowport/graphs/commit-activity)

> **Professional network reconnaissance tool for advanced port scanning and service enumeration - CHDEVSEC Pentest Arsenal**

## 📋 Table of Contents
- [Features](#-features)
- [Installation](#-installation)
- [Basic Usage](#-basic-usage)
- [Advanced Options](#-advanced-options)
- [Scanning Techniques](#-scanning-techniques)
- [Reports](#-reports)
- [Examples](#-examples)
- [Disclaimer](#-disclaimer)
- [License](#-license)

## 🚀 Features

### 🔥 Core Functionality
| Feature | Description |
|---------|-------------|
| **Multi-Protocol Scanning** | TCP, UDP, SYN scanning with stealth capabilities |
| **Service Detection** | Advanced service fingerprinting and banner grabbing |
| **DNS Enumeration** | Comprehensive DNS reconnaissance and subdomain discovery |
| **SSH Brute Force** | Intelligent SSH credential testing with rate limiting |

### 🛡️ Stealth Capabilities
```bash
# Advanced Evasion Techniques
SYN Stealth Scan    → Bypass basic firewalls
TCP Connect Scan    → Full connection establishment
UDP Scan           → Discover UDP services
Custom Packet Craft → Evade detection systems
```

## 📊 Output Formats
```
# Supported Formats
- JSON (structured data)
- XML (detailed reports)
- TXT (simple output)
- CSV (spreadsheet compatible)
```

## 🛠️ Installation

### Prerequisites
ShadowPort is designed to run on penetration testing distributions:

```bash
# Supported Operating Systems
- Kali Linux (Recommended)
- Parrot Security OS
- BlackArch Linux  
- Debian/Ubuntu based systems
```

### Verify Python Version
```bash
python3 --version  # Requires Python 3.6+
```

### Installation Steps
```bash
# Clone repository
git clone https://github.com/chdevsec/ShadowPort.git
cd ShadowPort

# Install dependencies
pip install -r requirements.txt

# Alternative installation with pip3
pip3 install -r requirements.txt
```

### Dependencies
```
scapy>=2.4.5
requests>=2.25.1
dnspython>=2.1.0
paramiko>=2.7.2
colorama>=0.4.4
python-nmap>=0.6.1
```

### System Dependencies & Core Tools

#### Essential System Packages
```bash
# Update package repositories
sudo apt update && sudo apt upgrade -y

# Install core networking tools (REQUIRED)
sudo apt install nmap masscan dnsutils netcat-traditional

# Install Python development packages
sudo apt install python3-dev python3-pip build-essential

# Install Scapy system dependencies (CRITICAL for stealth scanning)
sudo apt install python3-scapy libpcap-dev tcpdump

# Alternative Scapy installation for advanced features
sudo apt install python3-scapy python3-cryptography
```

#### Nmap Integration (HIGHLY RECOMMENDED)
```bash
# Verify Nmap installation
nmap --version

# Install latest Nmap from source (optional)
wget https://nmap.org/dist/nmap-7.94.tar.bz2
tar -xjf nmap-7.94.tar.bz2
cd nmap-7.94
./configure && make && sudo make install
```

#### Raw Socket Permissions (ESSENTIAL for Stealth Mode)
```bash
# Method 1: Grant capabilities to Python (RECOMMENDED)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)

# Method 2: Always run with sudo (ALTERNATIVE)
# sudo python3 shadowport.py target --stealth

# Verify raw socket access
python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP); print('Raw sockets: OK')"
```

#### Distribution-Specific Instructions

**🐉 Kali Linux:**
```bash
# All tools pre-installed, just update
sudo apt update && sudo apt install python3-pip
pip3 install -r requirements.txt
```

**🦜 Parrot Security OS:**
```bash
# Install missing packages
sudo apt install python3-scapy libpcap-dev
pip3 install -r requirements.txt
```

**🔧 Debian/Ubuntu:**
```bash
# Complete installation from scratch
sudo apt install nmap python3-scapy python3-pip libpcap-dev tcpdump
pip3 install -r requirements.txt
```

## 🎯 Basic Usage

```bash
python3 shadowport.py [TARGET] [OPTIONS]
```

### Quick Start Examples
```bash
# Basic port scan
python3 shadowport.py 192.168.1.1

# Scan specific ports
python3 shadowport.py 192.168.1.1 -p 22,80,443,8080

# Stealth SYN scan
python3 shadowport.py 192.168.1.1 --stealth

# Full network scan
python3 shadowport.py 192.168.1.0/24
```

## ⚙️ Advanced Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --ports` | Port range (22,80,443 or 1-1000) | Top 1000 |
| `-t, --threads` | Number of threads | 100 |
| `--stealth` | SYN stealth scanning | False |
| `--udp` | UDP port scanning | False |
| `--dns` | DNS enumeration | False |
| `--ssh-brute` | SSH brute force attack | False |
| `-o, --output` | Output file | None |
| `--format` | Output format (json/xml/txt/csv) | txt |
| `--timeout` | Connection timeout | 3 |
| `--delay` | Delay between requests | 0.1 |

## 🔧 Scanning Techniques

### Port Scanning Methods
```python
SCAN_TYPES = {
    "tcp_connect": "Full TCP connection scan",
    "syn_stealth": "SYN stealth scan (requires root)",
    "udp_scan": "UDP service discovery",
    "fin_scan": "FIN scan for firewall evasion",
    "null_scan": "NULL scan technique"
}
```

### Service Detection
```bash
# Banner Grabbing
HTTP/1.1 Server: Apache/2.4.41
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
220 ProFTPD 1.3.6 Server ready

# Service Fingerprinting
Port 22/tcp  → SSH (OpenSSH 8.2)
Port 80/tcp  → HTTP (Apache 2.4.41)
Port 443/tcp → HTTPS (Apache 2.4.41)
```

## 📊 Report Samples

### **JSON Report Preview**
```json
{
  "target": "192.168.1.100",
  "scan_time": "2024-06-29T10:30:00Z",
  "open_ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.2p1",
      "state": "open"
    }
  ],
  "dns_info": {
    "hostname": "target.local",
    "subdomains": ["www", "mail", "ftp"]
  }
}
```

### Console Output
```bash
[+] ShadowPort v1.0 - Network Reconnaissance Tool
[+] Target: 192.168.1.100
[+] Starting port scan...

PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.2p1
80/tcp   open   http       Apache 2.4.41
443/tcp  open   https      Apache 2.4.41
3306/tcp open   mysql      MySQL 8.0.25

[+] Scan completed in 45.2 seconds
[+] 4 open ports discovered
```

## 💡 Real-World Usage Examples

### Example 1: Corporate Network Discovery
```bash
# Scenario: Security assessment of company network
python3 shadowport.py 10.0.0.0/24 \
  --stealth \
  -p 21,22,23,25,53,80,135,139,443,445,993,995,3389 \
  --dns \
  --format json \
  -o corporate_scan.json \
  --threads 100 \
  --delay 0.5

# Expected Output:
[+] Discovered 15 live hosts
[+] Found 47 open ports across network
[+] Critical services: RDP (3389), SMB (445), SSH (22)
[+] Potential vulnerabilities: 3 hosts with Telnet (23)
```

### Example 2: Web Application Infrastructure Mapping
```bash
# Scenario: Mapping web application infrastructure
python3 shadowport.py webapp.company.com \
  --dns \
  -p 80,443,8000,8080,8443,9000,9443 \
  --format xml \
  -o webapp_infrastructure.xml

# DNS Enumeration Results:
api.webapp.company.com     → 203.0.113.10
admin.webapp.company.com   → 203.0.113.15
staging.webapp.company.com → 203.0.113.20
```

### Example 3: SSH Server Hardening Assessment
```bash
# Scenario: Testing SSH security across server farm
python3 shadowport.py servers.txt \
  -p 22,2222 \
  --ssh-brute \
  -u common_users.txt \
  -w weak_passwords.txt \
  --delay 2.0 \
  -o ssh_assessment.csv

# Sample Results:
192.168.1.50:22   → SUCCESS: admin:admin123
192.168.1.51:2222 → SUCCESS: root:password
192.168.1.52:22   → FAILED: Strong authentication
```

### Example 4: IoT Device Discovery
```bash
# Scenario: Identifying IoT devices on network
python3 shadowport.py 192.168.1.0/24 \
  -p 23,80,443,502,1883,8080,8443,9000 \
  --format json \
  -o iot_devices.json

# Typical IoT Signatures:
Port 1883 → MQTT Broker (IoT Communication)
Port 502  → Modbus (Industrial Control)
Port 23   → Telnet (Legacy IoT Devices)
```

### Example 5: Firewall Rule Testing
```bash
# Scenario: Testing firewall configuration
python3 shadowport.py internal.company.com \
  --stealth \
  -p 1-65535 \
  --format txt \
  -o firewall_test.txt \
  --threads 200

# Firewall Analysis:
Allowed: 22,80,443 (Expected)
Blocked: 135,139,445 (SMB - Good)
Unexpected: 3389 (RDP - Security Risk)
```

### Example 6: Bug Bounty Reconnaissance
```bash
# Scenario: Initial reconnaissance for bug bounty
python3 shadowport.py target.hackerone.com \
  --dns \
  -p 80,443,8000-8999 \
  --format json \
  -o bugbounty_recon.json \
  --delay 1.0

# Subdomain Discovery:
api.target.hackerone.com   → 104.16.1.1
dev.target.hackerone.com   → 104.16.1.2
test.target.hackerone.com  → 192.168.1.100 (Internal IP Exposed!)
```

### Example 7: Database Server Audit
```bash
# Scenario: Database security assessment
python3 shadowport.py db-servers.txt \
  -p 1433,1521,3306,5432,5984,6379,9042,27017 \
  --format csv \
  -o database_audit.csv

# Database Services Found:
MySQL (3306)     → 5 servers
PostgreSQL (5432) → 3 servers
Redis (6379)     → 2 servers (No authentication!)
MongoDB (27017)  → 1 server
```

### Example 8: Stealth Penetration Test
```bash
# Scenario: Advanced evasion during red team exercise
sudo python3 shadowport.py target-network.com \
  --stealth \
  --decoy-ips 10.0.0.1,10.0.0.2,10.0.0.3 \
  -p 22,80,443 \
  --source-port 53 \
  --delay 5.0 \
  -o stealth_scan.json

# Evasion Techniques Applied:
✓ SYN Stealth Scanning
✓ Decoy IP Addresses
✓ DNS Source Port Spoofing
✓ Slow Scan (5s delay)
```

## 🔍 Advanced Features

### DNS Enumeration
```bash
# Subdomain Discovery
www.target.com     → 192.168.1.10
mail.target.com    → 192.168.1.20
ftp.target.com     → 192.168.1.30

# DNS Record Types
A Records    → IPv4 addresses
AAAA Records → IPv6 addresses
MX Records   → Mail servers
TXT Records  → Additional information
```

### SSH Brute Force Module
```bash
# Credential Testing
[+] Testing SSH credentials on 192.168.1.50:22
[+] Success: admin:password123
[!] Rate limiting active (1 attempt per 2 seconds)
```

## 🖥️ System Requirements

### Recommended Distributions
```bash
# Primary Testing Platforms
🐉 Kali Linux 2024.x    (Recommended)
🦜 Parrot Security OS    (Fully Supported)
⚫ BlackArch Linux       (Compatible)
🔧 Debian 11/12          (Base Support)
🐧 Ubuntu 20.04/22.04    (Base Support)
```

### Hardware Requirements
```bash
RAM: 512MB minimum (2GB recommended)
CPU: Any modern processor
Storage: 100MB for tool + dependencies
Network: Ethernet or WiFi interface
```

### Permission Requirements
```bash
# For stealth scanning (SYN, FIN, NULL)
sudo python3 shadowport.py target --stealth

# For raw packet crafting
sudo setcap cap_net_raw+ep /usr/bin/python3
```

## 📈 Interpreting Results

### Port States
```bash
🟢 open       # Port is accessible and service is running
🔴 closed     # Port is accessible but no service
🟡 filtered   # Port is blocked by firewall
⚪ unknown    # Unable to determine state
```

### Service Confidence Levels
```bash
High Confidence    # Banner grabbed successfully
Medium Confidence  # Service detected by behavior
Low Confidence     # Port open, service unknown
```

## 🛡️ Evasion Techniques

### Firewall Bypass
```python
# Implemented Evasion Methods
- SYN Stealth Scanning
- Fragmented Packets
- Decoy Source IPs
- Random Source Ports
- Timing Randomization
```

### Rate Limiting
```bash
# Configurable Delays
--delay 0.1   # Fast scan (may trigger detection)
--delay 1.0   # Balanced approach
--delay 3.0   # Stealth mode (slower but quieter)
```

## ⚠️ Legal Disclaimer

This tool was developed for educational purposes and authorized security testing. The use of this tool is entirely the user's responsibility. Make sure you have explicit authorization before testing any system.

### Responsible Use

- ✅ Test only on your own systems or with explicit written authorization
- ✅ Respect the terms of service and local laws
- ✅ Use appropriate rate limiting to avoid service disruption
- ✅ Obtain proper consent before scanning third-party networks
- ✅ Follow responsible disclosure for discovered vulnerabilities
- ❌ Do not use for malicious or illegal activities
- ❌ Do not scan networks without permission
- ❌ Do not violate privacy rights or cause service disruption
- ❌ Do not use for unauthorized access attempts

### 🚨 IMPORTANT LEGAL NOTICE

**AUTHORIZED USE ONLY**: This software is intended for:
- Personal network security assessments
- Authorized penetration testing engagements
- Corporate security assessments with proper approval
- Educational and research purposes in controlled environments
- Bug bounty programs with explicit scope authorization

**PROHIBITED ACTIVITIES**:
- Scanning networks/systems without explicit authorization
- Violating computer fraud and abuse laws
- Accessing systems without permission
- Causing service disruption or damage
- Any illegal or malicious activities

The developer is **NOT RESPONSIBLE** for any misuse of this tool. Users must comply with all applicable laws and regulations in their jurisdiction.

### Ethical Guidelines

Before using ShadowPort, ensure you have:
1. Written authorization from system owners
2. Clearly defined scope and limitations
3. Understanding of applicable laws and regulations
4. Proper insurance and legal protection
5. Incident response procedures in place

## 🔧 Troubleshooting

### Common Issues

#### Permission Denied (Raw Sockets)
```bash
# Solution: Run with sudo for stealth scans
sudo python3 shadowport.py target --stealth
```

#### Module Import Errors
```bash
# Solution: Reinstall dependencies
pip3 install --upgrade -r requirements.txt
```

#### Slow Scanning Performance
```bash
# Solution: Increase thread count
python3 shadowport.py target -t 200
```

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help improve ShadowPort:

### How to Contribute

#### 🐛 Bug Reports
- Use GitHub Issues to report bugs
- Include detailed steps to reproduce
- Provide system information (OS, Python version)
- Attach relevant log files or screenshots

#### ✨ Feature Requests
- Open a GitHub Issue with the "enhancement" label
- Clearly describe the proposed feature
- Explain the use case and benefits
- Consider implementation complexity

#### 💻 Code Contributions
```bash
# Fork the repository
git clone https://github.com/yourusername/ShadowPort.git
cd ShadowPort

# Create a feature branch
git checkout -b feature/amazing-feature

# Make your changes and test thoroughly
python3 -m pytest tests/

# Commit with descriptive messages
git commit -m "Add advanced firewall evasion technique"

# Push and create a Pull Request
git push origin feature/amazing-feature
```

### Development Guidelines

#### Code Style
```python
# Follow PEP 8 style guidelines
# Use meaningful variable names
# Add docstrings to functions
# Include type hints where possible

def scan_port(target: str, port: int, timeout: float = 3.0) -> dict:
    """
    Scan a specific port on target host.
    
    Args:
        target: Target IP address or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds
    
    Returns:
        dict: Scan result with port status and service info
    """
    pass
```

#### Testing
```bash
# Write tests for new features
# Ensure all tests pass before submitting PR
python3 -m pytest tests/ -v

# Test on multiple Python versions
python3.6 -m pytest tests/
python3.9 -m pytest tests/
python3.11 -m pytest tests/
```

#### Documentation
- Update README.md for new features
- Add docstrings to all new functions
- Include usage examples
- Update command-line help text

### Community Guidelines

#### 🌟 Recognition
Contributors will be acknowledged in:
- README.md contributors section
- Release notes
- GitHub contributor page

#### 📧 Contact
- Join our Discord server: [ShadowPort Community]
- Follow updates: [@CHDevSec](https://twitter.com/chdevsec)
- Email: security@chdevsec.com

### Priority Contributions

We're particularly interested in:
- **New Evasion Techniques**: Advanced firewall bypass methods
- **Protocol Support**: Additional protocols (SNMP, LDAP, etc.)
- **Performance Optimization**: Faster scanning algorithms
- **OS Fingerprinting**: Enhanced operating system detection
- **Reporting Features**: Better output formats and visualizations

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 🔒 Developed by [CHDEVSEC](https://github.com/chdevsec) | Pentester Caio Henrique

**⭐ If this project was useful to you, consider giving it a star!**

[![GitHub followers](https://img.shields.io/github/followers/chdevsec.svg?style=social&label=Follow)](https://github.com/chdevsec)

</div>

## 📚 Tags and Keywords

`port-scanner` `network-reconnaissance` `penetration-testing` `ethical-hacking` `cybersecurity` `security-audit` `stealth-scanning` `service-enumeration` `dns-enumeration` `ssh-bruteforce` `vulnerability-scanner` `network-security` `kali-linux` `parrot-security` `red-team` `blue-team` `osint` `information-gathering` `network-mapping` `security-testing` `pentest-tools` `scapy` `python` `automation` `firewall-evasion` `banner-grabbing` `service-detection` `tcp-scanning` `udp-scanning` `syn-stealth`
