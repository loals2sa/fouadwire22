# ⚡ fouad wire — Advanced Network Toolkit

Modern, dark-themed network analysis toolkit with neon-green accents and a clean login experience. Combines packet capture, analysis views, device manager, logs, and optional integrations.

![App Icon](icon.png)

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.5.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🔥 Features

### 🎆 Modern UI
- **Dark, Neon Styling**: Dark background with neon-green accents
- **Polished Login**: Centered panel, rounded corners, drop shadow
- **Responsive Layout**: Scales for desktop and mobile screens
- **Enter-to-Submit**: Press Enter to login; shows a loading spinner
- **Forgot Password**: Quick link for recovery guidance
- **Multi-tab Interface**: Organized sections for tools

### 📦 Network Analysis
- **🔍 Packet Capture**: Real-time capture with advanced filtering
- **📊 Protocol Analysis**: TCP, UDP, HTTP/S, DNS, ARP, ICMP, SSH, FTP, SMB, RDP
- **🖥️ Device Manager**: 
  - Network device discovery
  - Block/Unblock devices from network
  - Deauthentication attacks
  - MAC/IP tracking

### ⚔️ Attack Tools
- **🔥 DDoS Attacks**:
  - SYN Flood
  - ICMP Flood
  - UDP Flood
  - DNS Amplification
- **💀 Exploitation**:
  - ARP Spoofing
  - MITM (Man-in-the-Middle)
  - DNS Spoofing
  - WiFi Deauthentication
- **🎯 Bettercap Integration**: Advanced attack framework

### 🛡️ Defense Features
- **⚠️ Attack Detection**:
  - ARP Spoofing detection
  - Port Scan detection
  - DDoS detection
  - DNS Tunneling detection
- **🛡️ Defense Mode**: IDS/IPS functionality
- **📊 Real-time Alerts**: Security notifications

## 📋 Requirements

- Python 3.7+
- Linux/Unix system (Kali Linux recommended)
- Root/sudo privileges for packet capture

## 🚀 Installation

### Quick Start
```bash
cd "/home/kali/Desktop/New Folder 2"
chmod +x myapp
./myapp
```

### Manual Installation
```bash
# Install Python dependencies
pip3 install scapy colorama netifaces requests

# Install system tools (optional but recommended)
sudo apt-get update
sudo apt-get install -y tcpdump nmap aircrack-ng ettercap-text-only bettercap
```

## 💻 Usage

### Launch via Python
```bash
python3 fouad_wire.py
```

### First Time Setup
1. Run as root/sudo
2. Select your network interface
3. Click "SCAN NETWORK" to discover devices
4. Choose between DEFENSE or ATTACK mode

## 🔐 Login

- **No password required** - App launches directly
- Login screen disabled for quick access

## 🖥️ Desktop Integration (Linux)

Install a desktop launcher so it appears in your Applications menu:
```bash
chmod +x "/home/kali/Desktop/New Folder 2/myapp"
chmod +x "/home/kali/Desktop/New Folder 2/MyApp.desktop" || true
mkdir -p "$HOME/.local/share/applications"
install -m 644 "/home/kali/Desktop/New Folder 2/MyApp.desktop" "$HOME/.local/share/applications/fouad-wire.desktop"
update-desktop-database "$HOME/.local/share/applications" || true
```

## 🎮 Interface Guide

### Control Panel
- **🔍 SCAN NETWORK**: Quick network discovery
- **🛡️ DEFENSE MODE**: Enable defensive monitoring
- **⚔️ ATTACK MODE**: Enable offensive tools (authorization required)
- **Interface**: Select network adapter
- **Filter**: BPF packet filters

### Tabs Overview
1. **📊 Dashboard**: Live statistics and network feed
2. **📦 Packets**: Real-time packet capture and analysis
3. **🖥️ Devices**: Network device management
4. **⚔️ Attack**: Offensive security tools
5. **⚠️ Alerts**: Security warnings and detections
6. **📝 Logs**: Comprehensive activity logs

### Device Management
- View all network devices
- Block devices (ARP isolation)
- Deauthenticate wireless clients
- Monitor device activity

### Attack Tools Usage
1. Enter target IP/Port
2. Select attack type
3. Monitor progress in attack log
4. Use responsibly and legally only!

### Filters Examples
- `tcp`: Capture only TCP packets
- `udp port 53`: Capture DNS traffic
- `host 192.168.1.1`: Capture traffic to/from specific host
- `tcp port 80 or tcp port 443`: Capture HTTP/HTTPS traffic
- `arp`: Capture ARP packets

## 🛡️ Security & Attack Capabilities

### Defensive Capabilities
- **Real-time Attack Detection**
  - ARP poisoning/spoofing
  - Port scanning (SYN, ACK, UDP)
  - DDoS attacks
  - DNS tunneling
  - MITM attempts
- **Network Monitoring**
  - Traffic analysis
  - Protocol inspection
  - Anomaly detection

### Offensive Capabilities (Ethical Build Note)
Offensive features may be disabled in this ethical build. Use responsibly and only with explicit authorization.

## ⚡ Performance Tips

1. Use specific filters to reduce packet volume
2. Clear packets periodically to free memory
3. Run on a dedicated monitoring interface if possible
4. Reduce background effects if needed

## 🎨 Customization

### Matrix Effect
Edit `matrix_effect.py` to customize:
- Character set
- Drop speed
- Color scheme
- Font size

### Detection Thresholds
Edit `network_analyzer.py` to adjust:
- Port scan threshold (default: 20 SYN packets)
- DNS query threshold (default: 50 queries)
- Flood detection limits

## ⚠️ Legal Disclaimer & Warnings

### 🚨 IMPORTANT LEGAL NOTICE
- **Authorization Required**: Only use on networks you own or have explicit written permission to test
- **Legal Compliance**: Unauthorized network attacks are illegal in most jurisdictions
- **Ethical Use**: This tool is for legitimate security testing and education only
- **Liability**: Users are responsible for their actions and any consequences

### 🔒 Security Considerations
- **Root Access**: Tool requires root/sudo privileges
- **Network Exposure**: Some attacks may expose your MAC/IP
- **Detection Risk**: Advanced attacks may trigger IDS/IPS systems
- **System Resources**: Heavy attacks consume significant resources

### 📚 Educational Purpose
This tool is designed for:
- Security professionals
- Penetration testers
- Network administrators
- Cybersecurity students
- Authorized security audits

## 🐛 Troubleshooting

### Permission Denied
```bash
sudo python3 fouad_wire.py
```

### No packets captured
- Check if interface is correct
- Verify network connectivity
- Try without filter first
- Check firewall settings

### Scapy Import Error
```bash
pip install --upgrade scapy
```

## 📝 License

MIT License - Feel free to modify and distribute

## 🔗 Integrated & Similar Tools

### Integrated Tools
- **Bettercap**: Advanced, modular, portable MITM framework
- **Scapy**: Powerful packet manipulation library
- **Aircrack-ng**: WiFi security auditing tools

### Similar Tools
- [Wireshark](https://www.wireshark.org/) - GUI packet analyzer
- [Ettercap](https://www.ettercap-project.org/) - MITM attack suite
- [Metasploit](https://www.metasploit.com/) - Penetration testing framework
- [Nmap](https://nmap.org/) - Network discovery and security auditing
- [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) - Wireless security auditing
- [WiFite2](https://github.com/derv82/wifite2) - Automated wireless attack tool

## 👨‍💻 Author & Contact

Created by **Fouad**

- Instagram: https://instagram.com/1.pvl
- Email: zalaffouad37@gmail.com

Open PRs and issues are welcome.

---

**Note**: This tool is for educational and legitimate security testing purposes only. Always obtain proper authorization before monitoring any network.
