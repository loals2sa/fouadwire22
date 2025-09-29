#!/bin/bash
# ===================================================
# FOUAD WIRE - Advanced Network Warfare System
# Launch Script
# ===================================================

echo -e "\033[32m"
cat << "EOF"
███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗     ██╗    ██╗██╗██████╗ ███████╗
██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔══██╗    ██║    ██║██║██╔══██╗██╔════╝
█████╗  ██║   ██║██║   ██║███████║██║  ██║    ██║ █╗ ██║██║██████╔╝█████╗  
██╔══╝  ██║   ██║██║   ██║██╔══██║██║  ██║    ██║███╗██║██║██╔══██╗██╔══╝  
██║     ╚██████╔╝╚██████╔╝██║  ██║██████╔╝    ╚███╔███╔╝██║██║  ██║███████╗
╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝
EOF
echo -e "\033[36m         [ ADVANCED NETWORK WARFARE SYSTEM ]\033[0m"
echo -e "\033[33m           [ Created by Elite Cyber Team ]\033[0m"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "\033[31m[!] This tool requires root privileges for network operations\033[0m"
    echo -e "\033[33m[*] Requesting sudo access...\033[0m"
    sudo "$0" "$@"
    exit
fi

echo -e "\033[32m[+] Running as root\033[0m"

# Install dependencies if needed
echo -e "\033[33m[*] Checking dependencies...\033[0m"

# Check Python3
if ! command -v python3 &> /dev/null; then
    echo -e "\033[31m[-] Python3 not found. Installing...\033[0m"
    apt-get update && apt-get install -y python3 python3-pip
fi

# Check and install Python packages
echo -e "\033[33m[*] Installing Python packages...\033[0m"
pip3 install -q scapy colorama netifaces requests 2>/dev/null

# Check for network tools
echo -e "\033[33m[*] Checking network tools...\033[0m"

# Install network tools if missing
tools=("tcpdump" "nmap" "aircrack-ng" "ettercap-text-only")
for tool in "${tools[@]}"; do
    if ! command -v ${tool%%-*} &> /dev/null; then
        echo -e "\033[33m[*] Installing $tool...\033[0m"
        apt-get install -y $tool 2>/dev/null
    fi
done

# Check Bettercap
if ! command -v bettercap &> /dev/null; then
    echo -e "\033[33m[*] Bettercap not found. Install? (y/n)\033[0m"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        apt-get install -y bettercap
    fi
fi

# Enable monitor mode on wireless interfaces (optional)
echo -e "\033[33m[*] Enable monitor mode on wireless interface? (y/n)\033[0m"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    # Find wireless interfaces
    for iface in $(iw dev | awk '$1=="Interface"{print $2}'); do
        echo -e "\033[33m[*] Enabling monitor mode on $iface...\033[0m"
        airmon-ng start $iface 2>/dev/null
    done
fi

# Enable IP forwarding for MITM attacks
echo 1 > /proc/sys/net/ipv4/ip_forward
echo -e "\033[32m[+] IP forwarding enabled\033[0m"

# Launch Fouad Wire
echo -e "\033[32m[+] Launching Fouad Wire...\033[0m"
echo -e "\033[33m[!] Press Ctrl+C to exit\033[0m"
echo ""

cd "$(dirname "$0")"
python3 fouad_wire.py

# Cleanup on exit
echo 0 > /proc/sys/net/ipv4/ip_forward
echo -e "\033[33m[*] IP forwarding disabled\033[0m"
echo -e "\033[32m[+] Fouad Wire closed\033[0m"
