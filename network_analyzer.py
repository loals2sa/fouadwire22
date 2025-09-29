"""Network analysis engine for packet capture and analysis"""

from datetime import datetime
from collections import defaultdict
import threading

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS
except ImportError:
    print("Please install scapy: pip install scapy")
    sys.exit(1)

class NetworkAnalyzer:
    def __init__(self, packet_queue):
        self.packet_queue = packet_queue
        self.packets = []
        self.is_sniffing = False
        self.sniffer_thread = None
        
        # For detecting attacks
        self.arp_table = defaultdict(set)
        self.syn_counts = defaultdict(int)
        self.dns_queries = defaultdict(int)
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        if not self.is_sniffing:
            return
        
        packet_info = self.parse_packet(packet)
        if packet_info:
            self.packets.append(packet_info)
            self.packet_queue.put(packet_info)
            self.detect_attacks(packet, packet_info)
    
    def parse_packet(self, packet):
        """Parse packet into displayable format"""
        info = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "number": len(self.packets) + 1,
            "length": len(packet),
            "protocol": "Unknown",
            "src": "-",
            "dst": "-",
            "info": "",
            "raw": packet
        }
        
        try:
            # Ethernet layer
            if Ether in packet:
                info["src_mac"] = packet[Ether].src
                info["dst_mac"] = packet[Ether].dst
            
            # IP layer
            if IP in packet:
                info["src"] = packet[IP].src
                info["dst"] = packet[IP].dst
                
                # TCP
                if TCP in packet:
                    info["protocol"] = "TCP"
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    
                    # Common protocols
                    if dport == 80 or sport == 80:
                        info["protocol"] = "HTTP"
                        if Raw in packet:
                            payload = str(packet[Raw].load)[:50]
                            if "GET" in payload or "POST" in payload:
                                info["info"] = payload.split('\\r\\n')[0]
                    elif dport == 443 or sport == 443:
                        info["protocol"] = "HTTPS"
                    elif dport == 22 or sport == 22:
                        info["protocol"] = "SSH"
                    elif dport == 21 or sport == 21:
                        info["protocol"] = "FTP"
                    elif dport == 23 or sport == 23:
                        info["protocol"] = "Telnet"
                    elif dport == 445 or sport == 445:
                        info["protocol"] = "SMB"
                    elif dport == 3389 or sport == 3389:
                        info["protocol"] = "RDP"
                    
                    # TCP flags
                    flag_str = ""
                    if flags & 0x02: flag_str += "SYN "
                    if flags & 0x10: flag_str += "ACK "
                    if flags & 0x01: flag_str += "FIN "
                    if flags & 0x04: flag_str += "RST "
                    if flags & 0x08: flag_str += "PSH "
                    
                    info["info"] = f"{sport} → {dport} [{flag_str}]"
                
                # UDP
                elif UDP in packet:
                    info["protocol"] = "UDP"
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    
                    if dport == 53 or sport == 53:
                        info["protocol"] = "DNS"
                        if DNS in packet:
                            if packet[DNS].qr == 0:
                                info["info"] = f"Query: {packet[DNS].qd.qname.decode()}"
                            else:
                                info["info"] = "DNS Response"
                    elif dport == 67 or dport == 68:
                        info["protocol"] = "DHCP"
                    elif dport == 161 or sport == 161:
                        info["protocol"] = "SNMP"
                    else:
                        info["info"] = f"{sport} → {dport}"
                
                # ICMP
                elif ICMP in packet:
                    info["protocol"] = "ICMP"
                    icmp_type = packet[ICMP].type
                    if icmp_type == 8:
                        info["info"] = "Echo Request (Ping)"
                    elif icmp_type == 0:
                        info["info"] = "Echo Reply (Pong)"
                    elif icmp_type == 3:
                        info["info"] = "Destination Unreachable"
                    elif icmp_type == 11:
                        info["info"] = "Time Exceeded"
                    else:
                        info["info"] = f"Type {icmp_type}"
            
            # ARP
            elif ARP in packet:
                info["protocol"] = "ARP"
                info["src"] = packet[ARP].psrc
                info["dst"] = packet[ARP].pdst
                
                if packet[ARP].op == 1:
                    info["info"] = f"Who has {packet[ARP].pdst}?"
                elif packet[ARP].op == 2:
                    info["info"] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
            
            return info
            
        except Exception as e:
            return None
    
    def detect_attacks(self, packet, info):
        """Detect potential attacks and suspicious activity"""
        
        # ARP Spoofing Detection
        if ARP in packet and packet[ARP].op == 2:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            
            if ip in self.arp_table and mac not in self.arp_table[ip]:
                if len(self.arp_table[ip]) > 0:
                    alert = {
                        "time": info["time"],
                        "type": "ARP Spoofing",
                        "details": f"IP {ip} MAC changed from {self.arp_table[ip]} to {mac}",
                        "severity": "HIGH"
                    }
                    self.packet_queue.put(("ALERT", alert))
            
            self.arp_table[ip].add(mac)
        
        # Port Scan Detection (SYN scan)
        if TCP in packet and packet[TCP].flags == 2:  # SYN flag only
            src = info.get("src", "")
            self.syn_counts[src] += 1
            
            if self.syn_counts[src] > 20:  # Threshold
                alert = {
                    "time": info["time"],
                    "type": "Port Scan",
                    "details": f"Possible SYN scan from {src}",
                    "severity": "MEDIUM"
                }
                self.packet_queue.put(("ALERT", alert))
                self.syn_counts[src] = 0  # Reset counter
        
        # DNS Tunneling Detection
        if DNS in packet and packet[DNS].qr == 0:  # DNS query
            query = packet[DNS].qd.qname.decode()
            
            # Check for suspicious long domain names (potential DNS tunneling)
            if len(query) > 50:
                alert = {
                    "time": info["time"],
                    "type": "DNS Tunneling",
                    "details": f"Suspicious DNS query: {query[:60]}...",
                    "severity": "MEDIUM"
                }
                self.packet_queue.put(("ALERT", alert))
            
            # Check for high frequency DNS queries
            self.dns_queries[query] += 1
            if self.dns_queries[query] > 50:
                alert = {
                    "time": info["time"],
                    "type": "DNS Flood",
                    "details": f"High frequency DNS queries for {query}",
                    "severity": "LOW"
                }
                self.packet_queue.put(("ALERT", alert))
                self.dns_queries[query] = 0
        
        # ICMP Flood Detection
        if ICMP in packet:
            src = info.get("src", "")
            # Simple ICMP flood detection (you can enhance this)
            if src in self.syn_counts:  # Reuse counter
                self.syn_counts[src] += 1
                if self.syn_counts[src] > 100:
                    alert = {
                        "time": info["time"],
                        "type": "ICMP Flood",
                        "details": f"Possible ICMP flood from {src}",
                        "severity": "MEDIUM"
                    }
                    self.packet_queue.put(("ALERT", alert))
                    self.syn_counts[src] = 0
    
    def start_sniffing(self, interface="any", filter_exp=""):
        """Start packet capture"""
        self.is_sniffing = True
        
        def sniff_thread():
            try:
                # Build filter if provided
                bpf_filter = filter_exp if filter_exp else None
                
                # Start sniffing
                sniff(iface=interface, prn=self.packet_callback, 
                     filter=bpf_filter, store=0)
            except PermissionError:
                self.packet_queue.put(("ALERT", {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "type": "Permission Error",
                    "details": "Run as root/sudo for packet capture",
                    "severity": "HIGH"
                }))
            except Exception as e:
                self.packet_queue.put(("ALERT", {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "type": "Error",
                    "details": str(e),
                    "severity": "HIGH"
                }))
        
        self.sniffer_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniffer_thread.start()
    
    def stop_sniffing(self):
        """Stop packet capture"""
        self.is_sniffing = False
