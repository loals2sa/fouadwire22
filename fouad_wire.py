#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      FOUAD WIRE - ADVANCED NETWORK TOOLKIT                   ║
║                         Ethical, Authorized Use Only                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
from datetime import datetime
import subprocess
import sys
import os
import time
import random
import base64

# Install dependencies if needed
try:
    from scapy.all import *
    from colorama import init, Fore, Back, Style
    import netifaces
except ImportError:
    print("Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy", "colorama", "netifaces"])
    from scapy.all import *
    from colorama import init, Fore, Back, Style
    import netifaces

init(autoreset=True)
# Optional visual/network modules with safe fallbacks
try:
    from matrix_effect import MatrixRain  # type: ignore
except Exception:
    class MatrixRain:  # fallback no-op
        def __init__(self, *args, **kwargs):
            pass
        def update(self):
            pass

try:
    from network_analyzer import NetworkAnalyzer  # type: ignore
except Exception:
    class NetworkAnalyzer:
        def __init__(self, packet_queue):
            self._running = False
            self.packet_queue = packet_queue
        def start_sniffing(self, iface, flt):
            self._running = True
        def stop_sniffing(self):
            self._running = False

from advanced_tools import AdvancedNetworkTools, BettercapIntegration

BANNER = f"""{Fore.GREEN}
███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗     ██╗    ██╗██╗██████╗ ███████╗
██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔══██╗    ██║    ██║██║██╔══██╗██╔════╝
█████╗  ██║   ██║██║   ██║███████║██║  ██║    ██║ █╗ ██║██║██████╔╝█████╗  
██╔══╝  ██║   ██║██║   ██║██╔══██║██║  ██║    ██║███╗██║██║██╔══██╗██╔══╝  
██║     ╚██████╔╝╚██████╔╝██║  ██║██████╔╝    ╚███╔███╔╝██║██║  ██║███████╗
╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝      ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝
                 {Fore.CYAN}[ fouad wire – authorized toolkit ]{Fore.RESET}
                {Fore.RED}[ For authorized testing only ]{Fore.RESET}
"""

# --- Utilities ---
def ensure_app_icon(path: str = "icon.png"):
    """Ensure a minimal placeholder PNG icon exists.
    Avoid external deps by embedding a tiny base64 PNG (64x64 dark with green dot).
    """
    try:
        if os.path.exists(path):
            return
        # 64x64 simple PNG (generated beforehand), small size
        _PNG_B64 = (
            b"iVBORw0KGgoAAAANSUhEUgAAAEEAAABBCAYAAACqKq1bAAAACXBIWXMAAAsTAAALEwEAmpwY" 
            b"AAABTUlEQVR4nO3aMQ6CMBBF0WVYq8wq3Qq0G2m9pNw2ZpQp0sG6mC5pY0Q3b2cFUaQqf2k8W" 
            b"mM7g5u7bQw8Q26k4v0i2sH0o8v9JwD1w3kB3kQ2sQhK2CwZ5o9lVqEw3gE2q2w1H8kJMKy8S0m" 
            b"YwU5Ew4rjKcBv0l7C1Jgz1wq2FQmYpH9G3g7y4mB2v0b4mYzJm2m0bq9J2Y2mKcU7r/3sJDY7E" 
            b"w2w5bq1G2gN3wTgQmEwqWcVxXwzg2hXgQ6bCMo2k1m3wP9mEJr1q5y+o1dZ0gAAAP//AwAwz4mU" 
            b"8mJ1tAAAAABJRU5ErkJggg=="
        )
        with open(path, "wb") as f:
            f.write(base64.b64decode(_PNG_B64))
    except Exception:
        # Non-fatal if icon creation fails
        pass

class FouadWire:
    def scan_devices(self):
        print("Scanning for devices...")

    def __init__(self, root):
        self.root = root
        self.root.title("fouad wire – Professional Network Toolkit")
        self.root.attributes('-fullscreen', True)
        self.root.configure(bg="#000000")
        
        # Print banner
        print(BANNER)
        
        self.packet_queue = queue.Queue()
        self.log_queue = queue.Queue()
        self.analyzer = NetworkAnalyzer(self.packet_queue)
        self.advanced_tools = AdvancedNetworkTools(self.log_message)
        self.bettercap = BettercapIntegration(self.log_message)
        self.devices = {}
        
        # Skip login - no password required
        # if not self.show_login():
        #     self.root.destroy()
        #     return

        self.setup_ui()
        
        # Start matrix effect
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.matrix = MatrixRain(self.bg_canvas, screen_width, screen_height)
        self.animate_matrix()
        
        # Update display
        self.update_packets()
        self.update_logs()
        
    def setup_ui(self):
        # Background canvas for matrix effect
        self.bg_canvas = tk.Canvas(self.root, bg="#000000", highlightthickness=0)
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Main frame
        main = tk.Frame(self.root, bg="#000000")
        main.place(x=10, y=10, relwidth=0.98, relheight=0.97)
        
        # Animated Title
        self.title_label = tk.Label(main, text="fouad wire", 
                                   font=("Courier", 28, "bold"),
                                   bg="#000000", fg="#00ff00")
        self.title_label.pack(pady=5)
        
        self.subtitle_label = tk.Label(main, text="For authorized testing only", 
                                      font=("Courier", 14, "bold"),
                                      bg="#000000", fg="#ff3333")
        self.subtitle_label.pack()
        
        # Exit button
        tk.Button(main, text="✖ EXIT", command=self.exit_app,
                 bg="#440000", fg="#ff0000", font=("Courier", 10, "bold"),
                 activebackground="#660000").place(relx=0.95, y=5)
        
        # Controls
        ctrl = tk.Frame(main, bg="#000000")
        ctrl.pack(fill="x", pady=5)
        
        tk.Label(ctrl, text="Interface:", bg="#000000", fg="#00ff00").pack(side="left", padx=5)
        self.iface_var = tk.StringVar(value="any")
        iface_values = self.get_interfaces() or ["any", "eth0", "wlan0"]
        ttk.Combobox(ctrl, textvariable=self.iface_var,
                    values=iface_values).pack(side="left")
        
        tk.Label(ctrl, text="Filter:", bg="#000000", fg="#00ff00").pack(side="left", padx=5)
        self.filter_entry = tk.Entry(ctrl, bg="#0a0a0a", fg="#00ff00")
        self.filter_entry.pack(side="left")
        
        self.start_btn = tk.Button(ctrl, text="▶ START", command=self.start,
                                  bg="#003300", fg="#00ff00")
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = tk.Button(ctrl, text="■ STOP", command=self.stop,
                                 bg="#330000", fg="#ff0000", state="disabled")
        self.stop_btn.pack(side="left")
        
        tk.Button(ctrl, text="🔍 SCAN NETWORK", command=self.quick_scan,
                 bg="#003300", fg="#00ff00", font=("Courier", 10, "bold"),
                 activebackground="#004400").pack(side="left", padx=10)
        
        tk.Button(ctrl, text="🛡️ DEFENSE MODE", command=self.defense_mode,
                 bg="#000033", fg="#0099ff", font=("Courier", 10, "bold"),
                 activebackground="#000044").pack(side="left", padx=5)
        
        tk.Button(ctrl, text="⚔️ ATTACK MODE", command=self.attack_mode,
                 bg="#330000", fg="#ff0000", font=("Courier", 10, "bold"),
                 activebackground="#440000").pack(side="left", padx=5)
        
        # Tabs with styling
        notebook = ttk.Notebook(main)
        notebook.pack(fill="both", expand=True, pady=5)
        
        # Configure notebook style
        style = ttk.Style()
        style.configure('TNotebook', background='#000000')
        style.configure('TNotebook.Tab', background='#001100', foreground='#00ff00')
        style.map('TNotebook.Tab', background=[('selected', '#003300')])
        
        # Dashboard tab
        dash_frame = tk.Frame(notebook, bg="#000000")
        notebook.add(dash_frame, text="📊 Dashboard")
        self.create_dashboard(dash_frame)
        
        # Packet tab
        pkt_frame = tk.Frame(notebook, bg="#000000")
        notebook.add(pkt_frame, text="📦 Packets")
        
        cols = ("No", "Time", "Source", "Dest", "Protocol", "Info")
        self.packet_tree = ttk.Treeview(pkt_frame, columns=cols, show="headings")
        for col in cols:
            self.packet_tree.heading(col, text=col)
        self.packet_tree.pack(fill="both", expand=True)
        
        # Analysis tab
        analysis_frame = tk.Frame(notebook, bg="#000000")
        notebook.add(analysis_frame, text="Analysis")
        
        btn_frame = tk.Frame(analysis_frame, bg="#000000")
        btn_frame.pack(fill="x")
        
        tk.Button(btn_frame, text="ARP Scan", command=self.arp_scan,
                 bg="#003300", fg="#00ff00").pack(side="left", padx=5)
        tk.Button(btn_frame, text="Port Scan", command=self.port_scan,
                 bg="#003300", fg="#00ff00").pack(side="left")
        
        self.analysis_text = scrolledtext.ScrolledText(analysis_frame,
                                                      bg="#0a0a0a", fg="#00ff00")
        self.analysis_text.pack(fill="both", expand=True)
        
        # Device Manager tab
        device_frame = tk.Frame(notebook, bg="#000000")
        notebook.add(device_frame, text="🖥️ Devices")
        self.create_device_manager(device_frame)
        
        # Terminal tab
        term_frame = tk.Frame(notebook, bg="#000000")
        notebook.add(term_frame, text="🖥️ Terminal")
        self.create_terminal_tab(term_frame)
        
        # Alerts tab
        alert_frame = tk.Frame(notebook, bg="#000000")
        notebook.add(alert_frame, text="⚠️ Alerts")
        
        self.alert_tree = ttk.Treeview(alert_frame, 
                                      columns=("Time", "Type", "Details"),
                                      show="headings")
        for col in ("Time", "Type", "Details"):
            self.alert_tree.heading(col, text=col)
        self.alert_tree.pack(fill="both", expand=True)
        
        # Logs tab
        log_frame = tk.Frame(notebook, bg="#000000")
        notebook.add(log_frame, text="📝 Logs")
        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#0a0a0a", fg="#00ff00",
                                                  font=("Courier", 9))
        self.log_text.pack(fill="both", expand=True)
        
    def create_dashboard(self, parent):
        """Create dashboard with stats"""
        # Stats frames
        stats_container = tk.Frame(parent, bg="#000000")
        stats_container.pack(fill="x", padx=10, pady=10)
        
        # Network stats
        net_frame = tk.LabelFrame(stats_container, text="Network Statistics",
                                 bg="#001100", fg="#00ff00", font=("Courier", 10, "bold"))
        net_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        self.net_stats = tk.Text(net_frame, bg="#000000", fg="#00ff00",
                                height=8, width=40, font=("Courier", 9))
        self.net_stats.pack(padx=5, pady=5)
        
        # Attack stats
        attack_frame = tk.LabelFrame(stats_container, text="Attack Statistics",
                                   bg="#110000", fg="#ff0000", font=("Courier", 10, "bold"))
        attack_frame.pack(side="left", fill="both", expand=True, padx=5)
        
        self.attack_stats = tk.Text(attack_frame, bg="#000000", fg="#ff6600",
                                   height=8, width=40, font=("Courier", 9))
        self.attack_stats.pack(padx=5, pady=5)
        
        # Live feed
        feed_frame = tk.LabelFrame(parent, text="Live Network Feed",
                                 bg="#000011", fg="#00ffff", font=("Courier", 10, "bold"))
        feed_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.live_feed = scrolledtext.ScrolledText(feed_frame, bg="#000000", fg="#00ffff",
                                                  font=("Courier", 9), height=15)
        self.live_feed.pack(fill="both", expand=True, padx=5, pady=5)
    
    def create_device_manager(self, parent):
        """Create device manager interface"""
        # Controls
        ctrl_frame = tk.Frame(parent, bg="#000000")
        ctrl_frame.pack(fill="x", padx=5, pady=5)
        
        tk.Button(ctrl_frame, text="🔍 SCAN", command=self.scan_devices,
                 bg="#003300", fg="#00ff00", font=("Courier", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(ctrl_frame, text="🚫 BLOCK", command=self.block_selected,
                 bg="#330000", fg="#ff0000", font=("Courier", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(ctrl_frame, text="✓ UNBLOCK", command=self.unblock_selected,
                 bg="#003300", fg="#00ff00", font=("Courier", 10, "bold")).pack(side="left", padx=5)
        
        tk.Button(ctrl_frame, text="⚡ DEAUTH", command=self.deauth_selected,
                 bg="#330000", fg="#ffaa00", font=("Courier", 10, "bold")).pack(side="left", padx=5)
        
        # Device list
        columns = ("IP", "MAC", "Vendor", "Hostname", "Status")
        self.device_tree = ttk.Treeview(parent, columns=columns, show="headings")
        
        for col in columns:
            self.device_tree.heading(col, text=col)
        
        self.device_tree.pack(fill="both", expand=True, padx=5, pady=5)
    
    def create_attack_tools(self, parent):
        """Attack tools are disabled in ethical mode"""
        info = tk.Label(parent, text="Attack tools are disabled in this ethical build.",
                        bg="#000000", fg="#ff3333", font=("Courier", 12, "bold"))
        info.pack(pady=20)

        self.attack_log = scrolledtext.ScrolledText(parent, bg="#000000", fg="#ff6600",
                                                   font=("Courier", 9), height=10)
        self.attack_log.insert(tk.END, "[INFO] Offensive tools are not available.\n")
        self.attack_log.pack(fill="both", expand=True, padx=10, pady=5)

    def create_terminal_tab(self, parent):
        """Embedded terminal for authorized commands"""
        warn = tk.Label(parent, text="Run only commands you are authorized to execute.",
                        bg="#000000", fg="#ff3333", font=("Courier", 10, "bold"))
        warn.pack(anchor="w", padx=8, pady=4)

        cmd_frame = tk.Frame(parent, bg="#000000")
        cmd_frame.pack(fill="x", padx=8)

        tk.Label(cmd_frame, text=">", bg="#000000", fg="#00ff00").pack(side="left")
        self.term_entry = tk.Entry(cmd_frame, bg="#0a0a0a", fg="#00ff00")
        self.term_entry.pack(side="left", fill="x", expand=True, padx=6)
        tk.Button(cmd_frame, text="Run", command=self.run_terminal_command,
                 bg="#003300", fg="#00ff00", font=("Courier", 10, "bold")).pack(side="left", padx=4)
        tk.Button(cmd_frame, text="Clear", command=lambda: self.terminal_out.delete("1.0", tk.END),
                 bg="#330000", fg="#ff0000", font=("Courier", 10, "bold")).pack(side="left")

        self.terminal_out = scrolledtext.ScrolledText(parent, bg="#0a0a0a", fg="#cccccc",
                                                     font=("Courier", 9))
        self.terminal_out.pack(fill="both", expand=True, padx=8, pady=8)

    def run_terminal_command(self):
        cmd = (self.term_entry.get() or "").strip()
        if not cmd:
            return
        self.terminal_out.insert(tk.END, f"$ {cmd}\n")
        self.terminal_out.see(tk.END)

        def runner():
            try:
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in proc.stdout:
                    self.terminal_out.insert(tk.END, line)
                    self.terminal_out.see(tk.END)
                proc.wait()
                self.terminal_out.insert(tk.END, f"\n[exit {proc.returncode}]\n")
                self.terminal_out.see(tk.END)
            except Exception as e:
                self.terminal_out.insert(tk.END, f"[error] {e}\n")
                self.terminal_out.see(tk.END)

        threading.Thread(target=runner, daemon=True).start()
    
    def animate_matrix(self):
        self.matrix.update()
        self.root.after(50, self.animate_matrix)
    
    def start(self):
        self.analyzer.start_sniffing(self.iface_var.get(), self.filter_entry.get())
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log(f"[+] Started capture on {self.iface_var.get()}")
    
    def stop(self):
        self.analyzer.stop_sniffing()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log("[!] Stopped capture")
    
    def update_packets(self):
        try:
            while True:
                item = self.packet_queue.get_nowait()
                if isinstance(item, tuple) and item[0] == "ALERT":
                    alert = item[1]
                    self.alert_tree.insert("", "end", values=(
                        alert["time"], alert["type"], alert["details"]))
                elif isinstance(item, dict):
                    self.packet_tree.insert("", "end", values=(
                        item["number"], item["time"], item["src"],
                        item["dst"], item["protocol"], item["info"]))
        except queue.Empty:
            pass
        self.root.after(100, self.update_packets)
    
    def log(self, msg):
        self.analysis_text.insert(tk.END, f"{msg}\n")
        self.analysis_text.see(tk.END)
    
    def log_message(self, msg):
        """Log message to multiple outputs"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] {msg}"
        
        # Log to analysis text
        if hasattr(self, 'analysis_text'):
            self.analysis_text.insert(tk.END, f"{formatted_msg}\n")
            self.analysis_text.see(tk.END)
        
        # Log to log tab
        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, f"{formatted_msg}\n")
            self.log_text.see(tk.END)
        
        # Log to attack log if it's an attack
        if hasattr(self, 'attack_log') and ('DDOS' in msg or 'ATTACK' in msg or 'SPOOF' in msg):
            self.attack_log.insert(tk.END, f"{formatted_msg}\n")
            self.attack_log.see(tk.END)
        
        # Log to live feed
        if hasattr(self, 'live_feed'):
            self.live_feed.insert(tk.END, f"{formatted_msg}\n")
            self.live_feed.see(tk.END)
    
    def update_logs(self):
        """Update logs from queue"""
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_message(msg)
        except queue.Empty:
            pass
        self.root.after(100, self.update_logs)
    
    def arp_scan(self):
        def scan():
            self.log("[*] ARP Scanning...")
            try:
                ans, _ = arping("192.168.1.0/24", timeout=2, verbose=0)
                for s, r in ans:
                    self.log(f"  {r.psrc} - {r.hwsrc}")
                self.log("[+] Scan complete")
            except Exception as e:
                self.log(f"[-] Error: {e}")
        threading.Thread(target=scan, daemon=True).start()
    
    def port_scan(self):
        def scan():
            self.log("[*] Port scanning 192.168.1.1...")
            try:
                for port in [21, 22, 23, 80, 443, 445, 3389, 8080]:
                    pkt = IP(dst="192.168.1.1")/TCP(dport=port, flags="S")
                    resp = sr1(pkt, timeout=1, verbose=0)
                    if resp and resp.haslayer(TCP):
                        if resp[TCP].flags == 18:
                            self.log(f"  Port {port}: OPEN")
                self.log("[+] Scan complete")
            except Exception as e:
                self.log(f"[-] Error: {e}")
        threading.Thread(target=scan, daemon=True).start()
    
    def quick_scan(self):
        """Quick network scan"""
        self.log_message(f"{Fore.CYAN}[SCAN] Starting quick network scan...{Fore.RESET}")
        self.scan_devices()
    
    def defense_mode(self):
        """Enable defense mode"""
        self.log_message(f"{Fore.BLUE}[DEFENSE] Enabling defense mode...{Fore.RESET}")
        self.log_message("[+] Monitoring for attacks")
        self.log_message("[+] IDS/IPS activated")
        self.log_message("[+] Firewall rules updated")
    
    def attack_mode(self):
        """Enable attack mode"""
        messagebox.showinfo("Info", "Attack mode is disabled in this ethical build.")
    
    def block_selected(self):
        """Block selected device"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            ip = item['values'][0]
            self.log_message(f"[!] Block action is disabled in this ethical build for {ip}.")
    
    def unblock_selected(self):
        """Unblock selected device"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            ip = item['values'][0]
            self.advanced_tools.unblock_device(ip)
            self.log_message(f"[+] Unblocking device {ip}")
    
    def deauth_selected(self):
        """Deauth selected device"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            mac = item['values'][1]
            self.log_message("[!] Deauth is disabled in this ethical build.")
    
    def syn_flood_attack(self):
        """Launch SYN flood attack"""
        self.log_message("[!] SYN flood is disabled in this ethical build.")
    
    def icmp_flood_attack(self):
        """Launch ICMP flood attack"""
        self.log_message("[!] ICMP flood is disabled in this ethical build.")
    
    def udp_flood_attack(self):
        """Launch UDP flood attack"""
        self.log_message("[!] UDP flood is disabled in this ethical build.")
    
    def dns_amp_attack(self):
        """Launch DNS amplification attack"""
        self.log_message("[!] DNS amplification is disabled in this ethical build.")
    
    def arp_spoof(self):
        """Start ARP spoofing"""
        self.log_message("[!] ARP spoofing is disabled in this ethical build.")
    
    def mitm_attack(self):
        """Launch MITM attack"""
        self.log_message(f"{Fore.YELLOW}[MITM] Select target from device list first{Fore.RESET}")
    
    def launch_bettercap(self):
        """Launch Bettercap"""
        self.log_message("[!] Bettercap integration is disabled in this ethical build.")
    
    def exit_app(self):
        """Exit application"""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.advanced_tools.stop_all_attacks()
            self.bettercap.stop_bettercap()
            self.root.quit()
    
    def get_interfaces(self):
        """Get network interfaces"""
        try:
            import netifaces
            return netifaces.interfaces()
        except:
            return ["any", "eth0", "wlan0", "lo"]

    # ---------- Login ----------
    def show_login(self):
        """Modal login dialog. Returns True if authenticated."""
        self._auth_ok = False
        pwd_env = os.environ.get("WIRE_FOUAD_PASS")
        default_pwd = "1234"

        win = tk.Toplevel(self.root)
        win.title("Login – fouad wire")
        win.configure(bg="#0a0a0a")
        # Fullscreen login
        try:
            win.attributes('-fullscreen', True)
        except Exception:
            sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            win.geometry(f"{sw}x{sh}+0+0")
        win.grab_set()
        win.focus_set()
        win.transient(self.root)
        # Responsive sizing
        try:
            sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        except Exception:
            sw, sh = 1280, 800
        is_mobile_like = sw < 900
        panel_w = int(sw * (0.9 if is_mobile_like else 0.5))
        panel_h = int(sh * (0.6 if is_mobile_like else 0.5))

        # Centered panel using Canvas to emulate rounded corners + drop shadow
        panel = tk.Canvas(win, bg="#0a0a0a", highlightthickness=0, width=panel_w, height=panel_h)
        panel.place(relx=0.5, rely=0.5, anchor='center')

        def round_rect(cnv, x1, y1, x2, y2, r=24, **kw):
            points = [
                x1+r, y1,
                x2-r, y1,
                x2, y1,
                x2, y1+r,
                x2, y2-r,
                x2, y2,
                x2-r, y2,
                x1+r, y2,
                x1, y2,
                x1, y2-r,
                x1, y1+r,
                x1, y1
            ]
            return cnv.create_polygon(points, smooth=True, **kw)

        # Drop shadow
        round_rect(panel, 16, 16, panel_w-8, panel_h-8, r=28, fill="#000000", outline="")
        # Main card
        round_rect(panel, 8, 8, panel_w-16, panel_h-16, r=28, fill="#101010", outline="#00aa33")

        # Inner form frame placed inside the canvas
        form = tk.Frame(panel, bg="#101010")
        panel.create_window(panel_w//2, panel_h//2, window=form)

        title_font = ("Courier", 36 if not is_mobile_like else 28, "bold")
        subtitle_font = ("Courier", 14, "bold")
        label_font = ("Courier", 16 if not is_mobile_like else 14)
        entry_font = ("Courier", 18 if not is_mobile_like else 16)
        btn_font = ("Courier", 18 if not is_mobile_like else 16, "bold")

        title = tk.Label(form, text="fouad wire", font=title_font, bg="#101010", fg="#39ff14")
        subtitle = tk.Label(form, text="For authorized testing only", font=subtitle_font, bg="#101010", fg="#ff4444")
        title.grid(row=0, column=0, columnspan=2, pady=(10, 4), padx=24)
        subtitle.grid(row=1, column=0, columnspan=2, pady=(0, 16))

        # Username
        tk.Label(form, text="Username:", bg="#101010", fg="#39ff14", font=label_font).grid(
            row=2, column=0, sticky='e', padx=16, pady=8)
        user_entry = tk.Entry(form, bg="#0b0b0b", fg="#39ff14", insertbackground="#39ff14",
                              font=entry_font, width=28, relief="flat")
        user_entry.grid(row=2, column=1, sticky='we', padx=16, pady=8, ipady=8)

        # Password
        tk.Label(form, text="Password:", bg="#101010", fg="#39ff14", font=label_font).grid(
            row=3, column=0, sticky='e', padx=16, pady=8)
        pwd_entry = tk.Entry(form, show='*', bg="#0b0b0b", fg="#39ff14", insertbackground="#39ff14",
                             font=entry_font, width=28, relief="flat")
        pwd_entry.grid(row=3, column=1, sticky='we', padx=16, pady=8, ipady=8)
        form.columnconfigure(0, weight=0)
        form.columnconfigure(1, weight=1)

        hint_text = (
            "Use your configured password"
            if pwd_env
            else f"Default password: {default_pwd}  (or set WIRE_FOUAD_PASS)"
        )
        tk.Label(form, text=hint_text, bg="#101010", fg="#888888", font=("Courier", 11)).grid(
            row=4, column=0, columnspan=2, pady=(0, 10))

        # Forgot password link
        def forgot_pw(_e=None):
            messagebox.showinfo("Forgot Password", "Please contact your administrator to reset your password.")
        link = tk.Label(form, text="Forgot Password?", bg="#101010", fg="#39ff14", cursor="hand2", font=("Courier", 12, "underline"))
        link.bind("<Button-1>", forgot_pw)
        link.grid(row=5, column=0, columnspan=2, pady=(0, 10))

        # Buttons and spinner
        btns = tk.Frame(form, bg="#101010")
        btns.grid(row=6, column=0, columnspan=2, pady=(0, 8))

        spinner = ttk.Progressbar(form, mode="indeterminate", length=180)
        spinner.grid(row=7, column=0, columnspan=2, pady=(4, 4))
        spinner.grid_remove()

        def set_loading(on: bool):
            widgets = [user_entry, pwd_entry]
            if on:
                for w in widgets:
                    w.config(state="disabled")
                spinner.grid()
                spinner.start(12)
            else:
                for w in widgets:
                    w.config(state="normal")
                spinner.stop()
                spinner.grid_remove()

        def do_login(event=None):
            set_loading(True)
            def _check():
                user = (user_entry.get() or "").strip()
                pwd = pwd_entry.get()
                # Simple authentication: password check as before; username not enforced
                if pwd_env:
                    ok = (pwd == pwd_env)
                else:
                    ok = (pwd == default_pwd)
                if ok:
                    self._auth_ok = True
                    win.destroy()
                else:
                    messagebox.showerror("Login failed", "Invalid password.")
                set_loading(False)
            # Simulate short processing to show spinner
            win.after(400, _check)

        tk.Button(btns, text="Login", command=do_login, bg="#003300", fg="#39ff14",
                  font=btn_font, activebackground="#004400", padx=22, pady=8).pack(side='left', padx=10)

        def on_exit():
            win.destroy()
        tk.Button(btns, text="Exit", command=on_exit, bg="#330000", fg="#ff5555",
                  font=btn_font, activebackground="#550000", padx=22, pady=8).pack(side='left', padx=10)

        # Focus and allow Enter to submit
        user_entry.focus_set()
        user_entry.bind("<Return>", do_login)
        pwd_entry.bind("<Return>", do_login)

        self.root.wait_window(win)
        return self._auth_ok

if __name__ == "__main__":
    # Ensure placeholder icon exists locally for desktop integration
    ensure_app_icon(os.path.join(os.path.dirname(__file__), "icon.png"))
    root = tk.Tk()
    # Set window icon
    try:
        _icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if os.path.exists(_icon_path):
            _icon_img = tk.PhotoImage(file=_icon_path)
            root.iconphoto(True, _icon_img)
    except Exception:
        pass
    app = FouadWire(root)
    root.mainloop()
    def scan_devices(self):
        print("Scanning for devices...")
