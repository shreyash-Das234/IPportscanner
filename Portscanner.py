import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import platform
import threading
import socket
import ipaddress
import time
import csv
import subprocess
from datetime import datetime
from queue import Queue

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    ARP = Ether = srp = None

import psutil
import nmap

# Common ports for quick scans
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389]

# OUI Database cache for MAC vendor lookup
OUI_DB = {}
def load_oui_db(file_path="oui.csv"):
    if not os.path.exists(file_path):
        return
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "," in line:
                prefix, vendor = line.strip().split(",", 1)
                OUI_DB[prefix.upper()] = vendor

load_oui_db()

class NetworkToolApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Unified Network Tool - IP & Port Scanner")
        self.root.geometry("1200x700")
        self.root.configure(bg="white")

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        ip_frame = tk.Frame(notebook, bg="white")
        port_frame = tk.Frame(notebook, bg="white")
        notebook.add(ip_frame, text="IP Scanner")
        notebook.add(port_frame, text="Port & Vulnerability Scanner")

        self.ip_scanner = IPScannerTab(ip_frame)
        self.port_scanner = PortScannerTab(port_frame)

class IPScannerTab:
    def __init__(self, parent):
        self.parent = parent
        self.search_var = tk.StringVar()
        self.network_var = tk.StringVar(value="10.10.0.0/24")
        self.interface_var = tk.StringVar(value="auto")
        self.data = []
        self.scanning = False
        self.queue = Queue()
        self.progress = tk.DoubleVar()
        self.status_var = tk.StringVar(value="Ready to scan")
        self.after_id = None  # auto-rescan timer

        self.setup_ui()
        self.parent.after(100, self.check_queue)

    def setup_ui(self):
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)
        style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))

        status_frame = tk.Frame(self.parent, bg="white")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(status_frame, textvariable=self.status_var, bg="white", font=('Helvetica', 10)).pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True)

        control_frame = tk.Frame(self.parent, bg="white")
        control_frame.pack(fill=tk.X, padx=10, pady=10)

        config_frame = tk.Frame(control_frame, bg="white")
        config_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Label(config_frame, text="Network:", bg="white").grid(row=0, column=0, sticky="e")
        tk.Entry(config_frame, textvariable=self.network_var, width=20).grid(row=0, column=1, padx=5)

        tk.Label(config_frame, text="Interface:", bg="white").grid(row=0, column=2, sticky="e")
        iface_dropdown = ttk.Combobox(config_frame, textvariable=self.interface_var, width=15)
        iface_dropdown.grid(row=0, column=3, padx=5)
        iface_dropdown['values'] = self.get_network_interfaces()

        search_frame = tk.Frame(control_frame, bg="white")
        search_frame.pack(side=tk.RIGHT)
        tk.Label(search_frame, text="Search:", bg="white").pack(side=tk.LEFT)
        tk.Entry(search_frame, textvariable=self.search_var, width=25).pack(side=tk.LEFT, padx=5)
        tk.Button(search_frame, text="Search", command=self.search_ip).pack(side=tk.LEFT)

        btn_frame = tk.Frame(self.parent, bg="white")
        btn_frame.pack(pady=5)
        button_style = {'bg': '#4CAF50', 'fg': 'white', 'padx': 10, 'pady': 5}
        tk.Button(btn_frame, text="Scan Now", command=self.scan_network_thread, **button_style).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, bg='#f44336', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Clear Results", command=self.clear_tree, bg='#FF9800', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Export CSV", command=self.export_csv, bg='#2196F3', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Ping Selected", command=self.ping_selected_ips, bg='#9C27B0', fg='white').pack(side=tk.LEFT, padx=5)

        tree_frame = tk.Frame(self.parent, bg="white")
        tree_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)

        columns = ("IP", "MAC", "Hostname", "Status", "Vendor", "Response", "Interface", "Ping Result")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20, selectmode="extended")
        col_widths = [150, 150, 200, 100, 150, 100, 100, 180]
        for col, width in zip(columns, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(expand=True, fill=tk.BOTH)

        self.tree.tag_configure('active', background='#e8f5e9')
        self.tree.tag_configure('inactive', background='#ffebee')
        self.tree.tag_configure('unknown', background='#fff8e1')
        self.tree.bind("<Double-1>", self.on_item_double_click)

    def get_network_interfaces(self):
        interfaces = []
        try:
            stats = psutil.net_if_stats()
            for iface in psutil.net_if_addrs():
                if stats.get(iface) and stats[iface].isup and iface != 'lo':
                    interfaces.append(iface)
        except Exception:
            pass
        return ['auto'] + sorted(interfaces)

    def clear_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.data.clear()
        self.status_var.set("Ready to scan")
        self.progress.set(0)

    def stop_scan(self):
        self.scanning = False
        self.status_var.set("Scan stopped")
        if self.after_id:
            try:
                self.parent.after_cancel(self.after_id)
            except Exception:
                pass
            self.after_id = None

    def search_ip(self):
        query = self.search_var.get().strip().lower()
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            matches = any(query in str(value).lower() for value in values)
            self.tree.selection_remove(item)
            if query and matches:
                self.tree.selection_add(item)
                self.tree.see(item)

    def on_item_double_click(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0], "values")[0]
        threading.Thread(target=self.ping_ip, args=(ip,), daemon=True).start()

    def ping_selected_ips(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("No Selection", "Please select one or more IP addresses to ping.")
            return
        ips = [self.tree.item(item, "values")[0] for item in selected_items]
        threading.Thread(target=self.ping_multiple_ips, args=(ips,), daemon=True).start()

    def ping_multiple_ips(self, ips):
        self.queue.put(("status", f"Pinging {len(ips)} selected IPs..."))
        for i, ip in enumerate(ips):
            if not self.scanning:
                break
            self.ping_ip(ip)
            time.sleep(0.3)
            self.queue.put(("progress", ((i + 1) / len(ips)) * 100))
        self.queue.put(("status", "Ping completed for selected IPs"))

    def ping_ip(self, ip):
        try:
            start_time = time.time()
            cmd = ["ping", "-n", "1", ip] if platform.system().lower() == "windows" else ["ping", "-c", "1", ip]
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            response_time = round((time.time() - start_time) * 1000, 2)
            if result.returncode == 0:
                self.queue.put(("update", {"ip": ip, "column": "Status", "value": "Active"}))
                self.queue.put(("update", {"ip": ip, "column": "Response", "value": f"{response_time} ms"}))
                self.queue.put(("update", {"ip": ip, "column": "Ping Result", "value": f"Success ({response_time} ms)"}))
                self.queue.put(("tag", {"ip": ip, "tag": "active"}))
            else:
                self.queue.put(("update", {"ip": ip, "column": "Status", "value": "Inactive"}))
                self.queue.put(("update", {"ip": ip, "column": "Response", "value": "Timeout"}))
                self.queue.put(("update", {"ip": ip, "column": "Ping Result", "value": "Failed"}))
                self.queue.put(("tag", {"ip": ip, "tag": "inactive"}))
        except Exception:
            self.queue.put(("update", {"ip": ip, "column": "Status", "value": "Error"}))
            self.queue.put(("update", {"ip": ip, "column": "Ping Result", "value": "Error"}))
            self.queue.put(("tag", {"ip": ip, "tag": "unknown"}))

    def scan_network_thread(self):
        if self.scanning:
            return
        self.scanning = True
        self.status_var.set("Scanning network...")
        self.progress.set(0)
        if self.after_id:
            try:
                self.parent.after_cancel(self.after_id)
            except Exception:
                pass
            self.after_id = None
        threading.Thread(target=self.scan_network, daemon=True).start()

    def scan_network(self):
        self.clear_tree()
        if ARP is None:
            self.queue.put(("error", "Scapy is not installed. Install with: pip install scapy"))
            self.scanning = False
            return
        try:
            ip_range = self.get_network_range()
            if not ip_range:
                self.queue.put(("error", "No valid network range found"))
                return
            iface = None if self.interface_var.get() == "auto" else self.interface_var.get()
            self.queue.put(("status", f"Scanning {ip_range} on {iface or 'auto'}..."))

            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result, _ = srp(packet, timeout=2, verbose=0, iface=iface, inter=0.1)

            active_ips = set()
            for i, (_, received) in enumerate(result):
                if not self.scanning:
                    break
                ip = received.psrc
                mac = received.hwsrc
                active_ips.add(ip)
                self.queue.put(("add", {
                    "ip": ip,
                    "mac": mac,
                    "hostname": "Resolving...",
                    "status": "Active",
                    "vendor": self.get_mac_vendor(mac),
                    "response": "",
                    "interface": iface or "auto",
                    "ping": ""
                }))
                self.queue.put(("progress", (i + 1) / max(len(result), 1) * 100))
                threading.Thread(target=self.resolve_hostname, args=(ip,), daemon=True).start()
                threading.Thread(target=self.ping_ip, args=(ip,), daemon=True).start()

            self.check_inactive_ips(active_ips, ip_range)
            self.queue.put(("status", f"Scan completed - {len(result)} active hosts found"))
            self.queue.put(("progress", 100))
        except Exception as e:
            self.queue.put(("error", f"Scan error: {str(e)}"))
        finally:
            self.scanning = False
            self.after_id = self.parent.after(300000, self.scan_network_thread)

    def get_network_range(self):
        manual_net = self.network_var.get().strip()
        if manual_net:
            try:
                net = ipaddress.IPv4Network(manual_net, strict=False)
                return str(net)
            except ValueError as e:
                self.queue.put(("warning", f"Invalid network format: {e}"))
        iface = None if self.interface_var.get() == "auto" else self.interface_var.get()
        return self.auto_detect_network(iface)

    def auto_detect_network(self, iface=None):
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        if iface and iface in interfaces:
            for snic in interfaces[iface]:
                if snic.family == socket.AF_INET:
                    ip = snic.address
                    if not (ip.startswith('127.') or ip.startswith('169.254.')):
                        try:
                            return str(ipaddress.IPv4Network(f"{ip}/{snic.netmask}", strict=False))
                        except Exception:
                            continue
        io_counters = psutil.net_io_counters(pernic=True)
        active_ifaces = sorted(
            [(iface, data.bytes_sent + data.bytes_recv)
             for iface, data in io_counters.items()
             if stats.get(iface) and stats[iface].isup and iface != 'lo'],
            key=lambda x: x[1],
            reverse=True
        )
        for iface, _ in active_ifaces:
            for snic in interfaces[iface]:
                if snic.family == socket.AF_INET:
                    ip = snic.address
                    if not (ip.startswith('127.') or ip.startswith('169.254.')):
                        try:
                            return str(ipaddress.IPv4Network(f"{ip}/{snic.netmask}", strict=False))
                        except Exception:
                            continue
        return None

    def check_inactive_ips(self, active_ips, ip_range):
        try:
            network = ipaddress.IPv4Network(ip_range)
            for i, ip in enumerate(network.hosts()):
                if not self.scanning:
                    break
                sip = str(ip)
                if sip in active_ips:
                    continue
                if sip.endswith('.0') or sip.endswith('.255'):
                    continue
                self.queue.put(("add", {
                    "ip": sip,
                    "mac": "Unknown",
                    "hostname": "Unknown",
                    "status": "Inactive",
                    "vendor": "Unknown",
                    "response": "No ARP response",
                    "interface": "N/A",
                    "ping": "Not Tested"
                }))
                if i >= 50:  # Only show up to 50 inactive IPs
                    break
        except Exception as e:
            self.queue.put(("warning", f"Couldn't check inactive IPs: {str(e)}"))

    def resolve_hostname(self, ip):
        try:
            hostname = socket.getfqdn(ip)
            if hostname == ip:
                hostname = "Unknown"
            self.queue.put(("update", {"ip": ip, "column": "Hostname", "value": hostname}))
        except Exception:
            self.queue.put(("update", {"ip": ip, "column": "Hostname", "value": "Unknown"}))

    def get_mac_vendor(self, mac):
        if not mac:
            return "Unknown"
        prefix = mac.upper()[0:8]
        return OUI_DB.get(prefix, "Unknown")

    def check_queue(self):
        while not self.queue.empty():
            action, *args = self.queue.get()
            if action == "add":
                data = args[0]
                self.tree.insert(
                    "",
                    "end",
                    values=(
                        data["ip"], data["mac"], data["hostname"], data["status"],
                        data["vendor"], data["response"], data["interface"], data.get("ping", "")
                    ),
                    tags=(data["status"].lower(),)
                )
                self.data.append(data)
            elif action == "update":
                data = args[0]
                for item in self.tree.get_children():
                    values = list(self.tree.item(item, 'values'))
                    if values[0] == data["ip"]:
                        col_index = self.tree['columns'].index(data["column"])
                        values[col_index] = data["value"]
                        self.tree.item(item, values=values)
                        break
            elif action == "tag":
                data = args[0]
                for item in self.tree.get_children():
                    values = self.tree.item(item, 'values')
                    if values[0] == data["ip"]:
                        self.tree.item(item, tags=(data["tag"],))
                        break
            elif action == "progress":
                self.progress.set(args[0])
            elif action == "status":
                self.status_var.set(args[0])
            elif action == "error":
                messagebox.showerror("Error", args[0])
                self.status_var.set("Error")
                self.scanning = False
            elif action == "warning":
                messagebox.showwarning("Warning", args[0])
                self.status_var.set("Warning")
        self.parent.after(100, self.check_queue)

    def export_csv(self):
        if not self.data:
            messagebox.showwarning("No Data", "There is no data to export.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save as"
        )
        if not file_path:
            return
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["IP", "MAC", "Hostname", "Status", "Vendor", "Response", "Interface", "Ping Result"])
                for data in self.data:
                    writer.writerow([
                        data["ip"], data["mac"], data["hostname"], data["status"],
                        data["vendor"], data["response"], data["interface"], data.get("ping", "")
                    ])
            messagebox.showinfo("Export Successful", f"Data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export data: {str(e)}")


class PortScannerTab:
    def __init__(self, parent):
        self.parent = parent
        self.target_var = tk.StringVar()
        self.scan_result = scrolledtext.ScrolledText(self.parent, width=140, height=30, wrap=tk.WORD)
        self.nm = nmap.PortScanner()

        self.setup_ui()

    def setup_ui(self):
        frame = tk.Frame(self.parent, bg="white")
        frame.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(frame, text="Target (IP/Domain):", bg="white").pack(side=tk.LEFT)
        tk.Entry(frame, textvariable=self.target_var, width=30).pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Quick Scan", command=self.quick_scan, bg='#4CAF50', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Full Scan", command=self.full_scan, bg='#2196F3', fg='white').pack(side=tk.LEFT, padx=5)
        tk.Button(frame, text="Vulnerability Scan", command=self.vuln_scan, bg='#f44336', fg='white').pack(side=tk.LEFT, padx=5)

        self.scan_result.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def quick_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Please enter a target IP or domain.")
            return
        self.scan_result.insert(tk.END, f"Starting quick scan on {target}...\n")
        threading.Thread(target=self.run_scan, args=(target, COMMON_PORTS), daemon=True).start()

    def full_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Please enter a target IP or domain.")
            return
        self.scan_result.insert(tk.END, f"Starting full scan on {target} (1-65535)...\n")
        threading.Thread(target=self.run_scan, args=(target, range(1, 65536)), daemon=True).start()

    def vuln_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Please enter a target IP or domain.")
            return
        self.scan_result.insert(tk.END, f"Starting vulnerability scan on {target} using Nmap scripts...\n")
        threading.Thread(target=self.run_vuln_scan, args=(target,), daemon=True).start()

    def run_scan(self, target, ports):
        try:
            open_ports = []
            for port in ports:
                if self.is_port_open(target, port):
                    open_ports.append(port)
                    self.scan_result.insert(tk.END, f"Port {port}: OPEN\n")
                else:
                    self.scan_result.insert(tk.END, f"Port {port}: closed\n")
            self.scan_result.insert(tk.END, f"\nScan completed. Open ports: {open_ports}\n\n")
        except Exception as e:
            self.scan_result.insert(tk.END, f"Scan error: {str(e)}\n")

    def is_port_open(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target, port))
                return result == 0
        except Exception:
            return False

    def run_vuln_scan(self, target):
        try:
            self.nm.scan(target, arguments="--script vuln")
            for host in self.nm.all_hosts():
                self.scan_result.insert(tk.END, f"\nHost: {host} ({self.nm[host].hostname()})\n")
                self.scan_result.insert(tk.END, f"State: {self.nm[host].state()}\n")
                for proto in self.nm[host].all_protocols():
                    self.scan_result.insert(tk.END, f"\nProtocol: {proto}\n")
                    lport = self.nm[host][proto].keys()
                    for port in sorted(lport):
                        self.scan_result.insert(tk.END, f"Port: {port}\tState: {self.nm[host][proto][port]['state']}\n")
        except Exception as e:
            self.scan_result.insert(tk.END, f"Vulnerability scan error: {str(e)}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolApp(root)
    root.mainloop()
