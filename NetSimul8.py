import scapy.all as scapy  # type: ignore
import socket
import time
import threading
import logging
import re
from tkinter import Tk, Label, Entry, Button, Text, END, messagebox


ASCII_BANNER = r"""
   _   _      _   _____           _       _   _ _______ 
  | \ | |    | | /  ___|         | |     | | | |_   _| |
  |  \| | ___| |_\ `--. _   _ ___| |_ ___| | | | | | | |
  | . ` |/ _ \ __|`--. \ | | / __| __/ _ \ | | | | | | |
  | |\  |  __/ |_/\__/ / |_| \__ \ ||  __/ |_| |_| |_| |
  \_| \_/\___|\__\____/ \__, |___/\__\___|\___/ \___/\__/
                         __/ |                           
                        |___/                            
"""


logging.basicConfig(filename="network_traffic.log", level=logging.INFO, format="%(asctime)s - %(message)s")


def validate_ip(ip):
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if pattern.match(ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split("."))
    return False


def validate_port_range(port_range):
    try:
        start, end = map(int, port_range.split("-"))
        if 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end:
            return (start, end)
    except ValueError:
        pass
    return None

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except Exception as e:
        return None

# Port Scanning Function
def scan_port(ip, port, output_text):
    syn_packet = scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="S")
    response = scapy.sr1(syn_packet, timeout=1, verbose=0)
    if response and response.haslayer(scapy.TCP) and response[scapy.TCP].flags == 0x12:
        result = f"[+] Port {port} is open."
        output_text.insert(END, result + "\n")
        logging.info(result)
        banner = grab_banner(ip, port)
        if banner:
            banner_result = f"[+] Banner: {banner}"
            output_text.insert(END, banner_result + "\n")
            logging.info(banner_result)
        scapy.send(scapy.IP(dst=ip) / scapy.TCP(dport=port, flags="R"), verbose=0)

def port_scanner(target_ip, port_range, output_text):
    output_text.insert(END, "[+] Starting Port Scanning...\n")
    threads = []
    for port in range(port_range[0], port_range[1] + 1):
        thread = threading.Thread(target=scan_port, args=(target_ip, port, output_text))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    output_text.insert(END, "[+] Port Scanning Completed.\n")

# Brute Force Simulation Function
def brute_force_simulation(target_ip, target_port, output_text):
    output_text.insert(END, "[+] Starting Brute Force Simulation...\n")
    usernames = ["admin", "user", "root"]
    passwords = ["1234", "password", "admin"]

    for username in usernames:
        for password in passwords:
            attempt = f"[-] Attempting login with Username: {username}, Password: {password}"
            output_text.insert(END, attempt + "\n")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target_ip, target_port))
                s.sendall(f"{username}:{password}".encode())
                s.close()
                time.sleep(0.5)
            except socket.timeout:
                output_text.insert(END, f"[!] Connection to {target_ip}:{target_port} timed out.\n")
            except ConnectionRefusedError:
                output_text.insert(END, f"[!] Connection to {target_ip}:{target_port} refused.\n")
            except Exception as e:
                output_text.insert(END, f"[!] Error: {e}\n")
    output_text.insert(END, "[+] Brute Force Simulation Completed.\n")

# Data Exfiltration Simulation Function
def data_exfiltration_simulation(target_ip, target_port, payload, output_text):
    output_text.insert(END, "[+] Starting Data Exfiltration Simulation...\n")
    if not payload:
        payload = "This is a simulated exfiltration payload. " * 10  # Default payload

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        s.sendall(payload.encode())
        s.close()
        output_text.insert(END, "[+] Data exfiltration simulated successfully.\n")
        logging.info(f"Data exfiltration simulated to {target_ip}:{target_port}.")
    except Exception as e:
        output_text.insert(END, f"[!] Error: {e}\n")


class NetworkToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetSimul8")
        self.root.geometry("800x700")

        
        self.banner_label = Label(root, text=ASCII_BANNER, font=("Courier", 10))
        self.banner_label.pack()

        
        self.ip_label = Label(root, text="Target IP:")
        self.ip_label.pack()
        self.ip_entry = Entry(root, width=30)
        self.ip_entry.pack()

        self.port_scan_label = Label(root, text="\nPort Scanning", font=("Arial", 12, "bold"))
        self.port_scan_label.pack()
        self.port_range_label = Label(root, text="Port Range (e.g., 20-80):")
        self.port_range_label.pack()
        self.port_range_entry = Entry(root, width=30)
        self.port_range_entry.pack()
        self.port_scan_button = Button(root, text="Start Port Scan", command=self.start_port_scan)
        self.port_scan_button.pack()

        self.brute_force_label = Label(root, text="\nBrute Force Simulation", font=("Arial", 12, "bold"))
        self.brute_force_label.pack()
        self.brute_force_port_label = Label(root, text="Brute Force Port:")
        self.brute_force_port_label.pack()
        self.brute_force_port_entry = Entry(root, width=30)
        self.brute_force_port_entry.pack()
        self.brute_force_button = Button(root, text="Start Brute Force", command=self.start_brute_force)
        self.brute_force_button.pack()

        self.exfil_label = Label(root, text="\nData Exfiltration Simulation", font=("Arial", 12, "bold"))
        self.exfil_label.pack()
        self.exfil_port_label = Label(root, text="Exfiltration Port:")
        self.exfil_port_label.pack()
        self.exfil_port_entry = Entry(root, width=30)
        self.exfil_port_entry.pack()
        self.payload_label = Label(root, text="Payload (for exfiltration):")
        self.payload_label.pack()
        self.payload_entry = Entry(root, width=30)
        self.payload_entry.pack()
        self.exfil_button = Button(root, text="Start Data Exfiltration", command=self.start_data_exfiltration)
        self.exfil_button.pack()

        # Output Text
        self.output_text = Text(root, height=20, width=90)
        self.output_text.pack()

    def start_port_scan(self):
        target_ip = self.ip_entry.get()
        port_range = self.port_range_entry.get()
        if not validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address.")
            return
        valid_range = validate_port_range(port_range)
        if not valid_range:
            messagebox.showerror("Error", "Invalid port range.")
            return
        self.output_text.insert(END, "[+] Starting Port Scanning...\n")
        port_scanner(target_ip, valid_range, self.output_text)

    def start_brute_force(self):
        target_ip = self.ip_entry.get()
        target_port = self.brute_force_port_entry.get()
        if not validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address.")
            return
        try:
            target_port = int(target_port)
        except ValueError:
            messagebox.showerror("Error", "Invalid port.")
            return
        self.output_text.insert(END, "[+] Starting Brute Force Simulation...\n")
        brute_force_simulation(target_ip, target_port, self.output_text)

    def start_data_exfiltration(self):
        target_ip = self.ip_entry.get()
        target_port = self.exfil_port_entry.get()
        payload = self.payload_entry.get()
        if not validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address.")
            return
        try:
            target_port = int(target_port)
        except ValueError:
            messagebox.showerror("Error", "Invalid port.")
            return
        self.output_text.insert(END, "[+] Starting Data Exfiltration Simulation...\n")
        data_exfiltration_simulation(target_ip, target_port, payload, self.output_text)


if __name__ == "__main__":
    root = Tk()
    app = NetworkToolGUI(root)
    root.mainloop()
