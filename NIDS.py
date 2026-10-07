from scapy.all import sniff
from scapy.layers.inet import IP, TCP
import datetime

with open("security_report.log", "a") as f:
    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"[{time_now}] [i] NIDS Log file initialized and monitoring started.\n")

print("[i] NIDS Monitoring started... Watching network traffic for suspicious activities.\n")

scans_tracker = {}

def catch_the_hacker(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        if src_ip not in scans_tracker:
            scans_tracker[src_ip] = set()
        
        scans_tracker[src_ip].add(dst_port)
        
        if len(scans_tracker[src_ip]) > 5:
            alert_text = f"[ALERT] Potential Port Scanning detected from IP: {src_ip}"
            print(f"\033[93m{alert_text}\033[0m")
            
            with open("security_report.log", "a") as f:
                time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{time_now}] {alert_text}\n")
            
            scans_tracker[src_ip] = set()

try:
    sniff(filter="ip", prn=catch_the_hacker, store=False)
except KeyboardInterrupt:
    print("\n[i] NIDS monitoring stopped by user.")

