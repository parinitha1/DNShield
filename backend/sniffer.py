from scapy.all import sniff, DNSQR
import time
from backend.detector import classify
from backend.database import insert_log
from backend.blocker import block_domain, is_blocked

def process_packet(packet):
    if packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode().rstrip(".")

        # Skip already-blocked domains (silently drop)
        if is_blocked(domain):
            print(f"[BLOCKED — dropped] {domain}")
            return

        result = classify(domain)

        log = {
            "domain": domain,
            "result": result,
            "timestamp": time.time()
        }

        insert_log(log)
        print(f"{domain} → {result}")

        # Auto-block on detection
        if result == "Malicious":
            block_domain(domain)

def start_sniffer():
    sniff(filter="udp port 53", prn=process_packet, store=0)
