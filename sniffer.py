from scapy.all import *
from scapy.arch.windows import get_windows_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS
import threading
import queue
import platform
import time
from datetime import datetime
import sys

class PacketSniffer:
    def __init__(self, packet_queue, status_queue):
        self.packet_queue = packet_queue
        self.status_queue = status_queue
        self.is_sniffing = False
        self.sniffer_thread = None
        self.interface = None
        self.filter = ""
        self.packet_count = 0
        self.packets = []
        self.start_time = None

    def _packet_handler(self, packet):
        if not self.is_sniffing:
            return

        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self.packets.append(packet)
        
        summary = self._get_packet_summary(packet)
        details = self._get_packet_details(packet)
        
        self.packet_queue.put({
            "timestamp": timestamp,
            "summary": summary,
            "details": details
        })

    def _get_packet_summary(self, packet):
        src_ip = dst_ip = src_port = dst_port = protocol = length = "N/A"
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            
            if proto == 6 and TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                if dst_port == 80 or src_port == 80:
                    protocol = "HTTP"
            elif proto == 17 and UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                if dst_port == 53 or src_port == 53:
                    protocol = "DNS"
            elif proto == 1 and ICMP in packet:
                protocol = "ICMP"
        
        if DNS in packet:
            protocol = "DNS"
        elif HTTPRequest in packet:
            protocol = "HTTP"
            
        length = len(packet)
        
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port if src_port != "N/A" else "",
            "dst_port": dst_port if dst_port != "N/A" else "",
            "protocol": protocol,
            "length": length
        }

    def _get_packet_details(self, packet):
        details = {}
        
        if Ether in packet:
            details["Ethernet"] = {
                "Source MAC": packet[Ether].src,
                "Destination MAC": packet[Ether].dst
            }
        
        if IP in packet:
            details["IP"] = {
                "Version": packet[IP].version,
                "Header Length": packet[IP].ihl,
                "TOS": packet[IP].tos,
                "Total Length": packet[IP].len,
                "Identification": packet[IP].id,
                "TTL": packet[IP].ttl,
                "Protocol": packet[IP].proto,
                "Source": packet[IP].src,
                "Destination": packet[IP].dst
            }
        
        if TCP in packet:
            details["TCP"] = {
                "Source Port": packet[TCP].sport,
                "Destination Port": packet[TCP].dport,
                "Sequence Number": packet[TCP].seq,
                "Acknowledgment": packet[TCP].ack,
                "Flags": packet[TCP].flags
            }
        elif UDP in packet:
            details["UDP"] = {
                "Source Port": packet[UDP].sport,
                "Destination Port": packet[UDP].dport,
                "Length": packet[UDP].len
            }
        elif ICMP in packet:
            details["ICMP"] = {
                "Type": packet[ICMP].type,
                "Code": packet[ICMP].code
            }
        
        if Raw in packet:
            try:
                payload = packet[Raw].load
                details["Payload"] = {
                    "Hex": payload.hex()[:100] + "..." if len(payload) > 100 else payload.hex(),
                    "ASCII": "".join([chr(x) if 32 <= x <= 126 else "." for x in payload])[:100] + "..."
                }
            except:
                pass
        
        return details

    def start_sniffing(self, interface, protocol_filter="All"):
        if self.is_sniffing:
            return

        self.interface = interface
        self.filter = self._create_filter(protocol_filter)
        self.is_sniffing = True
        self.packet_count = 0
        self.packets = []
        self.start_time = datetime.now()
        
        def sniff_thread():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    filter=self.filter,
                    store=False,
                    timeout=1
                )
            except Exception as e:
                self.status_queue.put(f"Error: {str(e)}")
                self.is_sniffing = False

        self.sniffer_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniffer_thread.start()
        self.status_queue.put(f"Sniffing started on {self.interface} (Filter: {protocol_filter})")

    def _create_filter(self, protocol_filter):
        filters = {
            "TCP": "tcp",
            "UDP": "udp",
            "HTTP": "tcp port 80",
            "DNS": "udp port 53 or tcp port 53",
            "ICMP": "icmp",
            "All": "ip or arp"
        }
        return filters.get(protocol_filter, "ip or arp")

    def stop_sniffing(self):
        self.is_sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        duration = datetime.now() - self.start_time
        self.status_queue.put(f"Stopped. Captured {self.packet_count} packets in {duration.total_seconds():.1f} seconds")

    def save_to_pcap(self, filename):
        try:
            wrpcap(filename, self.packets)
            return True
        except Exception as e:
            self.status_queue.put(f"Save failed: {str(e)}")
            return False

    def get_interfaces(self):
        try:
            if platform.system() == "Windows":
                return [iface['name'] for iface in get_windows_if_list()]
            else:
                return get_if_list()
        except Exception as e:
            print(f"Interface error: {e}", file=sys.stderr)
            return ["No interfaces found - Run as Admin"]