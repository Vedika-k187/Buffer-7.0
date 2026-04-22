from scapy.all import rdpcap, DNS, DNSQR, IP
from datetime import datetime
from capture.dns_record import DNSRecord
from capture.packet_queue import add_to_queue

def read_pcap(filepath):
    print(f"Reading PCAP file: {filepath}")
    packets = rdpcap(filepath)
    count = 0

    for packet in packets:
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                domain = packet[DNSQR].qname.decode().rstrip(".")
                src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                query_type = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT"}.get(
                    packet[DNSQR].qtype, "OTHER"
                )
                timestamp = datetime.fromtimestamp(float(packet.time))

                record = DNSRecord(
                    domain=domain,
                    src_ip=src_ip,
                    timestamp=timestamp,
                    query_type=query_type
                )

                add_to_queue(record)
                count += 1

            except Exception as e:
                print(f"Error parsing packet: {e}")
                continue

    print(f"Total DNS packets extracted: {count}")
    return count