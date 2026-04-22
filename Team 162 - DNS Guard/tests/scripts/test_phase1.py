import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from capture.pcap_reader import read_pcap
from capture.queue_processor import process_queue
from capture.db_writer import fetch_all_records

# ---- CHANGE THIS PATH TO YOUR PCAP FILE ----
PCAP_FILE = "data/pcap_samples/dns-remoteshell.pcap"

print("=" * 50)
print("PHASE 1 TEST — DNS CAPTURE ENGINE")
print("=" * 50)

print("\nStep 1: Reading PCAP file...")
count = read_pcap(PCAP_FILE)

print(f"\nStep 2: Processing queue ({count} records)...")
process_queue()

print("\nStep 3: Fetching from database...")
records = fetch_all_records()
print(f"Total records in database: {len(records)}")

print("\nFirst 5 records:")
for row in records[:5]:
    print(row)

print("\nPhase 1 Complete!")