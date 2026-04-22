from capture.packet_queue import get_from_queue, is_empty
from capture.db_writer import save_dns_record

def process_queue():
    processed = 0
    while not is_empty():
        record = get_from_queue()
        save_dns_record(record)
        processed += 1
        print(f"Saved: {record.domain} | {record.src_ip} | {record.timestamp}")

    print(f"Total records saved to database: {processed}")