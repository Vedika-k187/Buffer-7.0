from config.database import get_connection
from capture.dns_record import DNSRecord

def save_dns_record(record: DNSRecord):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO dns_records 
        (domain, src_ip, timestamp, query_type, entropy_score, threat_score, is_suspicious, detection_reasons)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, (
        record.domain,
        record.src_ip,
        record.timestamp,
        record.query_type,
        record.entropy_score,
        record.threat_score,
        record.is_suspicious,
        record.detection_reasons
    ))

    conn.commit()
    cursor.close()
    conn.close()

def fetch_all_records():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM dns_records ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows