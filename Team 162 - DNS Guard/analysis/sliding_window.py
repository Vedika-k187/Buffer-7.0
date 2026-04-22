from collections import deque, defaultdict
from datetime import datetime, timedelta
from config.settings import SLIDING_WINDOW_SECONDS, QUERY_FREQUENCY_THRESHOLD
from config.database import get_connection

# In-memory store for live detection
# key: base_domain, value: deque of timestamps
domain_windows = defaultdict(deque)

def extract_base_domain(domain):
    # a1.data.attacker.com → attacker.com
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def add_query(domain, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now()

    base = extract_base_domain(domain)
    window = domain_windows[base]

    # Add new timestamp
    window.append(timestamp)

    # Remove timestamps outside the window
    cutoff = timestamp - timedelta(seconds=SLIDING_WINDOW_SECONDS)
    while window and window[0] < cutoff:
        window.popleft()

    count = len(window)
    is_suspicious = count > QUERY_FREQUENCY_THRESHOLD

    return {
        "base_domain": base,
        "query_count": count,
        "window_seconds": SLIDING_WINDOW_SECONDS,
        "is_suspicious": is_suspicious,
        "reason": f"{count} queries in {SLIDING_WINDOW_SECONDS}s exceeds threshold {QUERY_FREQUENCY_THRESHOLD}" if is_suspicious else "Normal frequency"
    }

def save_tunneling_result(result):
    if not result["is_suspicious"]:
        return

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO tunneling_detections (base_domain, query_count, window_seconds)
        VALUES (%s, %s, %s)
    """

    cursor.execute(query, (
        result["base_domain"],
        result["query_count"],
        result["window_seconds"]
    ))

    conn.commit()
    cursor.close()
    conn.close()

def analyze_from_database():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain, timestamp FROM dns_records ORDER BY timestamp ASC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    results = []
    for domain, timestamp in rows:
        result = add_query(domain, timestamp)
        if result["is_suspicious"]:
            save_tunneling_result(result)
            results.append(result)

    return results