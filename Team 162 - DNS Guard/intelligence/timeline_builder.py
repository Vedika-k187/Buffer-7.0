from config.database import get_connection
from analysis.entropy_detector import is_suspicious_entropy
from analysis.sliding_window import add_query
from analysis.typosquatting_detector import check_typosquatting
from analysis.stego_detector import analyze_domain as stego_analyze
from analysis.anomaly_detector import predict_anomaly
from datetime import datetime, timedelta

def determine_severity(score):
    if score >= 76:
        return "CRITICAL"
    elif score >= 51:
        return "HIGH"
    elif score >= 26:
        return "MEDIUM"
    else:
        return "INFO"

def build_timeline_for_domain(domain):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT domain, src_ip, timestamp, query_type FROM dns_records WHERE domain = %s ORDER BY timestamp ASC",
        (domain,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    if not rows:
        return []

    events = []

    # Event 1 - First query seen
    first = rows[0]
    events.append({
        "domain": domain,
        "event_type": "FIRST_QUERY",
        "event_description": f"First DNS query seen from {first[1]} — type {first[3]}",
        "severity": "INFO",
        "occurred_at": first[2]
    })

    # Event 2 - Entropy check
    entropy = is_suspicious_entropy(domain)
    if entropy["is_suspicious"]:
        events.append({
            "domain": domain,
            "event_type": "ENTROPY_ALERT",
            "event_description": f"High entropy detected — {entropy['reason']}",
            "severity": "HIGH",
            "occurred_at": first[2] + timedelta(seconds=1)
        })

    # Event 3 - Tunneling check
    for _, _, ts, _ in rows:
        tunneling = add_query(domain, ts)
        if tunneling["is_suspicious"]:
            events.append({
                "domain": domain,
                "event_type": "TUNNELING_ALERT",
                "event_description": f"DNS tunneling detected — {tunneling['reason']}",
                "severity": "CRITICAL",
                "occurred_at": ts
            })
            break

    # Event 4 - Typosquatting check
    typo = check_typosquatting(domain)
    if typo["is_suspicious"]:
        events.append({
            "domain": domain,
            "event_type": "TYPOSQUATTING_ALERT",
            "event_description": f"Typosquatting detected — {typo['reason']}",
            "severity": "HIGH",
            "occurred_at": first[2] + timedelta(seconds=2)
        })

    # Event 5 - Steganography check
    stego = stego_analyze(domain)
    if stego["is_suspicious"]:
        events.append({
            "domain": domain,
            "event_type": "STEGANOGRAPHY_ALERT",
            "event_description": f"Hidden data found — {stego['reason']}",
            "severity": "CRITICAL",
            "occurred_at": first[2] + timedelta(seconds=3)
        })

    # Event 6 - ML Anomaly check
    anomaly = predict_anomaly(domain)
    if anomaly and anomaly["is_anomaly"]:
        events.append({
            "domain": domain,
            "event_type": "ANOMALY_ALERT",
            "event_description": f"ML anomaly detected — {anomaly['reason']}",
            "severity": "HIGH",
            "occurred_at": first[2] + timedelta(seconds=4)
        })

    # Event 7 - Last query seen
    if len(rows) > 1:
        last = rows[-1]
        events.append({
            "domain": domain,
            "event_type": "LAST_QUERY",
            "event_description": f"Last DNS query seen — total {len(rows)} queries recorded",
            "severity": "INFO",
            "occurred_at": last[2]
        })

    # Sort all events by time
    events.sort(key=lambda x: x["occurred_at"])
    return events

def save_timeline_events(events):
    conn = get_connection()
    cursor = conn.cursor()

    for event in events:
        if event["severity"] == "INFO":
            continue  # Only save warning+ events

        query = """
            INSERT INTO attack_timeline
            (domain, event_type, event_description, severity, occurred_at)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            event["domain"],
            event["event_type"],
            event["event_description"],
            event["severity"],
            event["occurred_at"]
        ))

    conn.commit()
    cursor.close()
    conn.close()

def print_timeline(domain, events):
    print(f"\nAttack Timeline for: {domain}")
    print("-" * 55)
    for event in events:
        time_str = event["occurred_at"].strftime("%H:%M:%S")
        print(f"  {time_str}  [{event['severity']:<8}]  {event['event_description']}")
    print("-" * 55)

def build_full_timeline():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT domain FROM dns_records")
    domains = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()

    all_events = []
    for domain in domains:
        events = build_timeline_for_domain(domain)
        save_timeline_events(events)
        all_events.extend(events)

    all_events.sort(key=lambda x: x["occurred_at"])
    return all_events

def fetch_timeline_from_db(domain=None):
    conn = get_connection()
    cursor = conn.cursor()

    if domain:
        cursor.execute("""
            SELECT domain, event_type, event_description, severity, occurred_at
            FROM attack_timeline
            WHERE domain = %s
            ORDER BY occurred_at ASC
        """, (domain,))
    else:
        cursor.execute("""
            SELECT domain, event_type, event_description, severity, occurred_at
            FROM attack_timeline
            ORDER BY occurred_at ASC
        """)

    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows