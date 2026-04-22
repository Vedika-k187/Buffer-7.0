from config.database import get_connection
from datetime import datetime

def format_alert(score_result):
    border = "=" * 55
    lines = []
    lines.append(border)
    lines.append(f"  ALERT: {score_result['domain']}")
    lines.append(border)
    lines.append(f"  Threat Score : {score_result['final_score']}/100")
    lines.append(f"  Severity     : {score_result['severity']}")
    lines.append(f"  Timestamp    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("  Detection Reasons:")
    for i, reason in enumerate(score_result["reasons"], 1):
        lines.append(f"    {i}. {reason}")
    lines.append("")
    lines.append("  Score Breakdown:")
    lines.append(f"    Entropy        : {score_result['entropy_contribution']}/25")
    lines.append(f"    Tunneling      : {score_result['tunneling_contribution']}/25")
    lines.append(f"    Typosquatting  : {score_result['typo_contribution']}/20")
    lines.append(f"    Steganography  : {score_result['stego_contribution']}/20")
    lines.append(f"    ML Anomaly     : {score_result['anomaly_contribution']}/10")
    lines.append(border)
    return "\n".join(lines)

def save_alert(score_result):
    if not score_result["is_threat"]:
        return

    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO alerts (domain, severity, threat_score, reasons)
        VALUES (%s, %s, %s, %s)
    """

    cursor.execute(query, (
        score_result["domain"],
        score_result["severity"],
        score_result["final_score"],
        "\n".join(score_result["reasons"])
    ))

    conn.commit()
    cursor.close()
    conn.close()

def fetch_all_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, severity, threat_score, reasons, created_at
        FROM alerts
        ORDER BY threat_score DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

def fetch_critical_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, severity, threat_score, reasons, created_at
        FROM alerts
        WHERE severity = 'CRITICAL'
        ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows