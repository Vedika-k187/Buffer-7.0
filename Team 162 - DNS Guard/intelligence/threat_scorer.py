from config.database import get_connection
from analysis.entropy_detector import is_suspicious_entropy
from analysis.sliding_window import add_query, extract_base_domain
from analysis.typosquatting_detector import check_typosquatting
from analysis.stego_detector import analyze_domain as stego_analyze
from analysis.anomaly_detector import predict_anomaly
from datetime import datetime

def calculate_severity(score):
    if score <= 25:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 75:
        return "HIGH"
    else:
        return "CRITICAL"

def score_domain(domain, timestamp=None):
    if timestamp is None:
        timestamp = datetime.now()

    total_score = 0
    reasons = []

    # --- Entropy Check (max 25 points) ---
    entropy_result = is_suspicious_entropy(domain)
    entropy_contribution = 0
    if entropy_result["is_suspicious"]:
        entropy_contribution = 25
        total_score += entropy_contribution
        reasons.append(f"[ENTROPY] {entropy_result['reason']}")

    # --- Tunneling Check (max 25 points) ---
    tunneling_result = add_query(domain, timestamp)
    tunneling_contribution = 0
    if tunneling_result["is_suspicious"]:
        tunneling_contribution = 25
        total_score += tunneling_contribution
        reasons.append(f"[TUNNELING] {tunneling_result['reason']}")

    # --- Typosquatting Check (max 20 points) ---
    typo_result = check_typosquatting(domain)
    typo_contribution = 0
    if typo_result["is_suspicious"]:
        typo_contribution = 20
        total_score += typo_contribution
        reasons.append(f"[TYPOSQUATTING] {typo_result['reason']}")

    # --- Steganography Check (max 20 points) ---
    stego_result = stego_analyze(domain)
    stego_contribution = 0
    if stego_result["is_suspicious"]:
        stego_contribution = 20
        total_score += stego_contribution
        reasons.append(f"[STEGANOGRAPHY] {stego_result['reason']}")

    # --- ML Anomaly Check (max 10 points) ---
    anomaly_result = predict_anomaly(domain)
    anomaly_contribution = 0
    if anomaly_result and anomaly_result["is_anomaly"]:
        anomaly_contribution = 10
        total_score += anomaly_contribution
        reasons.append(f"[ML ANOMALY] {anomaly_result['reason']}")

    total_score = min(total_score, 100)
    severity = calculate_severity(total_score)

    return {
        "domain": domain,
        "entropy_contribution": entropy_contribution,
        "tunneling_contribution": tunneling_contribution,
        "typo_contribution": typo_contribution,
        "stego_contribution": stego_contribution,
        "anomaly_contribution": anomaly_contribution,
        "final_score": total_score,
        "severity": severity,
        "reasons": reasons,
        "is_threat": total_score > 25
    }

def save_threat_score(result):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO threat_scores
        (domain, entropy_score, tunneling_score, typosquatting_score,
         stego_score, anomaly_score, final_score, severity, reasons)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, (
        result["domain"],
        result["entropy_contribution"],
        result["tunneling_contribution"],
        result["typo_contribution"],
        result["stego_contribution"],
        result["anomaly_contribution"],
        result["final_score"],
        result["severity"],
        "\n".join(result["reasons"])
    ))

    conn.commit()
    cursor.close()
    conn.close()

def analyze_all_records():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain, timestamp FROM dns_records ORDER BY timestamp ASC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    results = []
    for domain, timestamp in rows:
        result = score_domain(domain, timestamp)
        save_threat_score(result)
        results.append(result)

    return results