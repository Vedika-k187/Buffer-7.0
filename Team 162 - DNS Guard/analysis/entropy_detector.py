import math
from collections import Counter
from config.settings import ENTROPY_THRESHOLD
from config.database import get_connection

def calculate_entropy(domain):
    # Remove TLD for cleaner analysis
    # google.com → google
    name = domain.replace(".", "")
    
    if len(name) == 0:
        return 0.0

    freq = Counter(name)
    length = len(name)

    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )

    return round(entropy, 4)

def is_suspicious_entropy(domain):
    score = calculate_entropy(domain)
    suspicious = score > ENTROPY_THRESHOLD
    return {
        "domain": domain,
        "entropy_score": score,
        "is_suspicious": suspicious,
        "reason": f"Entropy {score} exceeds threshold {ENTROPY_THRESHOLD}" if suspicious else "Normal entropy"
    }

def save_entropy_result(result):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO entropy_results (domain, entropy_score, is_suspicious)
        VALUES (%s, %s, %s)
    """

    cursor.execute(query, (
        result["domain"],
        result["entropy_score"],
        result["is_suspicious"]
    ))

    conn.commit()
    cursor.close()
    conn.close()

def analyze_all_records():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM dns_records")
    domains = cursor.fetchall()
    cursor.close()
    conn.close()

    results = []
    for (domain,) in domains:
        result = is_suspicious_entropy(domain)
        save_entropy_result(result)
        results.append(result)

    return results