import re
import base64
from config.database import get_connection
from collections import defaultdict

BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/=]{16,}$')

def extract_subdomain(domain):
    parts = domain.split(".")
    if len(parts) > 2:
        return parts[0]
    return None

def is_base64_encoded(text):
    return bool(BASE64_PATTERN.match(text))

def decode_base64(text):
    try:
        # Add padding if needed
        padding = 4 - len(text) % 4
        if padding != 4:
            text += "=" * padding
        decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        return None

def analyze_domain(domain):
    subdomain = extract_subdomain(domain)

    if not subdomain:
        return {
            "domain": domain,
            "decoded_message": None,
            "is_suspicious": False,
            "reason": "No subdomain found"
        }

    if not is_base64_encoded(subdomain):
        return {
            "domain": domain,
            "decoded_message": None,
            "is_suspicious": False,
            "reason": "Subdomain not Base64 encoded"
        }

    decoded = decode_base64(subdomain)
    is_suspicious = decoded is not None and len(decoded) > 0

    return {
        "domain": domain,
        "decoded_message": decoded,
        "is_suspicious": is_suspicious,
        "reason": f"Hidden message found: '{decoded}'" if is_suspicious else "Decode failed"
    }

def reconstruct_message(base_domain):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT domain, timestamp FROM dns_records WHERE domain LIKE %s ORDER BY timestamp ASC",
        (f"%.{base_domain}",)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    message_parts = []
    for domain, _ in rows:
        result = analyze_domain(domain)
        if result["decoded_message"]:
            message_parts.append(result["decoded_message"])

    return "".join(message_parts)

def save_stego_result(result):
    if not result["is_suspicious"]:
        return

    conn = get_connection()
    cursor = conn.cursor()
    query = """
        INSERT INTO stego_results (domain, decoded_message, is_suspicious)
        VALUES (%s, %s, %s)
    """
    cursor.execute(query, (
        result["domain"],
        result["decoded_message"],
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
        result = analyze_domain(domain)
        save_stego_result(result)
        results.append(result)

    return results