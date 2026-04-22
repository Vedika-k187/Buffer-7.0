import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.stego_detector import analyze_domain, analyze_all_records
import base64

print("=" * 50)
print("STEGANOGRAPHY DETECTION TEST")
print("=" * 50)

def make_stego_domain(message, base):
    encoded = base64.b64encode(message.encode()).decode().rstrip("=")
    return f"{encoded}.{base}"

test_domains = [
    make_stego_domain("hello", "attacker.com"),
    make_stego_domain("secret_data", "evil.net"),
    make_stego_domain("exfiltrated", "c2server.com"),
    "mail.google.com",
    "normal.domain.com"
]

print("\nManual tests:")
for domain in test_domains:
    result = analyze_domain(domain)
    status = "SUSPICIOUS" if result["is_suspicious"] else "CLEAN"
    msg = f"→ '{result['decoded_message']}'" if result["decoded_message"] else ""
    print(f"{domain[:45]:<45} {status} {msg}")

print("\nAnalyzing database records...")
results = analyze_all_records()
suspicious = [r for r in results if r["is_suspicious"]]
print(f"Total analyzed: {len(results)}")
print(f"Steganography detected: {len(suspicious)}")