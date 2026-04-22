import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.entropy_detector import calculate_entropy, is_suspicious_entropy, analyze_all_records

print("=" * 50)
print("ENTROPY DETECTION TEST")
print("=" * 50)

test_domains = [
    "google.com",
    "mail.google.com",
    "a9x2kd8s3j.com",
    "xk29dhs82kla.evil.com",
    "facebook.com",
    "d8s9a2x1m4n6.net"
]

print("\nManual domain tests:")
for domain in test_domains:
    result = is_suspicious_entropy(domain)
    status = "SUSPICIOUS" if result["is_suspicious"] else "CLEAN"
    print(f"{domain:<35} Entropy: {result['entropy_score']:<8} Status: {status}")

print("\nAnalyzing all records in database...")
results = analyze_all_records()
suspicious = [r for r in results if r["is_suspicious"]]
print(f"Total analyzed: {len(results)}")
print(f"Suspicious domains: {len(suspicious)}")