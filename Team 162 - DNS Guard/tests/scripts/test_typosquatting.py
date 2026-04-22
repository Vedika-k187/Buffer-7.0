import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.typosquatting_detector import check_typosquatting, analyze_all_records

print("=" * 50)
print("TYPOSQUATTING DETECTION TEST")
print("=" * 50)

test_domains = [
    "google.com", "g00gle.com", "gooogle.com",
    "faceb00k.com", "amaz0n.com", "paypa1.com",
    "micros0ft.com", "randomdomain.com"
]

print("\nManual tests:")
for domain in test_domains:
    result = check_typosquatting(domain)
    status = "SUSPICIOUS" if result["is_suspicious"] else "CLEAN"
    print(f"{domain:<25} → {status:<12} {result['reason']}")

print("\nAnalyzing database records...")
results = analyze_all_records()
suspicious = [r for r in results if r["is_suspicious"]]
print(f"Total analyzed: {len(results)}")
print(f"Typosquatting detected: {len(suspicious)}")