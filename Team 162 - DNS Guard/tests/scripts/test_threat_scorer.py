import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.threat_scorer import score_domain, analyze_all_records
from intelligence.alert_generator import format_alert, save_alert, fetch_all_alerts

print("=" * 55)
print("THREAT SCORING & ALERT GENERATION TEST")
print("=" * 55)

test_domains = [
    "google.com",
    "g00gle.com",
    "xk29dhs82kla.evil.com",
    "mail.facebook.com",
    "a9x2kd83ls92.attacker.com"
]

print("\nManual domain scoring:\n")
for domain in test_domains:
    result = score_domain(domain)
    print(f"Domain  : {domain}")
    print(f"Score   : {result['final_score']}/100")
    print(f"Severity: {result['severity']}")
    print(f"Reasons : {len(result['reasons'])} detections")
    print()

print("\nFull alert example for suspicious domain:\n")
suspicious = score_domain("a9x2kd83ls92.attacker.com")
print(format_alert(suspicious))

print("\nAnalyzing all database records...")
results = analyze_all_records()

threats = [r for r in results if r["is_threat"]]
critical = [r for r in results if r["severity"] == "CRITICAL"]
high = [r for r in results if r["severity"] == "HIGH"]

print(f"\nTotal analyzed : {len(results)}")
print(f"Threats found  : {len(threats)}")
print(f"Critical       : {len(critical)}")
print(f"High           : {len(high)}")

for r in results:
    save_alert(r)

print("\nSaved alerts to database.")
alerts = fetch_all_alerts()
print(f"Total alerts in DB: {len(alerts)}")