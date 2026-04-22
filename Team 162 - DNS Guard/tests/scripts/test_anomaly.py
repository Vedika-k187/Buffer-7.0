import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.anomaly_detector import train_model, predict_anomaly, analyze_all_records

print("=" * 50)
print("ML ANOMALY DETECTION TEST")
print("=" * 50)

print("\nTraining model on database records...")
model = train_model()

test_domains = [
    "google.com",
    "mail.google.com",
    "xk29dhs82kla9s.evil.com",
    "a8b2c9d1e4f6g7.net",
    "github.com"
]

print("\nManual predictions:")
for domain in test_domains:
    result = predict_anomaly(domain)
    status = "ANOMALY" if result["is_anomaly"] else "NORMAL"
    print(f"{domain:<40} Score: {result['anomaly_score']:<10} {status}")

print("\nAnalyzing all database records...")
results = analyze_all_records()
anomalies = [r for r in results if r["is_anomaly"]]
print(f"Total analyzed: {len(results)}")
print(f"Anomalies detected: {len(anomalies)}")