import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from analysis.sliding_window import add_query, analyze_from_database

print("=" * 50)
print("SLIDING WINDOW DETECTION TEST")
print("=" * 50)

print("\nSimulating DNS tunneling attack...")
print("Sending 80 queries to attacker.com in 60 seconds\n")

base_time = datetime.now()
for i in range(80):
    timestamp = base_time + timedelta(seconds=i * 0.5)
    result = add_query(f"sub{i}.attacker.com", timestamp)

print(f"Base domain: {result['base_domain']}")
print(f"Query count in window: {result['query_count']}")
print(f"Status: {'SUSPICIOUS - TUNNELING DETECTED' if result['is_suspicious'] else 'CLEAN'}")
print(f"Reason: {result['reason']}")

print("\nAnalyzing database records...")
suspicious = analyze_from_database()
print(f"Tunneling detections found: {len(suspicious)}")
for s in suspicious[:3]:
    print(f"  {s['base_domain']} — {s['query_count']} queries")