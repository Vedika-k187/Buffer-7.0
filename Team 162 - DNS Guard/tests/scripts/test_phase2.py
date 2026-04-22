import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.entropy_detector import analyze_all_records as entropy_analyze
from analysis.sliding_window import analyze_from_database as sliding_analyze
from analysis.typosquatting_detector import analyze_all_records as typo_analyze
from analysis.stego_detector import analyze_all_records as stego_analyze
from analysis.anomaly_detector import train_model, analyze_all_records as anomaly_analyze

print("=" * 60)
print("PHASE 2 COMPLETE TEST — ALL DETECTION MODULES")
print("=" * 60)

print("\n[1/5] Running Entropy Detection...")
r1 = entropy_analyze()
print(f"Suspicious: {sum(1 for r in r1 if r['is_suspicious'])}/{len(r1)}")

print("\n[2/5] Running Sliding Window Detection...")
r2 = sliding_analyze()
print(f"Tunneling detected: {len(r2)}")

print("\n[3/5] Running Typosquatting Detection...")
r3 = typo_analyze()
print(f"Suspicious: {sum(1 for r in r3 if r['is_suspicious'])}/{len(r3)}")

print("\n[4/5] Running Steganography Detection...")
r4 = stego_analyze()
print(f"Suspicious: {sum(1 for r in r4 if r['is_suspicious'])}/{len(r4)}")

print("\n[5/5] Running ML Anomaly Detection...")
train_model()
r5 = anomaly_analyze()
print(f"Anomalies: {sum(1 for r in r5 if r['is_anomaly'])}/{len(r5)}")

print("\n" + "=" * 60)
print("PHASE 2 COMPLETE")
print("=" * 60)