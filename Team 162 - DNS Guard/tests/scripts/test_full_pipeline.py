import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.attack_simulator import run_full_simulation
from analysis.entropy_detector import analyze_all_records as entropy_run
from analysis.sliding_window import analyze_from_database as sliding_run
from analysis.typosquatting_detector import analyze_all_records as typo_run
from analysis.stego_detector import analyze_all_records as stego_run
from analysis.anomaly_detector import train_model, analyze_all_records as anomaly_run
from intelligence.threat_scorer import analyze_all_records as score_run
from intelligence.alert_generator import save_alert, fetch_all_alerts
from intelligence.timeline_builder import build_full_timeline
from intelligence.graph_builder import build_graph, export_graph_json
from intelligence.geo_locator import geolocate_all_ips

print("=" * 60)
print("FULL END TO END PIPELINE TEST")
print("=" * 60)

print("\n[1] Running attack simulation...")
total = run_full_simulation()
print(f"    Injected: {total} records")

print("\n[2] Running all analysis modules...")
entropy_run()
sliding_run()
typo_run()
stego_run()
train_model()
anomaly_run()
print("    All detection modules complete")

print("\n[3] Running threat scoring...")
results = score_run()
for r in results:
    save_alert(r)
alerts = fetch_all_alerts()
print(f"    Threats scored: {len(results)}")
print(f"    Alerts saved  : {len(alerts)}")

print("\n[4] Building attack timeline...")
events = build_full_timeline()
print(f"    Timeline events: {len(events)}")

print("\n[5] Building domain graph...")
G = build_graph()
export_graph_json(G)
print(f"    Graph nodes: {G.number_of_nodes()}")
print(f"    Graph edges: {G.number_of_edges()}")

print("\n[6] Geolocating IPs...")
geo = geolocate_all_ips()
print(f"    IPs located: {len(geo)}")

print("\n" + "=" * 60)
print("FULL PIPELINE COMPLETE — START DASHBOARD WITH:")
print("python dashboard/app.py")
print("Then open: http://127.0.0.1:5000")
print("=" * 60)