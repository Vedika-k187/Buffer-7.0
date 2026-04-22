import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.threat_scorer import analyze_all_records as score_all
from intelligence.alert_generator import save_alert, fetch_all_alerts, fetch_critical_alerts
from intelligence.timeline_builder import build_full_timeline, fetch_timeline_from_db
from intelligence.graph_builder import build_graph, get_graph_stats, export_graph_json

print("=" * 60)
print("PHASE 3 COMPLETE TEST — THREAT UNDERSTANDING ENGINE")
print("=" * 60)

print("\n[1/3] Running Threat Scorer...")
results = score_all()
threats = [r for r in results if r["is_threat"]]
for r in results:
    save_alert(r)
print(f"  Total domains scored  : {len(results)}")
print(f"  Threats identified    : {len(threats)}")
print(f"  Critical              : {sum(1 for r in results if r['severity'] == 'CRITICAL')}")
print(f"  High                  : {sum(1 for r in results if r['severity'] == 'HIGH')}")
print(f"  Medium                : {sum(1 for r in results if r['severity'] == 'MEDIUM')}")

alerts = fetch_all_alerts()
critical_alerts = fetch_critical_alerts()
print(f"  Alerts in DB          : {len(alerts)}")
print(f"  Critical alerts       : {len(critical_alerts)}")

print("\n[2/3] Building Attack Timeline...")
events = build_full_timeline()
db_events = fetch_timeline_from_db()
print(f"  Timeline events built : {len(events)}")
print(f"  Events saved to DB    : {len(db_events)}")

print("\n[3/3] Building Domain Relationship Graph...")
G = build_graph()
stats = get_graph_stats(G)
export_graph_json(G)
print(f"  Graph nodes           : {stats['total_nodes']}")
print(f"  Graph edges           : {stats['total_edges']}")
print(f"  Connected components  : {stats['connected_components']}")

print("\n" + "=" * 60)
print("PHASE 3 COMPLETE")
print("=" * 60)