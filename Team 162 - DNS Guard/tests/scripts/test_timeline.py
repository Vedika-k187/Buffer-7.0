import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.timeline_builder import (
    build_timeline_for_domain,
    print_timeline,
    build_full_timeline,
    fetch_timeline_from_db
)
from config.database import get_connection

print("=" * 55)
print("ATTACK TIMELINE RECONSTRUCTION TEST")
print("=" * 55)

# Get first domain from DB to test with
conn = get_connection()
cursor = conn.cursor()
cursor.execute("SELECT DISTINCT domain FROM dns_records LIMIT 3")
domains = [row[0] for row in cursor.fetchall()]
cursor.close()
conn.close()

print(f"\nBuilding timelines for {len(domains)} domains...\n")

for domain in domains:
    events = build_timeline_for_domain(domain)
    print_timeline(domain, events)

print("\nBuilding full timeline for all records...")
all_events = build_full_timeline()
print(f"Total timeline events generated: {len(all_events)}")

print("\nFetching from database...")
db_events = fetch_timeline_from_db()
print(f"Events saved to DB: {len(db_events)}")

print("\nMost recent 5 events:")
for row in db_events[-5:]:
    print(f"  {row[4].strftime('%H:%M:%S')}  [{row[3]:<8}]  {row[0]}  —  {row[2][:50]}")