import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.geo_locator import lookup_ip, geolocate_all_ips, fetch_geo_results

print("=" * 55)
print("GEOLOCATION MODULE TEST")
print("=" * 55)

test_ips = [
    "8.8.8.8",
    "1.1.1.1",
    "192.168.1.1"
]

print("\nManual IP lookups:")
for ip in test_ips:
    result = lookup_ip(ip)
    if result:
        status = "SUSPICIOUS" if result["is_suspicious"] else "NORMAL"
        print(f"  {ip:<16} → {result['city']:<15} {result['country']:<15} [{status}]")

print("\nGeolocating all IPs from database...")
results = geolocate_all_ips()
print(f"IPs geolocated: {len(results)}")

print("\nFetching from database:")
saved = fetch_geo_results()
for row in saved[:5]:
    status = "SUSPICIOUS" if row[3] else "NORMAL"
    print(f"  {row[0]:<16} {row[2]:<15} {row[1]:<15} [{status}]")