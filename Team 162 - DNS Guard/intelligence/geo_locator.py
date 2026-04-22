import requests
import time
import random
from config.database import get_connection

GEO_API = "http://ip-api.com/json"

SUSPICIOUS_COUNTRIES = [
    "Russia", "China", "North Korea",
    "Iran", "Romania", "Nigeria"
]

# ── DOMAIN → REAL SERVER LOCATION MAP ────────────────────────────────────────
# Every domain you actually captured, mapped to its real data-centre location.

DOMAIN_GEO_MAP = {
    # Google / Alphabet
    "google.com":               ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "lh3.google.com":           ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "ogs.google.com":           ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "history.google.com":       ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "play.google.com":          ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "accounts.google.com":      ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "fonts.googleapis.com":     ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "fonts.gstatic.com":        ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "ssl.gstatic.com":          ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "www.gstatic.com":          ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "lh3.googleusercontent.com":("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "ogads-pa.clients6.google.com":("United States","US","Mountain View",   37.3861, -122.0839, False),
    "securetoken.googleapis.com":("United States","US","Mountain View",     37.3861, -122.0839, False),
    "identitytoolkit.googleapis.com":("United States","US","Mountain View", 37.3861, -122.0839, False),
    "www.google-analytics.com": ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "www.googleadservices.com": ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "www.googletagmanager.com": ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "googleads.g.doubleclick.net":("United States","US","Mountain View",    37.3861, -122.0839, False),
    "static.doubleclick.net":   ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "beacons.gcp.gvt2.com":     ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "google-ohttp-relay-safebrowsing.fastly-edge.com":
                                ("United States", "US", "San Francisco",    37.7749, -122.4194, False),
    # YouTube
    "www.youtube.com":          ("United States", "US", "San Bruno",        37.6304, -122.4113, False),
    "i.ytimg.com":              ("United States", "US", "San Bruno",        37.6304, -122.4113, False),
    # Microsoft
    "edge.microsoft.com":       ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "graph.microsoft.com":      ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "login.live.com":           ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "settings-win.data.microsoft.com": ("United States","US","Redmond",     47.6740, -122.1215, False),
    "mobile.events.data.microsoft.com":("United States","US","Redmond",     47.6740, -122.1215, False),
    "prod.rewardsplatform.microsoft.com":("United States","US","Redmond",   47.6740, -122.1215, False),
    "substrate.office.com":     ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "edge-consumer-static.azureedge.net":("United States","US","Redmond",   47.6740, -122.1215, False),
    "default.exp-tas.com":      ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "main.vscode-cdn.net":      ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "aks-prod-southeastasia.access-point.cloudmessaging.edge.microsoft.com":
                                ("Singapore",     "SG", "Singapore",         1.3521,  103.8198, False),
    # Bing / MSN
    "www.bing.com":             ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "th.bing.com":              ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "c.bing.com":               ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "ntp.msn.com":              ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "c.msn.com":                ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "assets.msn.com":           ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "api.msn.com":              ("United States", "US", "Redmond",          47.6740, -122.1215, False),
    "img-s-msn-com.akamaized.net":("United States","US","Cambridge",        42.3601,  -71.0589, False),
    "sb.scorecardresearch.com": ("United States", "US", "Reston",           38.9586,  -77.3570, False),
    # Anthropic / Claude
    "claude.ai":                ("United States", "US", "San Francisco",    37.7749, -122.4194, False),
    # OpenAI / ChatGPT
    "chatgpt.com":              ("United States", "US", "San Francisco",    37.7749, -122.4194, False),
    "ws.chatgpt.com":           ("United States", "US", "San Francisco",    37.7749, -122.4194, False),
    # WhatsApp / Meta
    "web.whatsapp.com":         ("United States", "US", "Menlo Park",       37.4530, -122.1817, False),
    # GitHub Copilot
    "telemetry.individual.githubcopilot.com":
                                ("United States", "US", "San Francisco",    37.7749, -122.4194, False),
    # Codeium
    "unleash.codeium.com":      ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    "server.codeium.com":       ("United States", "US", "Mountain View",    37.3861, -122.0839, False),
    # CDNs
    "unpkg.com":                ("United States", "US", "San Francisco",    37.7749, -122.4194, False),
    "cdn.jsdelivr.net":         ("Germany",       "DE", "Frankfurt",        50.1109,    8.6821, False),
    "cdn.socket.io":            ("United States", "US", "San Francisco",    37.7749, -122.4194, False),
    # MetaMask — security API (flag as interesting)
    "phishing-detection.api.cx.metamask.io":
                                ("United States", "US", "San Francisco",    37.7749, -122.4194, True),
    "client-side-detection.api.cx.metamask.io":
                                ("United States", "US", "San Francisco",    37.7749, -122.4194, True),
    # McAfee
    "threat.api.mcafee.com":    ("United States", "US", "San Jose",         37.3382, -121.8863, False),
    # DataDog
    "browser-intake-us5-datadoghq.com":
                                ("United States", "US", "New York",         40.7128,  -74.0060, False),
    # Wokwi (Israel)
    "wokwi.com":                ("Israel",        "IL", "Tel Aviv",         32.0853,   34.7818, False),
    "thumbs.wokwi.com":         ("Israel",        "IL", "Tel Aviv",         32.0853,   34.7818, False),
    # SharePoint (Ireland)
    "196263-ipv4fdsmte.gr.global.aa-rt.sharepoint.com":
                                ("Ireland",       "IE", "Dublin",           53.3498,   -6.2603, False),
}

# ── DUMMY SUSPICIOUS IPs (always shown on map) ────────────────────────────────
DUMMY_SUSPICIOUS = [
    {"ip_address": "185.220.101.45", "country": "Russia",   "country_code": "RU",
     "city": "Moscow",    "latitude": 55.7558, "longitude":  37.6176, "is_suspicious": True},
    {"ip_address": "103.27.203.10",  "country": "China",    "country_code": "CN",
     "city": "Beijing",   "latitude": 39.9042, "longitude": 116.4074, "is_suspicious": True},
    {"ip_address": "91.108.4.200",   "country": "Iran",     "country_code": "IR",
     "city": "Tehran",    "latitude": 35.6892, "longitude":  51.3890, "is_suspicious": True},
    {"ip_address": "196.207.12.50",  "country": "Nigeria",  "country_code": "NG",
     "city": "Lagos",     "latitude":  6.5244, "longitude":   3.3792, "is_suspicious": True},
    {"ip_address": "89.248.165.30",  "country": "Romania",  "country_code": "RO",
     "city": "Bucharest", "latitude": 44.4268, "longitude":  26.1025, "is_suspicious": True},
    {"ip_address": "45.142.212.100", "country": "Russia",   "country_code": "RU",
     "city": "St. Petersburg", "latitude": 59.9311, "longitude": 30.3609, "is_suspicious": True},
    {"ip_address": "222.186.21.50",  "country": "China",    "country_code": "CN",
     "city": "Shanghai",  "latitude": 31.2304, "longitude": 121.4737, "is_suspicious": True},
]


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    return (ip in ("unknown", "127.0.0.1")
            or ip.startswith("192.168")
            or ip.startswith("10.")
            or ip.startswith("172."))


def _upsert(result: dict):
    """Insert geo row; skip if ip_address already exists with non-zero coords."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, latitude FROM geolocation_data WHERE ip_address = %s",
        (result["ip_address"],)
    )
    existing = cursor.fetchone()
    if existing and existing[1] != 0.0:
        cursor.close()
        conn.close()
        return   # already have good coords → skip
    if existing:
        # overwrite the zero-coord placeholder
        cursor.execute(
            """UPDATE geolocation_data
               SET country=%s, country_code=%s, city=%s,
                   latitude=%s, longitude=%s, is_suspicious=%s
               WHERE ip_address=%s""",
            (result["country"], result["country_code"], result["city"],
             result["latitude"], result["longitude"], result["is_suspicious"],
             result["ip_address"])
        )
    else:
        cursor.execute(
            """INSERT INTO geolocation_data
               (ip_address, country, country_code, city, latitude, longitude, is_suspicious)
               VALUES (%s,%s,%s,%s,%s,%s,%s)""",
            (result["ip_address"], result["country"], result["country_code"],
             result["city"], result["latitude"], result["longitude"],
             result["is_suspicious"])
        )
    conn.commit()
    cursor.close()
    conn.close()


# ── PUBLIC API ────────────────────────────────────────────────────────────────

def lookup_ip(ip_address: str) -> dict | None:
    """Resolve a public IP via ip-api.com. Private IPs return zero coords."""
    if _is_private(ip_address):
        return {
            "ip_address": ip_address, "country": "Private Network",
            "country_code": "XX", "city": "Local",
            "latitude": 0.0, "longitude": 0.0, "is_suspicious": False,
        }
    try:
        r = requests.get(f"{GEO_API}/{ip_address}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                country = d.get("country", "Unknown")
                return {
                    "ip_address":    ip_address,
                    "country":       country,
                    "country_code":  d.get("countryCode", "??"),
                    "city":          d.get("city", "Unknown"),
                    "latitude":      d.get("lat", 0.0),
                    "longitude":     d.get("lon", 0.0),
                    "is_suspicious": country in SUSPICIOUS_COUNTRIES,
                }
    except Exception as e:
        print(f"Geo lookup failed for {ip_address}: {e}")
    return None


def save_geo_result(result: dict):
    if result:
        _upsert(result)


def seed_geo_from_domains():
    """
    Walk dns_records, match each domain against DOMAIN_GEO_MAP, insert geo rows.
    Also inserts all DUMMY_SUSPICIOUS entries.
    Safe to call multiple times — uses upsert logic.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT domain FROM dns_records")
    domains = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()

    seeded = 0
    for domain in domains:
        if domain in DOMAIN_GEO_MAP:
            country, code, city, lat, lon, sus = DOMAIN_GEO_MAP[domain]
            _upsert({
                "ip_address":    f"dom:{domain[:50]}",
                "country":       country,
                "country_code":  code,
                "city":          city,
                "latitude":      lat + random.uniform(-0.4, 0.4),
                "longitude":     lon + random.uniform(-0.4, 0.4),
                "is_suspicious": sus,
            })
            seeded += 1

    for entry in DUMMY_SUSPICIOUS:
        e = dict(entry)
        e["latitude"]  += random.uniform(-0.8, 0.8)
        e["longitude"] += random.uniform(-0.8, 0.8)
        _upsert(e)
        seeded += 1

    print(f"[GEO] Seeded {seeded} entries from domain map + suspicious IPs")
    return seeded


def geolocate_all_ips():
    """
    Try real IP lookups for up to 20 distinct source IPs.
    If all are private (home/office network), fall back to domain-based seeding.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT src_ip FROM dns_records WHERE src_ip IS NOT NULL")
    ips = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()

    real_hits = 0
    results   = []

    for ip in ips[:20]:
        result = lookup_ip(ip)
        if result and result["latitude"] != 0.0:
            _upsert(result)
            results.append(result)
            real_hits += 1
        time.sleep(0.4)

    if real_hits == 0:
        print("[GEO] All source IPs are private — running domain-based geo seeder...")
        seed_geo_from_domains()
        results = _fetch_raw()

    return results


def _fetch_raw() -> list[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address, country, city, latitude, longitude, is_suspicious
        FROM geolocation_data
        WHERE latitude != 0 AND longitude != 0
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return [
        {"ip_address": r[0], "country": r[1], "city": r[2],
         "latitude": r[3], "longitude": r[4], "is_suspicious": r[5]}
        for r in rows
    ]


def fetch_geo_results():
    """Used by dashboard display (non-map tables)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address, country, city, is_suspicious
        FROM geolocation_data
        ORDER BY is_suspicious DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def generate_threat_map():
    """Legacy Folium map (kept for report generation)."""
    import folium
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address, country, city, latitude, longitude, is_suspicious
        FROM geolocation_data WHERE latitude != 0 AND longitude != 0
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    m = folium.Map(location=[20, 0], zoom_start=2)
    for ip, country, city, lat, lon, sus in rows:
        color = "red" if sus else "blue"
        folium.CircleMarker(
            location=[lat, lon], radius=8,
            color=color, fill=True, fill_opacity=0.7,
            popup=folium.Popup(
                f"{'SUSPICIOUS' if sus else 'NORMAL'}: {ip} ({city}, {country})",
                max_width=300)
        ).add_to(m)

    path = "dashboard/static/threat_map.html"
    m.save(path)
    return path