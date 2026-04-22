from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from config.database import get_connection
import json
import os
from flask import send_file
from intelligence.report_generator import export_json_report, generate_pdf_report
from intelligence.pipeline import run_full_pipeline

app = Flask(__name__)
app.config["SECRET_KEY"] = "dnsguard_secret_2024"
socketio = SocketIO(app, cors_allowed_origins="*")

# ─────────────────────────────────────────
# HELPER — fetch dashboard summary stats
# ─────────────────────────────────────────
def get_summary_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM dns_records")
    total_queries = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM threat_scores WHERE final_score > 25")
    suspicious_domains = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
    high_alerts = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return {
        "total_queries": total_queries,
        "suspicious_domains": suspicious_domains,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts
    }

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.route("/")
def index():
    stats = get_summary_stats()
    return render_template("index.html", stats=stats)

@app.route("/api/stats")
def api_stats():
    return jsonify(get_summary_stats())

@app.route("/api/live-feed")
def api_live_feed():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, src_ip, timestamp, query_type
        FROM dns_records
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    data = [
        {
            "domain": r[0],
            "src_ip": r[1],
            "timestamp": str(r[2]),
            "query_type": r[3]
        }
        for r in rows
    ]
    return jsonify(data)

@app.route("/api/threat-scores")
def api_threat_scores():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, final_score, severity, reasons, analyzed_at
        FROM threat_scores
        WHERE final_score > 0
        ORDER BY final_score DESC
        LIMIT 50
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    data = [
        {
            "domain": r[0],
            "score": r[1],
            "severity": r[2],
            "reasons": r[3],
            "analyzed_at": str(r[4])
        }
        for r in rows
    ]
    return jsonify(data)

@app.route("/api/timeline")
def api_timeline():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, event_type, event_description, severity, occurred_at
        FROM attack_timeline
        ORDER BY occurred_at DESC
        LIMIT 50
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    data = [
        {
            "domain": r[0],
            "event_type": r[1],
            "description": r[2],
            "severity": r[3],
            "occurred_at": str(r[4])
        }
        for r in rows
    ]
    return jsonify(data)

@app.route("/api/graph")
def api_graph():
    graph_path = "data/graph_data.json"
    if os.path.exists(graph_path):
        with open(graph_path, "r") as f:
            return jsonify(json.load(f))
    return jsonify({"nodes": [], "edges": []})

@app.route("/api/alerts")
def api_alerts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, severity, threat_score, reasons, created_at
        FROM alerts
        ORDER BY threat_score DESC
        LIMIT 30
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    data = [
        {
            "domain": r[0],
            "severity": r[1],
            "score": r[2],
            "reasons": r[3],
            "created_at": str(r[4])
        }
        for r in rows
    ]
    return jsonify(data)

# ── DROP THIS INTO dashboard/app.py ──────────────────────────────────────────
# Replace your existing  @app.route("/api/geo")  block with this:

@app.route("/api/geo")
def api_geo():
    from intelligence.geo_locator import seed_geo_from_domains
    conn = get_connection()
    cursor = conn.cursor()

    # Check if we have any usable geo rows
    cursor.execute(
        "SELECT COUNT(*) FROM geolocation_data WHERE latitude != 0 AND longitude != 0"
    )
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()

    # Nothing in DB yet → seed immediately so the map shows dots right away
    if count == 0:
        seed_geo_from_domains()

    # Now fetch
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address, country, city, latitude, longitude, is_suspicious
        FROM geolocation_data
        WHERE latitude != 0 AND longitude != 0
        ORDER BY is_suspicious DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    data = [
        {
            "ip":        r[0],
            "country":   r[1],
            "city":      r[2],
            "lat":       r[3],
            "lon":       r[4],
            "suspicious": r[5],
        }
        for r in rows
    ]
    return jsonify(data)

@app.route("/api/virustotal")
def api_virustotal():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, malicious_count, total_engines, threat_category, checked_at
        FROM virustotal_results
        ORDER BY malicious_count DESC
    """)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    data = [
        {
            "domain": r[0],
            "malicious": r[1],
            "total": r[2],
            "category": r[3],
            "checked_at": str(r[4])
        }
        for r in rows
    ]
    return jsonify(data)
@app.route("/api/report/json")
def download_json_report():
    results = {"summary": {}, "steps": {}}
    path = export_json_report(results)
    return send_file(path, as_attachment=True, download_name="dnsguard_report.json")

@app.route("/api/report/pdf")
def download_pdf_report():
    results = {"summary": {}, "steps": {}}
    path = generate_pdf_report(results)
    return send_file(path, as_attachment=True, download_name="dnsguard_report.pdf")

@app.route("/api/run-pipeline")
def run_pipeline_route():
    results = run_full_pipeline(use_simulator=False)
    return jsonify(results)

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5000)