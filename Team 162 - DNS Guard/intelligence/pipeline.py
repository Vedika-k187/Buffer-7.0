from config.logger import get_logger
from config.database import get_connection
from capture.pcap_reader import read_pcap
from capture.queue_processor import process_queue
from analysis.entropy_detector import analyze_all_records as run_entropy
from analysis.sliding_window import analyze_from_database as run_sliding
from analysis.typosquatting_detector import analyze_all_records as run_typo
from analysis.stego_detector import analyze_all_records as run_stego
from analysis.anomaly_detector import train_model, analyze_all_records as run_anomaly
from intelligence.threat_scorer import analyze_all_records as run_scorer
from intelligence.alert_generator import save_alert, fetch_all_alerts
from intelligence.timeline_builder import build_full_timeline
from intelligence.graph_builder import build_graph, export_graph_json
from intelligence.geo_locator import geolocate_all_ips
from datetime import datetime

log = get_logger()

def run_full_pipeline(pcap_path=None, use_simulator=False):
    start_time = datetime.now()

    log.info("=" * 55)
    log.info("DNSGUARD UNIFIED THREAT PIPELINE STARTED")
    log.info("=" * 55)

    pipeline_results = {
        "start_time": str(start_time),
        "steps": {},
        "summary": {}
    }

    # ── STEP 1: DATA INGESTION ──────────────────────────
    log.info("[STEP 1/8] Data Ingestion")

    if pcap_path:
        log.info(f"Reading PCAP: {pcap_path}")
        count = read_pcap(pcap_path)
        process_queue()
        log.info(f"Ingested {count} DNS records from PCAP")
        pipeline_results["steps"]["ingestion"] = {"source": "pcap", "records": count}

    elif use_simulator:
        from intelligence.attack_simulator import run_full_simulation
        log.info("Running attack simulator...")
        count = run_full_simulation()
        log.info(f"Simulated {count} DNS records")
        pipeline_results["steps"]["ingestion"] = {"source": "simulator", "records": count}

    else:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM dns_records")
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        log.info(f"Using existing {count} records in database")
        pipeline_results["steps"]["ingestion"] = {"source": "database", "records": count}

    # ── STEP 2: ENTROPY DETECTION ───────────────────────
    log.info("[STEP 2/8] Entropy Detection")
    entropy_results = run_entropy()
    entropy_suspicious = sum(1 for r in entropy_results if r["is_suspicious"])
    log.info(f"Entropy: {entropy_suspicious}/{len(entropy_results)} suspicious")
    pipeline_results["steps"]["entropy"] = {
        "total": len(entropy_results),
        "suspicious": entropy_suspicious
    }

    # ── STEP 3: TUNNELING DETECTION ─────────────────────
    log.info("[STEP 3/8] DNS Tunneling Detection")
    tunneling_results = run_sliding()
    log.info(f"Tunneling: {len(tunneling_results)} detections")
    pipeline_results["steps"]["tunneling"] = {"detections": len(tunneling_results)}

    # ── STEP 4: TYPOSQUATTING DETECTION ─────────────────
    log.info("[STEP 4/8] Typosquatting Detection")
    typo_results = run_typo()
    typo_suspicious = sum(1 for r in typo_results if r["is_suspicious"])
    log.info(f"Typosquatting: {typo_suspicious}/{len(typo_results)} suspicious")
    pipeline_results["steps"]["typosquatting"] = {
        "total": len(typo_results),
        "suspicious": typo_suspicious
    }

    # ── STEP 5: STEGANOGRAPHY DETECTION ─────────────────
    log.info("[STEP 5/8] Steganography Detection")
    stego_results = run_stego()
    stego_suspicious = sum(1 for r in stego_results if r["is_suspicious"])
    log.info(f"Steganography: {stego_suspicious}/{len(stego_results)} suspicious")
    pipeline_results["steps"]["steganography"] = {
        "total": len(stego_results),
        "suspicious": stego_suspicious
    }

    # ── STEP 6: ML ANOMALY DETECTION ────────────────────
    log.info("[STEP 6/8] ML Anomaly Detection")
    log.info("Training Isolation Forest model...")
    train_model()
    anomaly_results = run_anomaly()
    anomalies = sum(1 for r in anomaly_results if r["is_anomaly"])
    log.info(f"Anomalies: {anomalies}/{len(anomaly_results)} detected")
    pipeline_results["steps"]["anomaly"] = {
        "total": len(anomaly_results),
        "anomalies": anomalies
    }

    # ── STEP 7: THREAT SCORING ───────────────────────────
    log.info("[STEP 7/8] Unified Threat Scoring")
    score_results = run_scorer()
    threats = [r for r in score_results if r["is_threat"]]
    critical = [r for r in score_results if r["severity"] == "CRITICAL"]
    high = [r for r in score_results if r["severity"] == "HIGH"]
    medium = [r for r in score_results if r["severity"] == "MEDIUM"]

    for r in score_results:
        save_alert(r)

    log.warning(f"THREATS FOUND: {len(threats)} — CRITICAL: {len(critical)} HIGH: {len(high)}")
    pipeline_results["steps"]["scoring"] = {
        "total": len(score_results),
        "threats": len(threats),
        "critical": len(critical),
        "high": len(high),
        "medium": len(medium)
    }

    # ── STEP 8: VISUALIZATION DATA ───────────────────────
    log.info("[STEP 8/8] Building Visualization Data")

    timeline_events = build_full_timeline()
    log.info(f"Timeline: {len(timeline_events)} events built")

    G = build_graph()
    export_graph_json(G)
    log.info(f"Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    geo_results = geolocate_all_ips()
    log.info(f"Geolocation: {len(geo_results)} IPs located")

    pipeline_results["steps"]["visualization"] = {
        "timeline_events": len(timeline_events),
        "graph_nodes": G.number_of_nodes(),
        "graph_edges": G.number_of_edges(),
        "ips_geolocated": len(geo_results)
    }

    # ── SUMMARY ──────────────────────────────────────────
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    pipeline_results["summary"] = {
        "total_records": count,
        "total_threats": len(threats),
        "critical_count": len(critical),
        "high_count": len(high),
        "medium_count": len(medium),
        "duration_seconds": round(duration, 2),
        "completed_at": str(end_time)
    }

    log.info("=" * 55)
    log.info(f"PIPELINE COMPLETE in {duration:.2f}s")
    log.info(f"Total Records  : {count}")
    log.info(f"Total Threats  : {len(threats)}")
    log.info(f"Critical       : {len(critical)}")
    log.info(f"High           : {len(high)}")
    log.info(f"Medium         : {len(medium)}")
    log.info("=" * 55)

    return pipeline_results