import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.report_generator import export_json_report, generate_pdf_report

print("=" * 55)
print("REPORT GENERATOR TEST")
print("=" * 55)

dummy_results = {
    "summary": {
        "total_records": 258,
        "total_threats": 23,
        "critical_count": 4,
        "high_count": 9,
        "medium_count": 10,
        "duration_seconds": 8.34,
        "completed_at": "2024-01-15 10:02:09"
    },
    "steps": {
        "ingestion":     {"source": "simulator", "records": 115},
        "entropy":       {"total": 258, "suspicious": 34},
        "tunneling":     {"detections": 3},
        "typosquatting": {"total": 258, "suspicious": 11},
        "steganography": {"total": 258, "suspicious": 4},
        "anomaly":       {"total": 258, "anomalies": 27},
        "scoring":       {"total": 258, "threats": 23, "critical": 4, "high": 9, "medium": 10}
    }
}

print("\nGenerating JSON report...")
json_path = export_json_report(dummy_results)
print(f"JSON saved to: {json_path}")
print(f"File exists : {os.path.exists(json_path)}")

print("\nGenerating PDF report...")
pdf_path = generate_pdf_report(dummy_results)
print(f"PDF saved to : {pdf_path}")
print(f"File exists  : {os.path.exists(pdf_path)}")
print(f"File size    : {os.path.getsize(pdf_path)} bytes")