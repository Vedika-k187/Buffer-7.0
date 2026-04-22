import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import cm
from config.database import get_connection
from config.logger import get_logger

log = get_logger()

def fetch_report_data():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM dns_records")
    total_queries = cursor.fetchone()[0]

    cursor.execute("""
        SELECT domain, final_score, severity, reasons, analyzed_at
        FROM threat_scores
        WHERE severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
        ORDER BY final_score DESC
        LIMIT 20
    """)
    threats = cursor.fetchall()

    cursor.execute("""
        SELECT domain, event_type, event_description, severity, occurred_at
        FROM attack_timeline
        ORDER BY occurred_at DESC
        LIMIT 15
    """)
    timeline = cursor.fetchall()

    cursor.execute("""
        SELECT relationship_type, COUNT(*)
        FROM domain_relationships
        GROUP BY relationship_type
    """)
    relationships = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
    critical_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
    high_count = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return {
        "total_queries": total_queries,
        "threats": threats,
        "timeline": timeline,
        "relationships": relationships,
        "critical_count": critical_count,
        "high_count": high_count
    }

def export_json_report(pipeline_results, output_path="data/logs/report.json"):
    data = fetch_report_data()
    pipeline_results["database_summary"] = {
        "total_queries": data["total_queries"],
        "critical_alerts": data["critical_count"],
        "high_alerts": data["high_count"]
    }

    with open(output_path, "w") as f:
        json.dump(pipeline_results, f, indent=2, default=str)

    log.info(f"JSON report saved to {output_path}")
    return output_path

def generate_pdf_report(pipeline_results, output_path="data/logs/dnsguard_report.pdf"):
    os.makedirs("data/logs", exist_ok=True)
    data = fetch_report_data()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#1565C0"),
        spaceAfter=6
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0D47A1"),
        spaceBefore=16,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "Normal",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#333333"),
        spaceAfter=4
    )

    story = []

    # ── HEADER ──────────────────────────────────────
    story.append(Paragraph("DNSGuard Threat Intelligence Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        normal_style
    ))
    story.append(HRFlowable(
        width="100%", thickness=1,
        color=colors.HexColor("#1565C0")
    ))
    story.append(Spacer(1, 0.4*cm))

    # ── EXECUTIVE SUMMARY ────────────────────────────
    story.append(Paragraph("Executive Summary", heading_style))

    summary = pipeline_results.get("summary", {})
    summary_data = [
        ["Metric", "Value"],
        ["Total DNS Records Analyzed", str(data["total_queries"])],
        ["Total Threats Identified",   str(summary.get("total_threats", "N/A"))],
        ["Critical Severity",          str(data["critical_count"])],
        ["High Severity",              str(data["high_count"])],
        ["Analysis Duration",          f"{summary.get('duration_seconds', 'N/A')}s"],
        ["Report Generated",           datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
    ]

    summary_table = Table(summary_data, colWidths=[9*cm, 7*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1,  0), colors.HexColor("#1565C0")),
        ("TEXTCOLOR",   (0, 0), (-1,  0), colors.white),
        ("FONTNAME",    (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("BACKGROUND",  (0, 1), (-1, -1), colors.HexColor("#F5F5F5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
            [colors.HexColor("#F5F5F5"), colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4*cm))

    # ── THREAT TABLE ─────────────────────────────────
    story.append(Paragraph("Top Threats Detected", heading_style))

    threat_data = [["Domain", "Score", "Severity"]]
    severity_colors = {
        "CRITICAL": colors.HexColor("#FFEBEE"),
        "HIGH":     colors.HexColor("#FFF3E0"),
        "MEDIUM":   colors.HexColor("#FFFDE7"),
        "LOW":      colors.HexColor("#F1F8E9")
    }

    for row in data["threats"]:
        threat_data.append([
            str(row[0])[:45],
            str(row[1]),
            str(row[2])
        ])

    if len(threat_data) > 1:
        threat_table = Table(
            threat_data,
            colWidths=[10*cm, 2.5*cm, 3.5*cm]
        )
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1,  0), colors.HexColor("#0D47A1")),
            ("TEXTCOLOR",  (0, 0), (-1,  0), colors.white),
            ("FONTNAME",   (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("PADDING",    (0, 0), (-1, -1), 5),
        ]
        for i, row in enumerate(data["threats"], start=1):
            sev = str(row[2])
            bg  = severity_colors.get(sev, colors.white)
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))

        threat_table.setStyle(TableStyle(style_cmds))
        story.append(threat_table)
    else:
        story.append(Paragraph("No threats detected.", normal_style))

    story.append(Spacer(1, 0.4*cm))

    # ── ATTACK TIMELINE ──────────────────────────────
    story.append(Paragraph("Recent Attack Timeline", heading_style))

    timeline_data = [["Time", "Domain", "Event", "Severity"]]
    for row in data["timeline"]:
        timeline_data.append([
            str(row[4])[:19] if row[4] else "N/A",
            str(row[0])[:30],
            str(row[2])[:40],
            str(row[3])
        ])

    if len(timeline_data) > 1:
        tl_table = Table(
            timeline_data,
            colWidths=[3.5*cm, 4.5*cm, 6.5*cm, 2*cm]
        )
        tl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1,  0), colors.HexColor("#1565C0")),
            ("TEXTCOLOR",  (0, 0), (-1,  0), colors.white),
            ("FONTNAME",   (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 7.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                [colors.HexColor("#F5F5F5"), colors.white]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("PADDING",    (0, 0), (-1, -1), 4),
        ]))
        story.append(tl_table)
    else:
        story.append(Paragraph("No timeline events found.", normal_style))

    story.append(Spacer(1, 0.4*cm))

    # ── RELATIONSHIP SUMMARY ─────────────────────────
    story.append(Paragraph("Domain Relationship Summary", heading_style))

    rel_data = [["Relationship Type", "Count"]]
    for row in data["relationships"]:
        rel_data.append([str(row[0]), str(row[1])])

    if len(rel_data) > 1:
        rel_table = Table(rel_data, colWidths=[9*cm, 7*cm])
        rel_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1,  0), colors.HexColor("#1565C0")),
            ("TEXTCOLOR",  (0, 0), (-1,  0), colors.white),
            ("FONTNAME",   (0, 0), (-1,  0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                [colors.HexColor("#F5F5F5"), colors.white]),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("PADDING",    (0, 0), (-1, -1), 6),
        ]))
        story.append(rel_table)

    story.append(Spacer(1, 0.4*cm))

    # ── FOOTER ───────────────────────────────────────
    story.append(HRFlowable(
        width="100%", thickness=1,
        color=colors.HexColor("#CCCCCC")
    ))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "Generated by DNSGuard — Intelligent DNS Threat Intelligence Platform",
        normal_style
    ))

    doc.build(story)
    log.info(f"PDF report saved to {output_path}")
    return output_path