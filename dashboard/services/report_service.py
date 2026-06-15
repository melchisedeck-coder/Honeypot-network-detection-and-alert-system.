import os
from datetime import datetime
from loguru import logger


def generate_pdf_report(title: str, admin_id: int) -> str:
    """Generates a PDF report and returns the saved file path."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from dashboard.database import SessionLocal
    from dashboard.models.attack_log import AttackLog
    from dashboard.models.attacker_profile import AttackerProfile
    from dashboard.models.alert_history import AlertHistory

    os.makedirs("reports", exist_ok=True)
    filename = f"reports/report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc      = SimpleDocTemplate(filename, pagesize=A4)
    styles   = getSampleStyleSheet()
    story    = []

    db = SessionLocal()
    try:
        total_attacks   = db.query(AttackLog).count()
        total_attackers = db.query(AttackerProfile).count()
        total_alerts    = db.query(AlertHistory).count()
        latest          = db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(20).all()

        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
        story.append(Paragraph("KIU Tanzania — Low Interaction Honeypot System", styles["Normal"]))
        story.append(Spacer(1, 0.3 * inch))

        story.append(Paragraph("Summary Statistics", styles["Heading2"]))
        summary_data = [
            ["Metric", "Value"],
            ["Total Attacks Logged",    str(total_attacks)],
            ["Unique Attacker IPs",     str(total_attackers)],
            ["Total Alerts Triggered",  str(total_alerts)],
            ["Report Generated At",     datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
        ]
        t = Table(summary_data, colWidths=[3 * inch, 3 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.3 * inch))

        story.append(Paragraph("Recent Attack Events (Last 20)", styles["Heading2"]))
        rows = [["Timestamp", "IP Address", "Attack Type", "Severity", "Service"]]
        for log in latest:
            rows.append([
                log.timestamp.strftime("%Y-%m-%d %H:%M") if log.timestamp else "N/A",
                log.attacker_ip or "Unknown",
                log.attack_type or "Unknown",
                log.severity or "Low",
                log.target_service or "Web",
            ])
        at = Table(rows, colWidths=[1.4*inch, 1.4*inch, 1.6*inch, 0.9*inch, 0.9*inch])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("GRID",       (0, 0), (-1, -1), 0.3, colors.grey),
        ]))
        story.append(at)
        doc.build(story)
        logger.info(f"[REPORT] Generated: {filename}")
        return filename
    except Exception as e:
        logger.error(f"[REPORT] Failed: {e}")
        return ""
    finally:
        db.close()
