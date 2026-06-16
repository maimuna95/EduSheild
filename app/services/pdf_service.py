import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def generate_pdf_report(scan_results: dict) -> str:
    """Generate a branded PDF report. Returns the file path."""

    scan_id = scan_results.get("scan_id", "NA")
    url = scan_results.get("target_url", "Unknown")
    filename = f"EduShield_Report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm)
    styles = getSampleStyleSheet()
    story = []

    # Custom styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=HexColor("#1e3a8a"),
        spaceAfter=12,
        alignment=1)
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=HexColor("#64748b"),
        spaceAfter=20,
        alignment=1)
    heading_style = ParagraphStyle(
        'Heading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=HexColor("#1e3a8a"),
        spaceAfter=8,
        spaceBefore=12)
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=10,
        textColor=HexColor("#1f2937"),
        spaceAfter=6)

    # Header
    story.append(Paragraph("EduShield Security Report", title_style))
    story.append(
        Paragraph(
            "Cybersecurity Monitoring for Australian Educational Institutions",
            subtitle_style))
    story.append(Spacer(1, 0.3 * cm))

    # Summary table
    risk_score = scan_results.get("risk_score", 0)
    risk_level = scan_results.get("risk_level", "Unknown")
    risk_color = (
        HexColor("#10b981") if risk_level == "Low" else
        HexColor("#f59e0b") if risk_level == "Medium" else
        HexColor("#f97316") if risk_level == "High" else
        HexColor("#ef4444")
    )

    summary_data = [
        ["Target URL", url],
        ["Scan ID", str(scan_id)],
        ["Risk Score", f"{risk_score}/100"],
        ["Risk Level", risk_level],
        ["Scanned At", scan_results.get("scanned_at", datetime.utcnow().isoformat())],
    ]
    summary_table = Table(summary_data, colWidths=[5 * cm, 11 * cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), HexColor("#eff6ff")),
        ('TEXTCOLOR', (0, 0), (-1, -1), HexColor("#1f2937")),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ('BACKGROUND', (1, 3), (1, 3), risk_color),
        ('TEXTCOLOR', (1, 3), (1, 3), colors.white),
        ('FONTNAME', (1, 3), (1, 3), 'Helvetica-Bold'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.8 * cm))

    # Scanner modules
    modules = [
        ("Reconnaissance", scan_results.get("recon", {})),
        ("SSL Certificate", scan_results.get("ssl", {})),
        ("Security Headers", scan_results.get("headers", {})),
        ("Login Security", scan_results.get("login", {})),
        ("Phishing Detection", scan_results.get("phishing", {})),
    ]

    story.append(Paragraph("Scanner Module Findings", heading_style))
    for name, data in modules:
        story.append(Paragraph(f"<b>{name}</b>", body_style))
        story.append(
            Paragraph(
                f"Status: {data.get('status', 'N/A')}",
                body_style))
        story.append(
            Paragraph(
                f"Result: {data.get('message', 'N/A')}",
                body_style))
        story.append(Spacer(1, 0.3 * cm))

    # Detailed Findings
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Detailed Findings", heading_style))
    findings = scan_results.get("findings", [])
    if findings:
        for f in findings:
            title = f.get("title", f.get("finding", "Issue"))
            severity = f.get("severity", "Info")
            threat = f.get("threat", "")
            detail = f.get("detail", f.get("description", ""))

            story.append(
                Paragraph(
                    f"<b>{title}</b> (Severity: {severity})",
                    body_style))
            if threat:
                story.append(Paragraph(f"<b>Threat:</b> {threat}", body_style))
            if detail:
                story.append(Paragraph(f"<b>Detail:</b> {detail}", body_style))
            story.append(Spacer(1, 0.2 * cm))
    else:
        story.append(
            Paragraph(
                "No vulnerabilities or issues detected.",
                body_style))

    # Recommendations
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("Recommendations", heading_style))
    recs = scan_results.get("recommendations", [])
    if recs:
        for r in recs:
            rec_text = r.get("recommendation", "")
            vuln = r.get("vulnerability", "")
            if rec_text:
                story.append(
                    Paragraph(
                        f"• <b>Fix for {vuln}:</b> {rec_text}",
                        body_style))
                story.append(Spacer(1, 0.1 * cm))
    else:
        story.append(
            Paragraph(
                "No critical issues found. Maintain current security posture.",
                body_style))

    # Footer - Compliance
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Compliance", heading_style))
    story.append(
        Paragraph(
            "This report complies with the Australian Privacy Act 1988, Cyber Security Act 2024, and ACSC Essential Eight.",
            body_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "Generated by EduShield - Tech Adaptive Pandit Pty Ltd",
            body_style))

    doc.build(story)
    return filepath
