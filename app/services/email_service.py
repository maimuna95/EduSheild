import os
import aiosmtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
FROM_EMAIL = os.getenv("REPORT_FROM_EMAIL", SMTP_USER)


async def send_scan_email(
        to_email: str,
        scan_results: dict,
        pdf_path: str = None):
    """Send scan results via email with optional PDF attachment."""

    url = scan_results.get("target_url", "Unknown")
    risk_score = scan_results.get("risk_score", 0)
    risk_level = scan_results.get("risk_level", "Unknown")

    subject = f"EduShield Security Report - {url} [{risk_level} Risk]"

    body = f"""Hello,

Your EduShield security scan is complete.

TARGET URL: {url}
RISK SCORE: {risk_score}/100
RISK LEVEL: {risk_level}

SCAN SUMMARY
------------
SSL Certificate: {scan_results.get("ssl", {}).get("message", "N/A")}
Security Headers: {scan_results.get("headers", {}).get("message", "N/A")}
Login Security: {scan_results.get("login", {}).get("message", "N/A")}
Phishing Detection: {scan_results.get("phishing", {}).get("message", "N/A")}
Reconnaissance: {scan_results.get("recon", {}).get("message", "N/A")}

The full PDF report is attached to this email.

This scan complies with the Australian Privacy Act 1988, Cyber Security Act 2024, and ACSC Essential Eight.

Regards,
EduShield Security Team
Tech Adaptive Pandit Pty Ltd
"""

    message = EmailMessage()
    message["From"] = FROM_EMAIL
    message["To"] = to_email
    message["Subject"] = subject
    message.set_content(body)

    # Attach PDF if provided
    if pdf_path and os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            pdf_data = f.read()
        message.add_attachment(
            pdf_data,
            maintype="application",
            subtype="pdf",
            filename=os.path.basename(pdf_path))

    try:
        await aiosmtplib.send(
            message,
            hostname=SMTP_HOST,
            port=SMTP_PORT,
            start_tls=True,
            username=SMTP_USER,
            password=SMTP_PASSWORD,
        )
        return {"status": "sent", "to": to_email,
                "message": f"Email sent successfully to {to_email}"}
    except Exception as e:
        return {"status": "failed", "to": to_email, "message": str(e)}
