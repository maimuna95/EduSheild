from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json

from app.services.scanner_service import run_full_scan
from app.services.email_service import send_scan_email
from app.services.pdf_service import generate_pdf_report
from app.database import get_db
from app.models.scan_model import ScanResult

router = APIRouter()


class ScanRequest(BaseModel):
    url: str
    email: str = None


@router.get("/health")
async def health_check():
    return {"status": "EduShield Scanner is ready"}


@router.post("/scan")
async def run_scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    url = request.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    # Run the scan
    results = await run_full_scan(url)

    # Save to database
    scan = ScanResult(
        target_url=results["target_url"],
        risk_score=results["risk_score"],
        risk_level=results["risk_level"],
        ssl_status=results["ssl"]["message"],
        headers_status=results["headers"]["message"],
        login_status=results["login"]["message"],
        phishing_status=results["phishing"]["message"],
        recon_status=results["recon"]["message"],
        raw_results=json.dumps(results),
        email_sent_to=request.email
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    results["db_scan_id"] = scan.id

    # Generate PDF report
    pdf_path = generate_pdf_report(results)
    results["pdf_path"] = pdf_path

    # Send email with PDF attached
    if request.email:
        email_result = await send_scan_email(request.email, results, pdf_path=pdf_path)
        results["email_status"] = email_result
    else:
        results["email_status"] = {
            "status": "skipped",
            "message": "No email provided"}

    return results


@router.get("/scans")
async def get_all_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanResult).order_by(ScanResult.created_at.desc()))
    scans = result.scalars().all()
    return [
        {
            "scan_id": s.id,
            "target_url": s.target_url,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "ssl_status": s.ssl_status,
            "headers_status": s.headers_status,
            "login_status": s.login_status,
            "phishing_status": s.phishing_status,
            "recon_status": s.recon_status,
            "email_sent_to": s.email_sent_to,
            "scanned_at": s.created_at
        }
        for s in scans
    ]
