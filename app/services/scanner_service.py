import asyncio
from datetime import datetime

from app.services.recon_scanner import recon_scan
from app.services.ssl_scanner import ssl_scan
from app.services.headers_scanner import header_analyzer_scan
from app.services.login_scanner import login_scanner_scan
from app.services.phishing_scanner import phishing_detector_scan
from app.services.zap_scanner import zap_scanner_scan


async def run_recon(url: str) -> dict:
    result = await asyncio.to_thread(recon_scan, url)
    return {
        "status": "success",
        "message": f"Found {result.get('info', {}).get('total_findings', 0)} findings.",
        "data": result}


async def run_ssl_check(url: str) -> dict:
    result = await asyncio.to_thread(ssl_scan, url)
    days_left = result.get('info', {}).get('days_until_expiry')
    status = "valid" if (
        days_left is not None and days_left > 0) else "invalid"
    return {
        "status": status,
        "message": f"Found {result.get('info', {}).get('total_findings', 0)} findings.",
        "data": result}


async def run_headers_check(url: str) -> dict:
    result = await asyncio.to_thread(header_analyzer_scan, url)
    return {
        "status": "success",
        "message": f"Found {result.get('info', {}).get('total_findings', 0)} findings.",
        "data": result}


async def run_login_check(url: str) -> dict:
    result = await asyncio.to_thread(login_scanner_scan, url)
    return {
        "status": "success",
        "message": f"Found {result.get('info', {}).get('total_findings', 0)} findings.",
        "data": result}


async def run_phishing_check(url: str) -> dict:
    result = await asyncio.to_thread(phishing_detector_scan, url)
    return {
        "status": "success",
        "message": f"Found {result.get('info', {}).get('total_findings', 0)} findings.",
        "data": result}


async def run_zap_check(url: str) -> dict:
    result = await asyncio.to_thread(zap_scanner_scan, url, False)
    return {
        "status": "success",
        "message": f"Found {result.get('info', {}).get('total_findings', 0)} findings.",
        "data": result}


async def run_full_scan(url: str) -> dict:
    # Keep these - the scanners you want
    recon = await run_recon(url)
    ssl_res = await run_ssl_check(url)
    headers_res = await run_headers_check(url)
    login_res = await run_login_check(url)
    phishing_res = await run_phishing_check(url)
    zap_res = await run_zap_check(url)

    # Initialize score based only on the active scanners
    score = 100.0
    if ssl_res["status"] != "valid":
        score -= 50  # Adjusted weight for partial scan

    # Simple score deduction for headers
    headers_major = headers_res.get(
        "data",
        {}).get(
        "info",
        {}).get(
            "major_threats",
        0)
    if headers_major > 0:
        score -= min(30, headers_major * 10)

    login_major = login_res.get(
        "data",
        {}).get(
        "info",
        {}).get(
            "major_threats",
        0)
    if login_major > 0:
        score -= min(30, login_major * 10)

    phishing_major = phishing_res.get(
        "data",
        {}).get(
        "info",
        {}).get(
            "major_threats",
        0)
    if phishing_major > 0:
        score -= min(30, phishing_major * 10)

    zap_major = zap_res.get("data", {}).get("info", {}).get("major_threats", 0)
    if zap_major > 0:
        score -= min(40, zap_major * 10)

    score = max(0, score)

    risk_score = round(100.0 - score, 1)
    if risk_score >= 80:
        risk_level = "Critical"
    elif risk_score >= 60:
        risk_level = "High"
    elif risk_score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Count findings and severity
    critical = 0
    high = 0
    medium = 0
    low = 0

    recon_findings = recon.get("data", {}).get("findings", [])
    for f in recon_findings:
        f["module"] = "Reconnaissance"

    ssl_findings = ssl_res.get("data", {}).get("findings", [])
    for f in ssl_findings:
        f["module"] = "SSL/TLS Analysis"

    headers_findings = headers_res.get("data", {}).get("findings", [])
    for f in headers_findings:
        f["module"] = "Security Headers"

    login_findings = login_res.get("data", {}).get("findings", [])
    for f in login_findings:
        f["module"] = "Login Security"

    phishing_findings = phishing_res.get("data", {}).get("findings", [])
    for f in phishing_findings:
        f["module"] = "Phishing Detection"

    zap_findings = zap_res.get("data", {}).get("findings", [])
    for f in zap_findings:
        f["module"] = "OWASP ZAP"

    all_findings_raw = recon_findings + ssl_findings + headers_findings + \
        login_findings + phishing_findings + zap_findings

    # Deduplicate findings based on title
    all_findings = []
    seen_titles = set()
    for f in all_findings_raw:
        title = f.get("title", f.get("finding", "Issue"))
        if title not in seen_titles:
            seen_titles.add(title)
            all_findings.append(f)

    for f in all_findings:
        sev = f.get("severity", "").lower()
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        elif sev == "low" or sev == "info":
            low += 1

    # Extract recommendations from findings (already deduplicated by title)
    recommendations = []
    seen_recs = set()
    for f in all_findings:
        if "remediation" in f and f["remediation"]:
            rec_text = f["remediation"]
            if rec_text not in seen_recs:
                seen_recs.add(rec_text)
                recommendations.append({
                    "module": f.get("module", "Unknown"),
                    "vulnerability": f.get("title", "Issue"),
                    "severity": f.get("severity", "Info"),
                    "recommendation": rec_text,
                    "description": f.get("detail", ""),
                    "priority": f.get("severity", "Info"),
                    "compliance": "Essential 8"  # Default placeholder for frontend
                })

    # Format module stats for frontend
    modules = [
        {
            "name": "Reconnaissance",
            "subtitle": "DNS, subdomains, tech stack",
            "icon": "🔎",
            "findings": len(recon_findings)
        },
        {
            "name": "SSL/TLS Analysis",
            "subtitle": "Certificates, protocols, ciphers",
            "icon": "🔒",
            "findings": len(ssl_findings)
        },
        {
            "name": "Security Headers",
            "subtitle": "OWASP security headers",
            "icon": "🛡️",
            "findings": len(headers_findings)
        },
        {
            "name": "Login Security",
            "subtitle": "Auth flaws, brute force",
            "icon": "🔑",
            "findings": len(login_findings)
        },
        {
            "name": "Phishing Detection",
            "subtitle": "SPF, DKIM, DMARC",
            "icon": "🎣",
            "findings": len(phishing_findings)
        },
        {
            "name": "OWASP ZAP",
            "subtitle": "XSS, SQL injection, vulnerabilities",
            "icon": "⚠️",
            "findings": len(zap_findings)
        }
    ]

    # Return only the data from the active scanners
    return {
        "target_url": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        },
        "total_findings": len(all_findings),
        "modules": modules,
        "findings": all_findings,
        "recommendations": recommendations,
        "recon": recon,
        "ssl": ssl_res,
        "headers": headers_res,
        "login": login_res,
        "phishing": phishing_res,
        "zap": zap_res,
        "scanned_at": datetime.utcnow().isoformat()
    }
