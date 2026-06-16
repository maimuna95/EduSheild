import time
import json
import warnings
import httpx
from urllib.parse import urlparse
from zapv2 import ZAPv2

warnings.filterwarnings("ignore")

# Backend API where scan result can be sent later
BACKEND_URL = "http://127.0.0.1:8000/scan-result/"
TIMEOUT = 10

# Make sure OWASP ZAP is running on this same port
ZAP_PROXY = "http://127.0.0.1:8090"

# If ZAP API key is enabled, put it here as a string
ZAP_API_KEY = None

SCAN_TIMEOUT_SECONDS = 12000

ALLOWED_TEST_TARGETS = [
    "testphp.vulnweb.com",
    "public-firing-range.appspot.com",
    "demo.testfire.net",
    "localhost",
    "127.0.0.1",
    "juice-shop",
    "webgoat",
    "dvwa"
]


def clean_target(target):
    target = target.strip()

    if not target:
        return ""

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    return target.rstrip("/")


def get_hostname(target):
    try:
        parsed = urlparse(target)
        return parsed.hostname or ""
    except Exception:
        return ""


def is_allowed_test_target(target):
    hostname = get_hostname(target).lower()

    if not hostname:
        return False

    return any(
        hostname == allowed or allowed in hostname
        for allowed in ALLOWED_TEST_TARGETS
    )


def severity_to_level(severity):
    severity = severity.lower()

    if severity in ["high", "medium"]:
        return "Major"

    return "Minor"


def zap_risk_to_severity(risk):
    risk = risk.lower()

    if risk == "high":
        return "High"

    if risk == "medium":
        return "Medium"

    if risk == "low":
        return "Low"

    return "Informational"


def check_zap_connection(zap):
    try:
        version = zap.core.version
        return True, version
    except Exception as e:
        return False, str(e)


def open_target_through_zap(zap, target):
    try:
        zap.urlopen(target)
        time.sleep(3)
        return True
    except Exception as e:
        print(f"Could not open target through ZAP: {e}")
        return False


def spider_scan(zap, target):
    try:
        scan_id = zap.spider.scan(target)
        print(f"Spider scan ID: {scan_id}")

        if not scan_id or not str(scan_id).isdigit():
            print(f"Spider scan did not start properly. Scan ID: {scan_id}")
            return False

        start_time = time.time()

        while True:
            status = zap.spider.status(scan_id)
            print(f"Raw spider status: {status}")

            if not str(status).isdigit():
                print(f"Spider status invalid: {status}")
                return False

            progress = int(status)
            print(f"Spider progress: {progress}%")

            if progress >= 100:
                print("Spider scan completed.")
                return True

            if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
                print("Spider scan timed out.")
                return False

            time.sleep(2)

    except Exception as e:
        print(f"Spider scan failed: {e}")
        return False


def passive_scan_wait(zap):
    try:
        start_time = time.time()

        while True:
            remaining = int(zap.pscan.records_to_scan)
            print(f"Passive scan records remaining: {remaining}")

            if remaining <= 0:
                print("Passive scan completed.")
                return True

            if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
                print("Passive scan wait timed out.")
                return False

            time.sleep(2)

    except Exception as e:
        print(f"Passive scan wait failed: {e}")
        return False


def active_scan(zap, target):
    try:
        scan_id = zap.ascan.scan(target)
        print(f"Active scan ID: {scan_id}")

        if not scan_id or not str(scan_id).isdigit():
            print(f"Active scan did not start properly. Scan ID: {scan_id}")
            return False

        start_time = time.time()

        while True:
            status = zap.ascan.status(scan_id)
            print(f"Raw active scan status: {status}")

            if not str(status).isdigit():
                print(f"Active scan status invalid: {status}")
                return False

            progress = int(status)
            print(f"Active scan progress: {progress}%")

            if progress >= 100:
                print("Active scan completed.")
                return True

            if time.time() - start_time > SCAN_TIMEOUT_SECONDS:
                print("Active scan timed out.")
                return False

            time.sleep(5)

    except Exception as e:
        print(f"Active scan failed: {e}")
        return False


def convert_zap_alerts_to_findings(alerts):
    findings = []

    for alert in alerts:
        risk = alert.get("risk", "Informational")
        severity = zap_risk_to_severity(risk)

        if severity == "Informational":
            continue

        title = alert.get("alert", "ZAP Security Alert")
        detail = alert.get("description", "No description provided.")
        url = alert.get("url", "Unknown URL")
        solution = alert.get(
            "solution",
            "Review the issue and apply secure configuration.")
        evidence = alert.get("evidence", "")

        finding = {
            "severity": severity,
            "level": severity_to_level(severity),
            "title": title,
            "threat": f"OWASP ZAP identified a {risk} risk issue.",
            "detail": f"{detail} URL: {url}. Evidence: {evidence}",
            "remediation": solution
        }

        findings.append(finding)

    return findings


def zap_scanner_scan(target, run_active_scan=False):
    target = clean_target(target)
    findings = []

    if not target:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Invalid Target",
            "threat": "ZAP scanner cannot run without a valid target.",
            "detail": "The provided target was empty or invalid.",
            "remediation": "Enter a valid test target URL."
        })

        return build_result(target, findings, False, None, run_active_scan, 0)

    if not is_allowed_test_target(target):
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Unauthorised Target Blocked",
            "threat": "Active web vulnerability scanning without permission may be illegal or unethical.",
            "detail": f"The target {target} is not in the approved test target list.",
            "remediation": "Use only approved vulnerable websites or targets where written permission has been granted."
        })

        return build_result(target, findings, False, None, run_active_scan, 0)

    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": ZAP_PROXY,
            "https": ZAP_PROXY
        }
    )

    connected, version_or_error = check_zap_connection(zap)

    if not connected:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "OWASP ZAP Not Connected",
            "threat": "The scanner could not connect to the local OWASP ZAP proxy.",
            "detail": f"ZAP connection failed: {version_or_error}",
            "remediation": "Start OWASP ZAP on 127.0.0.1:8080 and make sure the API is enabled."
        })

        return build_result(target, findings, False, None, run_active_scan, 0)

    print(f"Connected to OWASP ZAP version: {version_or_error}")
    print(f"Target: {target}")

    print("\nOpening target through ZAP...")
    open_target_through_zap(zap, target)

    print("\nStarting spider scan...")
    spider_ok = spider_scan(zap, target)

    if not spider_ok:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Spider Scan Failed",
            "threat": "ZAP could not crawl the target, so vulnerability scanning may not be reliable.",
            "detail": "The spider scan did not complete successfully.",
            "remediation": "Check that the target URL is reachable, use the correct HTTP/HTTPS protocol, confirm ZAP proxy settings, and try again."
        })

    print("\nWaiting for passive scan...")
    passive_scan_wait(zap)

    active_ok = False

    if run_active_scan:
        if spider_ok:
            print("\nStarting active scan...")
            active_ok = active_scan(zap, target)

            if not active_ok:
                findings.append({
                    "severity": "High",
                    "level": "Major",
                    "title": "Active Scan Failed",
                    "threat": "OWASP ZAP could not complete active vulnerability scanning.",
                    "detail": "The active scan returned an invalid scan ID, invalid status, timeout, or execution error.",
                    "remediation": "Restart OWASP ZAP, confirm the target is reachable, check API/proxy settings, and make sure the spider scan completes before active scanning."
                })

            print("\nWaiting for passive scan after active scan...")
            passive_scan_wait(zap)
        else:
            print("Skipping active scan because spider scan failed.")
            findings.append({
                "severity": "High",
                "level": "Major",
                "title": "Active Scan Skipped",
                "threat": "Active scanning was skipped because the spider scan failed.",
                "detail": "Running active scan without successful crawling may produce unreliable results.",
                "remediation": "Fix spider scan issues first, then run active scan again."
            })

    try:
        alerts = zap.core.alerts(baseurl=target)
    except Exception as e:
        print(f"Could not collect ZAP alerts: {e}")
        alerts = []

    findings.extend(convert_zap_alerts_to_findings(alerts))

    return build_result(
        target=target,
        findings=findings,
        zap_connected=True,
        zap_version=version_or_error,
        active_scan_used=run_active_scan,
        alerts_collected=len(alerts)
    )


def build_result(
        target,
        findings,
        zap_connected,
        zap_version,
        active_scan_used,
        alerts_collected):
    return {
        "module": "zap_scanner",
        "findings": findings,
        "info": {
            "target": target,
            "zap_connected": zap_connected,
            "zap_version": zap_version,
            "active_scan_used": active_scan_used,
            "total_findings": len(findings),
            "major_threats": len([f for f in findings if f["level"] == "Major"]),
            "minor_threats": len([f for f in findings if f["level"] == "Minor"]),
            "alerts_collected": alerts_collected
        }
    }


def send_scan_result(scan_result):
    try:
        response = httpx.post(
            BACKEND_URL,
            json=scan_result,
            timeout=TIMEOUT
        )

        return {
            "success": response.status_code in [200, 201],
            "status_code": response.status_code,
            "response_text": response.text
        }

    except httpx.RequestError as e:
        return {
            "success": False,
            "status_code": None,
            "response_text": f"Request failed: {str(e)}"
        }

    except Exception as e:
        return {
            "success": False,
            "status_code": None,
            "response_text": f"Unexpected error: {str(e)}"
        }


if __name__ == "__main__":
    target = input("Enter approved test target URL: ").strip()

    active_choice = input(
        "Run active scan? Type yes only for legal lab targets: ").strip().lower()
    run_active = active_choice == "yes"

    result = zap_scanner_scan(target, run_active_scan=run_active)

    print("\nScan Result:")
    print(json.dumps(result, indent=2))

    # Backend integration later
    # post_response = send_scan_result(result)
    # print("\nPOST Response:")
    # print(json.dumps(post_response, indent=2))
