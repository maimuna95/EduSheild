import socket
import httpx
import json

# =========================
# CONFIG
# =========================
# Replace YOUR_IP later when integration is needed
BACKEND_URL = "http://127.0.0.1:8000/scan-result/"
TIMEOUT = 10

SUBDOMAINS = [
    "www", "mail", "admin", "login", "portal",
    "student", "staff", "moodle", "lms", "library",
    "vpn", "webmail", "api", "dev", "test",
    "staging", "secure", "sso", "idp", "courses",
    "elearning", "admissions", "results", "timetable",
    "helpdesk", "intranet", "dashboard", "cpanel"
]

HIGH_RISK_SUBDOMAINS = [
    "admin",
    "login",
    "vpn",
    "secure",
    "sso",
    "idp",
    "cpanel"]
MEDIUM_RISK_SUBDOMAINS = [
    "dev",
    "test",
    "staging",
    "api",
    "intranet",
    "dashboard",
    "portal"]


# =========================
# HELPERS
# =========================
def dns_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None
    except Exception:
        return None


def clean_domain(domain):
    domain = domain.strip().lower()

    if domain.startswith("http://"):
        domain = domain.replace("http://", "", 1)
    elif domain.startswith("https://"):
        domain = domain.replace("https://", "", 1)

    domain = domain.split("/")[0]
    return domain


def detect_technology(domain):
    urls = [f"https://{domain}", f"http://{domain}"]

    for url in urls:
        try:
            response = httpx.get(url, timeout=5, follow_redirects=True)

            return {
                "server": response.headers.get("Server", "Unknown"),
                "powered_by": response.headers.get("X-Powered-By", "Unknown"),
                "reachable_url": str(response.url),
                "status_code": response.status_code
            }

        except httpx.RequestError:
            continue
        except Exception:
            continue

    return {
        "server": "Unknown",
        "powered_by": "Unknown",
        "reachable_url": None,
        "status_code": None
    }


# =========================
# MAIN SCAN
# =========================
def recon_scan(domain):
    domain = clean_domain(domain)
    findings = []
    discovered_subdomains = []

    for sub in SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        ip = dns_lookup(full_domain)

        if ip:
            discovered_subdomains.append({
                "subdomain": full_domain,
                "ip": ip
            })

            if sub in HIGH_RISK_SUBDOMAINS:
                findings.append({
                    "severity": "high",
                    "level": "major",
                    "title": "Potential Sensitive Subdomain Identified",
                    "threat": "Potential authentication or administrative attack surface",
                    "detail": f"{full_domain} resolves to {ip}",
                    "remediation": "The system found that another public login or admin page is linked to your organization.This could allow hackers to misuse it. Enable extra protection and ensure that it is only accessed by staff. It is better to remove it, if it is no longer required. "
                })

            elif sub in MEDIUM_RISK_SUBDOMAINS:
                findings.append({
                    "severity": "medium",
                    "level": "major",
                    "title": "Potential Internal or Development Subdomain Identified",
                    "threat": "Potential internal service exposure or misconfiguration risk",
                    "detail": f"{full_domain} resolves to {ip}",
                    "remediation": "•	The system found a public testing or internal-looking website linked to your organization. Test systems may have weaker security. Contact your IT team to confirm if it should be public, and restrict access if it is only for internal use."
                })

    tech = detect_technology(domain)

    if tech["server"] != "Unknown" or tech["powered_by"] != "Unknown":
        findings.append({
            "severity": "low",
            "level": "minor",
            "title": "Technology Information Exposed",
            "threat": "Information disclosure",
            "detail": f"Server: {tech['server']}, X-Powered-By: {tech['powered_by']}",
            "remediation": "The system found that your website is showing extra server details. This can help attackers plan targeted attacks. Contact your developer or hosting provider to hide unnecessary software version information."
        })

    result = {
        "module": "Reconnaissance",
        "findings": findings,
        "info": {
            "target": domain,
            "total_findings": len(findings),
            "major_threats": len([f for f in findings if f["level"] == "major"]),
            "minor_threats": len([f for f in findings if f["level"] == "minor"]),
            "total_discovered_subdomains": len(discovered_subdomains),
            "discovered_subdomains": discovered_subdomains,
            "technology": tech
        }
    }

    return result

# =========================
# OPTIONAL: SEND RESULT TO BACKEND
# =========================


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


# =========================
# RUN
# =========================
if __name__ == "__main__":
    target = input("Enter domain (e.g. badssl.com): ").strip()

    if not target:
        print("Error: domain cannot be empty.")
    else:
        result = recon_scan(target)
        print("\nScan Result:")
        print(json.dumps(result, indent=2))
        post_response = send_scan_result(result)
        print("\nPOST Response:")
        print(json.dumps(post_response, indent=2))
