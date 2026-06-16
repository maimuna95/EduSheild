import dns.resolver
import json
import httpx
import warnings

warnings.filterwarnings("ignore")

BACKEND_URL = "http://127.0.0.1:8000/scan-result/"
TIMEOUT = 5

DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "mail",
    "smtp",
    "dkim",
    "s1",
    "s2"
]


def clean_domain(target):
    target = target.strip()

    if target.startswith("http://"):
        target = target.replace("http://", "")

    if target.startswith("https://"):
        target = target.replace("https://", "")

    target = target.split("/")[0]
    target = target.split(":")[0]

    return target.lower().strip()


def severity_to_level(severity):
    if severity in ["Critical", "High", "Medium"]:
        return "Major"
    return "Minor"


def query_dns_record(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=TIMEOUT)
        return [str(answer).strip('"') for answer in answers]

    except dns.resolver.NoAnswer:
        return []

    except dns.resolver.NXDOMAIN:
        return []

    except dns.resolver.Timeout:
        return []

    except Exception:
        return []


def check_mx_records(domain):
    return query_dns_record(domain, "MX")


def check_spf_record(domain):
    txt_records = query_dns_record(domain, "TXT")

    spf_records = [
        record for record in txt_records
        if record.lower().startswith("v=spf1")
    ]

    return spf_records


def check_dmarc_record(domain):
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = query_dns_record(dmarc_domain, "TXT")

    dmarc_records = [
        record for record in txt_records
        if record.lower().startswith("v=dmarc1")
    ]

    return dmarc_records


def check_dkim_records(domain):
    found_dkim_records = {}

    for selector in DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = query_dns_record(dkim_domain, "TXT")

        dkim_records = [record for record in txt_records if "v=dkim1" in record.lower(
        ) or "k=rsa" in record.lower() or "p=" in record.lower()]

        if dkim_records:
            found_dkim_records[selector] = dkim_records

    return found_dkim_records


def analyze_spf(spf_records):
    findings = []

    if not spf_records:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Missing SPF Record",
            "threat": "Attackers may spoof emails from this domain more easily",
            "detail": "No SPF record was found for the domain.",
            "remediation": "Your domain does not mention that which mail servers are allowed to send email on its behalf. That makes email impersonation easier.  Contact your email administrator to add an SPF record.”"
        })
        return findings

    for spf in spf_records:
        spf_lower = spf.lower()

        if "+all" in spf_lower:
            findings.append({
                "severity": "High",
                "level": "Major",
                "title": "Weak SPF Policy Allows All Senders",
                "threat": "The SPF policy allows any server to send email for this domain",
                "detail": f"SPF record contains '+all': {spf}",
                "remediation": "The website email security rule is not strict enough to block unauthorized senders. After confirming the authorised mail servers, replace +all with -all or ~all to prevent fake or suspicious emails"
            })

        elif "?all" in spf_lower:
            findings.append({
                "severity": "Medium",
                "level": "Major",
                "title": "Neutral SPF Policy Detected",
                "threat": "The SPF policy does not clearly reject unauthorised senders",
                "detail": f"SPF record contains '?all': {spf}",
                "remediation": "The website email security rule is not strict enough to fully block unauthorized senders. Review approved email systems and use a stronger SPF ending such as -all or ~all to prevent fake or suspicious emails."
            })

        elif "~all" in spf_lower:
            findings.append({
                "severity": "Low",
                "level": "Minor",
                "title": "SoftFail SPF Policy Detected",
                "threat": "Unauthorised emails may not be strictly rejected",
                "detail": f"SPF record contains '~all': {spf}",
                "remediation": "The website email security rule is not strict enough to fully block fake or unauthorized senders. Review approved email systems and consider using ~all to better prevent fake or suspicious emails."
            })

    return findings


def analyze_dmarc(dmarc_records):
    findings = []

    if not dmarc_records:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Missing DMARC Record",
            "threat": "Domain is more vulnerable to email spoofing and phishing abuse",
            "detail": "No DMARC record was found for the domain.",
            "remediation": "The domain does not have a clear DMARC instruction telling receiving mail systems what to do with fake emails. Create a DMARC TXT record at `_dmarc.domain` with a policy such as `p=quarantine` or `p=reject`."
        })
        return findings

    for dmarc in dmarc_records:
        dmarc_lower = dmarc.lower()

        if "p=none" in dmarc_lower:
            findings.append({
                "severity": "Medium",
                "level": "Major",
                "title": "DMARC Policy Set to None",
                "threat": "DMARC is only monitoring and not actively blocking spoofed emails",
                "detail": f"DMARC record uses p=none: {dmarc}",
                "remediation": "The current DMARC policy is not strict enough to block suspicious emails. After monitoring approved email systems, move the DMARC policy from `p=none` to `p=quarantine` or `p=reject` for better email protection."
            })

        elif "p=quarantine" in dmarc_lower:
            findings.append({
                "severity": "Low",
                "level": "Minor",
                "title": "DMARC Policy Uses Quarantine",
                "threat": "Spoofed emails may be quarantined but not fully rejected",
                "detail": f"DMARC record uses p=quarantine: {dmarc}",
                "remediation": "The current DMARC policy is not strict enough to block suspicious emails. After monitoring approved email systems, move the DMARC policy to `p=reject` for better email protection"
            })

    return findings


def analyze_dkim(dkim_records):
    findings = []

    if not dkim_records:
        findings.append({
            "severity": "Medium",
            "level": "Major",
            "title": "No Common DKIM Record Found",
            "threat": "Email authenticity may be harder to verify if DKIM is not configured",
            "detail": "No DKIM record was found using common selectors.",
            "remediation": "The system is unable to confirm DKIM using the common selectors checked during the scan. This does not always mean DKIM is missing, but it should be verified by your email administrator. Configure DKIM signing and publish the correct selector TXT record to improve email protection"
        })

    return findings


def analyze_mx(mx_records):
    findings = []

    if not mx_records:
        findings.append({
            "severity": "Medium",
            "level": "Major",
            "title": "Missing MX Record",
            "threat": "The domain may not be configured to receive email properly",
            "detail": "No MX records were found for the domain.",
            "remediation": "The system is unable to find a valid MX record for this domain. If the domain is meant to send or receive email, contact your email provider to review and update the DNS mail settings"
        })

    return findings


def phishing_detector_scan(target):
    domain = clean_domain(target)
    findings = []

    if not domain:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Invalid Target",
            "threat": "Scanner cannot check DNS security records without a valid domain",
            "detail": "The provided target was empty or invalid.",
            "remediation": "Enter a valid domain such as example.com."
        })

        return {
            "module": "phishing_detector",
            "findings": findings,
            "info": {
                "target": target,
                "domain": domain,
                "total_findings": len(findings),
                "major_threats": len([f for f in findings if f["level"] == "Major"]),
                "minor_threats": len([f for f in findings if f["level"] == "Minor"]),
                "spf_records": [],
                "dmarc_records": [],
                "dkim_records": {},
                "mx_records": []
            }
        }

    mx_records = check_mx_records(domain)
    spf_records = check_spf_record(domain)
    dmarc_records = check_dmarc_record(domain)
    dkim_records = check_dkim_records(domain)

    findings.extend(analyze_mx(mx_records))
    findings.extend(analyze_spf(spf_records))
    findings.extend(analyze_dmarc(dmarc_records))
    findings.extend(analyze_dkim(dkim_records))

    return {
        "module": "phishing_detector",
        "findings": findings,
        "info": {
            "target": target,
            "domain": domain,
            "total_findings": len(findings),
            "major_threats": len([f for f in findings if f["level"] == "Major"]),
            "minor_threats": len([f for f in findings if f["level"] == "Minor"]),
            "spf_records": spf_records,
            "dmarc_records": dmarc_records,
            "dkim_records": dkim_records,
            "mx_records": mx_records
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
    target = input("Enter domain or URL (e.g. example.com): ").strip()

    if not target:
        print("Error: target cannot be empty.")
    else:
        result = phishing_detector_scan(target)

        print("\nScan Result:")
        print(json.dumps(result, indent=2))
