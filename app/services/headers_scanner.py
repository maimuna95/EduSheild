import httpx
import json
import warnings

warnings.filterwarnings("ignore")

BACKEND_URL = "http://127.0.0.1:8000/scan-result/"
TIMEOUT = 10

SECURITY_HEADERS = {"Strict-Transport-Security": {"severity": "High",
                                                  "threat": "Users may be exposed to protocol downgrade or SSL stripping attacks",
                                                  "remediation": "Add Strict-Transport-Security with max-age and includeSubDomains where appropriate."},
                    "Content-Security-Policy": {"severity": "High",
                                                "threat": "Higher risk of XSS and malicious content injection",
                                                "remediation": "Add a Content-Security-Policy restricting trusted sources."},
                    "X-Frame-Options": {"severity": "Medium",
                                        "threat": "Page may be exposed to clickjacking attacks",
                                        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN."},
                    "X-Content-Type-Options": {"severity": "Medium",
                                               "threat": "Browser may MIME-sniff files and execute unexpected content",
                                               "remediation": "Add X-Content-Type-Options: nosniff."},
                    "Referrer-Policy": {"severity": "Low",
                                        "threat": "Sensitive URL information may leak through Referer header",
                                        "remediation": "Add Referrer-Policy such as strict-origin-when-cross-origin."},
                    "Permissions-Policy": {"severity": "Low",
                                           "threat": "Browser features may be available more broadly than needed",
                                           "remediation": "Add Permissions-Policy to restrict camera, microphone, geolocation, etc."},
                    "Cross-Origin-Opener-Policy": {"severity": "Low",
                                                   "threat": "Weak browser isolation may increase cross-origin attack risk",
                                                   "remediation": "Add Cross-Origin-Opener-Policy: same-origin where suitable."}}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]

SENSITIVE_COOKIE_KEYWORDS = [
    "session", "auth", "token", "jwt", "sid", "login", "user"
]


def clean_target(target):
    target = target.strip()

    if not target:
        return ""

    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")

    return target.lower().rstrip("/")


def build_urls(target):
    target = clean_target(target)

    if target.startswith("http://") or target.startswith("https://"):
        return [target]

    return [
        f"https://{target}",
        f"http://{target}"
    ]


def fetch_response(target):
    urls = build_urls(target)

    for url in urls:
        try:
            response = httpx.get(
                url,
                headers={"User-Agent": "Mozilla/5.0"},
                timeout=TIMEOUT,
                follow_redirects=True,
                verify=False
            )
            return response

        except httpx.RequestError:
            continue

        except Exception:
            continue

    return None


def get_all_headers(response):
    combined_headers = {}

    all_responses = list(response.history) + [response]

    for res in all_responses:
        for key, value in res.headers.items():
            combined_headers[key] = value

    return combined_headers


def get_all_set_cookie_headers(response):
    cookies = []

    all_responses = list(response.history) + [response]

    for res in all_responses:
        try:
            cookies.extend(res.headers.get_list("set-cookie"))
        except Exception:
            pass

    return cookies


def severity_to_level(severity):
    if severity in ["High", "Medium"]:
        return "Major"
    return "Minor"


def is_sensitive_cookie(cookie_name):
    cookie_name = cookie_name.lower()
    return any(keyword in cookie_name for keyword in SENSITIVE_COOKIE_KEYWORDS)


def analyze_missing_security_headers(response):
    findings = []
    present_headers = []
    missing_headers = []

    headers = get_all_headers(response)
    lower_headers = {key.lower(): value for key, value in headers.items()}

    for header, data in SECURITY_HEADERS.items():
        if header.lower() in lower_headers:
            present_headers.append(header)
        else:
            missing_headers.append(header)

            findings.append({
                "severity": data["severity"],
                "level": severity_to_level(data["severity"]),
                "title": f"Missing {header} Header",
                "threat": data["threat"],
                "detail": f"The response is missing the {header} security header.",
                "remediation": data["remediation"]
            })

    return findings, present_headers, missing_headers


def analyze_cookie_flags(response):
    findings = []
    cookies_detected = 0

    set_cookie_headers = get_all_set_cookie_headers(response)

    for cookie in set_cookie_headers:
        cookies_detected += 1

        cookie_parts = cookie.split(";")
        cookie_name = cookie_parts[0].split("=")[0].strip()

        if not is_sensitive_cookie(cookie_name):
            continue

        cookie_lower = cookie.lower()

        if "secure" not in cookie_lower:
            findings.append({
                "severity": "Medium",
                "level": "Major",
                "title": "Sensitive Cookie Missing Secure Flag",
                "threat": "Sensitive cookies may be sent over unencrypted connections",
                "detail": f"Sensitive cookie '{cookie_name}' does not appear to use the Secure flag.",
                "remediation": "Set the Secure flag on sensitive cookies so they are only sent over HTTPS."
            })

        if "httponly" not in cookie_lower:
            findings.append({
                "severity": "Medium",
                "level": "Major",
                "title": "Sensitive Cookie Missing HttpOnly Flag",
                "threat": "Client-side scripts may access sensitive cookies if XSS occurs",
                "detail": f"Sensitive cookie '{cookie_name}' does not appear to use the HttpOnly flag.",
                "remediation": "Set HttpOnly on session and authentication cookies."
            })

        if "samesite" not in cookie_lower:
            findings.append({
                "severity": "Low",
                "level": "Minor",
                "title": "Sensitive Cookie Missing SameSite Attribute",
                "threat": "Cookies may be sent with cross-site requests, increasing CSRF risk",
                "detail": f"Sensitive cookie '{cookie_name}' does not appear to use SameSite.",
                "remediation": "Set SameSite=Lax or SameSite=Strict where possible."
            })

    return findings, cookies_detected


def analyze_info_leak_headers(response):
    findings = []
    leaks = {}

    headers = get_all_headers(response)
    lower_headers = {key.lower(): value for key, value in headers.items()}

    for header in INFO_LEAK_HEADERS:
        value = lower_headers.get(header.lower())

        if value:
            leaks[header] = value

    if leaks:
        detail = ", ".join([f"{key}: {value}" for key, value in leaks.items()])

        findings.append({
            "severity": "Low",
            "level": "Minor",
            "title": "Technology Information Exposed",
            "threat": "Attackers may use exposed technology details for fingerprinting",
            "detail": detail,
            "remediation": "Remove or minimize unnecessary technology-identifying response headers."
        })

    return findings, leaks


def header_analyzer_scan(target):
    target = clean_target(target)
    findings = []

    response = fetch_response(target)

    if response is None:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Target Not Reachable",
            "threat": "Scanner could not retrieve HTTP response headers",
            "detail": f"No valid HTTP or HTTPS response was received from {target}.",
            "remediation": "Check whether the domain is correct, reachable, and allowing HTTP/HTTPS traffic."
        })

        return {
            "module": "header_analyzer",
            "findings": findings,
            "info": {
                "target": target,
                "reachable_url": None,
                "status_code": None,
                "total_findings": len(findings),
                "major_threats": 1,
                "minor_threats": 0,
                "present_security_headers": [],
                "missing_security_headers": list(SECURITY_HEADERS.keys()),
                "cookies_detected": 0,
                "info_leak_headers": {}
            }
        }

    header_findings, present_headers, missing_headers = analyze_missing_security_headers(
        response)
    cookie_findings, cookies_detected = analyze_cookie_flags(response)
    leak_findings, info_leaks = analyze_info_leak_headers(response)

    findings.extend(header_findings)
    findings.extend(cookie_findings)
    findings.extend(leak_findings)

    return {
        "module": "header_analyzer",
        "findings": findings,
        "info": {
            "target": target,
            "hostname": response.url.host,
            "reachable_url": str(response.url),
            "status_code": response.status_code,
            "total_findings": len(findings),
            "major_threats": len([f for f in findings if f["level"] == "Major"]),
            "minor_threats": len([f for f in findings if f["level"] == "Minor"]),
            "present_security_headers": present_headers,
            "missing_security_headers": missing_headers,
            "cookies_detected": cookies_detected,
            "info_leak_headers": info_leaks
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
    target = input("Enter URL or domain (e.g.badssl.com): ").strip()

    if not target:
        print("Error: target cannot be empty.")
    else:
        result = header_analyzer_scan(target)

        print("\nScan Result:")
        print(json.dumps(result, indent=2))

        # Backend integration later
        # post_response = send_scan_result(result)
        # print("\nPOST Response:")
        # print(json.dumps(post_response, indent=2))
