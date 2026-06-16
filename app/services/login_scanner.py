import httpx
import json
import warnings

warnings.filterwarnings("ignore")

BACKEND_URL = "http://127.0.0.1:8000/scan-result/"
TIMEOUT = 3

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/user/login",
    "/admin", "/admin/login", "/administrator",
    "/wp-login.php", "/wp-admin",
    "/dashboard", "/portal", "/account",
    "/auth/login", "/users/sign_in",
    "/student/login", "/staff/login",
    "/moodle/login/index.php",
    "/cpanel", "/webmail",
    # Extra paths for modern apps and testing labs
    "/rest/user/login",
    "/api/login",
    "/auth",
    "/users/login",
    "/user",
    "/profile",
    "/account/login",
    "/WebGoat/login",
    "/WebGoat",
    "/dvwa/login.php",
    "/DVWA/login.php"
]
SENSITIVE_FILES = [
    "/.env", "/wp-config.php", "/config.php",
    "/backup.zip", "/backup.sql", "/db.sql",
    "/.git/config"
]
LOGIN_KEYWORDS = [
    "login", "sign in", "signin", "password",
    "username", "email", "auth", "account"
]
CAPTCHA_KEYWORDS = [
    "captcha", "recaptcha", "g-recaptcha", "hcaptcha"
]


def clean_target(target):
    target = target.strip()

    if not target:
        return ""

    return target.rstrip("/")


def build_base_urls(target):
    target = clean_target(target)

    if target.startswith("http://") or target.startswith("https://"):
        return [target]

    return [
        f"https://{target}",
        f"http://{target}"
    ]


def request_url(url):
    try:
        return httpx.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=TIMEOUT,
            follow_redirects=True,
            verify=False
        )
    except Exception:
        return None


def severity_to_level(severity):
    if severity in ["Critical", "High", "Medium"]:
        return "Major"
    return "Minor"


def page_contains_login(response):
    html = response.text.lower()
    # A true login page must contain a password input field
    return 'type="password"' in html or "type='password'" in html


def page_has_captcha(response):
    html = response.text.lower()
    return any(keyword in html for keyword in CAPTCHA_KEYWORDS)


def is_http_url(url):
    return str(url).startswith("http://")


def is_sensitive_file_exposed(response):
    if response is None:
        return False

    if response.status_code != 200:
        return False

    body = response.text.lower()

    indicators = [
        "db_password", "database_password", "mysql",
        "wordpress", "app_key", "secret_key",
        "private_key", "[core]", "repositoryformatversion"
    ]

    return any(indicator in body for indicator in indicators)


def login_scanner_scan(target):
    target = clean_target(target)
    findings = []

    reachable_bases = []
    discovered_login_pages = []
    exposed_sensitive_files = []

    # Check both HTTPS and HTTP automatically
    for base_url in build_base_urls(target):
        response = request_url(base_url)

        if response is not None:
            reachable_bases.append(base_url)

    if not reachable_bases:
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Target Not Reachable",
            "threat": "Scanner could not reach the target website",
            "detail": f"No valid HTTP or HTTPS response was received from {target}.",
            "remediation": "Check whether the domain is correct, reachable, and allowing HTTP/HTTPS traffic."
        })

        return {
            "module": "login_scanner",
            "findings": findings,
            "info": {
                "target": target,
                "reachable_base_urls": [],
                "total_findings": len(findings),
                "major_threats": len([f for f in findings if f["level"] == "Major"]),
                "minor_threats": len([f for f in findings if f["level"] == "Minor"]),
                "total_login_pages_found": 0,
                "discovered_login_pages": [],
                "total_sensitive_files_found": 0,
                "exposed_sensitive_files": []
            }
        }

    login_without_captcha = []
    login_over_http = []

    # Login/admin path checks
    for base_url in reachable_bases:
        for path in LOGIN_PATHS:
            url = base_url.rstrip("/") + path
            response = request_url(url)

            if response is None:
                continue

            if response.status_code in [200, 301, 302, 401, 403]:
                if page_contains_login(response):
                    final_url = str(response.url)
                    page_data = {
                        "url": final_url,
                        "status_code": response.status_code
                    }

                    if page_data not in discovered_login_pages:
                        discovered_login_pages.append(page_data)

                        if not page_has_captcha(response):
                            if final_url not in login_without_captcha:
                                login_without_captcha.append(final_url)

                        if is_http_url(final_url):
                            if final_url not in login_over_http:
                                login_over_http.append(final_url)

    # Sensitive file checks
    for base_url in reachable_bases:
        for file_path in SENSITIVE_FILES:
            url = base_url.rstrip("/") + file_path
            response = request_url(url)

            if is_sensitive_file_exposed(response):
                file_data = {
                    "url": str(response.url),
                    "status_code": response.status_code
                }

                if file_data not in exposed_sensitive_files:
                    exposed_sensitive_files.append(file_data)

    # Consolidate findings to avoid duplicate rows
    if discovered_login_pages:
        urls_list = "\n".join([f"• {p['url']} (Status: {p['status_code']})" for p in discovered_login_pages])
        findings.append({
            "severity": "Medium",
            "level": "Major",
            "title": "Exposed Login Interface Detected",
            "threat": "Public login pages may be targeted by brute-force or credential stuffing attacks",
            "detail": f"Login interfaces detected at:\n{urls_list}",
            "remediation": "Protect login pages with MFA, rate limiting, strong authentication, and monitoring."
        })

    if login_without_captcha:
        urls_list = "\n".join([f"• {url}" for url in login_without_captcha])
        findings.append({
            "severity": "Low",
            "level": "Minor",
            "title": "Login Page Missing CAPTCHA Protection",
            "threat": "Automated bots may attempt brute-force or credential stuffing attacks",
            "detail": f"CAPTCHA verification missing on login pages:\n{urls_list}",
            "remediation": "Consider implementing CAPTCHA, rate limiting, account lockout, or bot protection."
        })

    if login_over_http:
        urls_list = "\n".join([f"• {url}" for url in login_over_http])
        findings.append({
            "severity": "High",
            "level": "Major",
            "title": "Login Interface Accessible Over HTTP",
            "threat": "Credentials may be transmitted over an unencrypted connection",
            "detail": f"Unencrypted HTTP login interfaces accessible at:\n{urls_list}",
            "remediation": "Force HTTPS for all login pages and redirect HTTP traffic to HTTPS."
        })

    if exposed_sensitive_files:
        urls_list = "\n".join([f"• {p['url']} (Status: {p['status_code']})" for p in exposed_sensitive_files])
        findings.append({
            "severity": "Critical",
            "level": "Major",
            "title": "Sensitive File Exposed",
            "threat": "Sensitive configuration or backup files may expose credentials or internal system details",
            "detail": f"Sensitive files exposed at:\n{urls_list}",
            "remediation": "Remove sensitive files from the public web root, restrict access, and rotate exposed credentials."
        })

    return {
        "module": "login_scanner",
        "findings": findings,
        "info": {
            "target": target,
            "reachable_base_urls": reachable_bases,
            "total_findings": len(findings),
            "major_threats": len([f for f in findings if f["level"] == "Major"]),
            "minor_threats": len([f for f in findings if f["level"] == "Minor"]),
            "total_login_pages_found": len(discovered_login_pages),
            "discovered_login_pages": discovered_login_pages,
            "total_sensitive_files_found": len(exposed_sensitive_files),
            "exposed_sensitive_files": exposed_sensitive_files
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
    target = input("Enter domain (e.g. badssl.com): ").strip()
    if not target:
        print("Error: target cannot be empty.")
    else:
        result = login_scanner_scan(target)

        print("\nScan Result:")
        print(json.dumps(result, indent=2))

        # Backend integration later
        # post_response = send_scan_result(result)
        # print("\nPOST Response:")
        # print(json.dumps(post_response, indent=2))
