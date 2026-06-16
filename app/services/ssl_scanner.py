import ssl
import socket
import datetime

from urllib.parse import urlparse, urljoin

import httpx
# pyrefly: ignore [missing-import]
from cryptography import x509
# pyrefly: ignore [missing-import]
from cryptography.x509.oid import NameOID

# =========================
# Config
# =========================
USER_AGENT = "EduShield-Scanner/1.0"
DEFAULT_TIMEOUT = 15.0
MAX_REDIRECT_HOPS = 5
WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5"]
DEPRECATED_TLS_VERSIONS = {"SSLv3", "TLSv1", "TLSv1.1"}

# =========================
# Helpers
# =========================


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if "://" in target:
        return (urlparse(target).hostname or target).lower()
    if "/" in target:
        return (urlparse("https://" + target).hostname or target.split("/")[0]).lower()
    return target.lower()


def _format_error(exc: Exception) -> str:
    return f"{exc.__class__.__name__}: {exc}"


def _make_finding(
        severity: str,
        level: str,
        title: str,
        threat: str,
        detail: str,
        remediation: str) -> dict:
    return {
        "severity": severity,
        "level": level,
        "title": title,
        "threat": threat,
        "detail": detail,
        "remediation": remediation,
    }


def _hostname_matches(hostname: str, pattern: str) -> bool:
    hostname = hostname.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count(
            ".") >= pattern.count(".")
    return hostname == pattern

# =========================
# Certificate decode
# =========================


def decode_certificate(der_bytes: bytes) -> tuple[dict | None, str | None]:
    if not der_bytes:
        return None, "No certificate bytes received from peer"
    try:
        cert = x509.load_der_x509_certificate(der_bytes)

        def _cn(name_obj):
            attrs = name_obj.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else None

        expiry = getattr(
            cert,
            "not_valid_after_utc",
            None) or cert.not_valid_after
        if isinstance(expiry, datetime.datetime) and expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)

        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName)
            san_dns = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_dns = []

        cert_info = {
            "not_after": expiry.astimezone(
                datetime.timezone.utc).strftime("%b %d %H:%M:%S %Y GMT"), "subject_cn": _cn(
                cert.subject), "issuer_cn": _cn(
                cert.issuer), "san_dns": san_dns, }
        return cert_info, None
    except Exception as exc:
        return None, _format_error(exc)

# =========================
# TLS probe
# =========================


def probe_tls(domain: str,
              port: int = 443,
              timeout: float = DEFAULT_TIMEOUT) -> tuple[dict | None,
                                                         str | None]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as tls_sock:
                return {
                    "tls_version": tls_sock.version(),
                    "cipher": tls_sock.cipher(),
                    "der_cert": tls_sock.getpeercert(binary_form=True),
                }, None
    except Exception as exc:
        return None, _format_error(exc)

# =========================
# HTTP -> HTTPS check
# =========================


def check_http_to_https_redirect(domain: str,
                                 timeout: float = DEFAULT_TIMEOUT,
                                 max_hops: int = MAX_REDIRECT_HOPS) -> tuple[dict,
                                                                             str | None]:
    url = f"http://{domain}/"
    chain: list[dict] = []
    visited: set[str] = set()
    saw_redirect = False

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False, trust_env=False, headers={"User-Agent": USER_AGENT}) as client:
            for hop in range(max_hops + 1):
                if url in visited:
                    return {"state": "redirect_loop", "hops": hop,
                            "final_url": url, "https_url": None, "chain": chain}, None
                visited.add(url)
                resp = client.get(url)
                location = resp.headers.get("Location")

                chain.append({"url": str(resp.url),
                              "status": resp.status_code,
                              "location": location})
                is_redirect = resp.status_code in (
                    301, 302, 303, 307, 308) and bool(location)

                if not is_redirect:
                    state = "redirect_non_https" if saw_redirect else "no_redirect"
                    return {"state": state, "hops": hop, "final_url": str(
                        resp.url), "https_url": None, "chain": chain}, None

                saw_redirect = True
                next_url = urljoin(str(resp.url), location)
                if next_url.lower().startswith("https://"):
                    state = "direct_https" if hop == 0 else "eventual_https"
                    return {"state": state, "hops": hop + 1, "final_url": next_url,
                            "https_url": next_url, "chain": chain}, None

                url = next_url
            return {"state": "redirect_non_https", "hops": max_hops + 1,
                    "final_url": url, "https_url": None, "chain": chain}, None
    except Exception as exc:
        return {"state": "error", "hops": len(chain), "final_url": url, "https_url": None,
                "chain": chain, "error_type": exc.__class__.__name__}, _format_error(exc)

# =========================
# HSTS check
# =========================


def check_hsts(domain: str,
               timeout: float = DEFAULT_TIMEOUT) -> tuple[dict,
                                                          str | None]:
    candidates = [domain] if domain.startswith(
        "www.") else [domain, f"www.{domain}"]
    checked: list[dict] = []
    errors: list[str] = []

    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False, trust_env=False, headers={"User-Agent": USER_AGENT}) as client:
        for host in candidates:
            url = f"https://{host}/"
            try:
                resp = client.get(url)
                checked.append(
                    {"host": host, "urls": [str(r.url) for r in resp.history + [resp]]})
                for r in resp.history + [resp]:
                    if str(r.url).lower().startswith("https://"):
                        hsts_value = r.headers.get("Strict-Transport-Security")
                        if hsts_value:
                            return {
                                "state": "present", "hsts": hsts_value, "found_on": str(
                                    r.url), "checked": checked}, None
            except Exception as exc:
                errors.append(f"{host}: {_format_error(exc)}")

    if checked:
        return {"state": "missing", "hsts": None,
                "found_on": None, "checked": checked}, None

    error_msg = "; ".join(errors) or "HSTS check failed for unknown reasons"
    return {"state": "error", "hsts": None,
            "found_on": None, "checked": checked}, error_msg

# =========================
# Finding builders
# =========================


def _cert_expiry_findings(cert_details: dict | None,
                          tls_ok: bool) -> tuple[list, str | None, int | None]:
    findings: list[dict] = []
    expiry_str = cert_details.get("not_after") if cert_details else None
    days_left = None

    if not expiry_str:
        if tls_ok:
            findings.append(
                _make_finding(
                    "Medium",
                    "Major",
                    "Certificate Expiry Could Not Be Determined",
                    "Certificate visibility and validation gap",
                    "TLS handshake succeeded but certificate expiry could not be decoded.",
                    "Ensure certificate decoding support is enabled and verify the certificate manually."))
        else:
            findings.append(
                _make_finding(
                    "High",
                    "Major",
                    "TLS Connection Could Not Be Established",
                    "HTTPS service unavailable or unreachable",
                    "Failed to connect on port 443 to inspect TLS configuration.",
                    "Ensure the target supports HTTPS on port 443 and the service is reachable."))
        return findings, expiry_str, days_left

    try:
        expiry_ts = ssl.cert_time_to_seconds(expiry_str)
        expiry_dt = datetime.datetime.fromtimestamp(
            expiry_ts, datetime.timezone.utc)
        days_left = (expiry_dt - datetime.datetime.now(datetime.timezone.utc)).days

        if days_left < 0:
            findings.append(
                _make_finding(
                    "Critical",
                    "Major",
                    "Expired SSL Certificate Detected",
                    "Service trust failure and encrypted communication risk",
                    f"Certificate expired {abs(days_left)} day(s) ago (notAfter: {expiry_str})",
                    "Renew and deploy a valid TLS certificate immediately."))
        elif days_left <= 7:
            findings.append(
                _make_finding(
                    "High",
                    "Major",
                    "SSL Certificate Expiring Very Soon",
                    "Potential service disruption and trust warning risk",
                    f"Certificate expires in {days_left} day(s) (notAfter: {expiry_str})",
                    "Renew the certificate immediately and verify deployment."))
        elif days_left <= 30:
            findings.append(
                _make_finding(
                    "Medium",
                    "Major",
                    "SSL Certificate Expiring Soon",
                    "Potential upcoming service trust and availability risk",
                    f"Certificate expires in {days_left} day(s) (notAfter: {expiry_str})",
                    "Schedule renewal soon and verify certificate management process."))
    except Exception as exc:
        findings.append(
            _make_finding(
                "Medium",
                "Major",
                "Certificate Expiry Could Not Be Evaluated",
                "Certificate monitoring gap",
                f"Failed to parse notAfter value: {expiry_str} — {_format_error(exc)}",
                "Manually verify certificate expiry and ensure reliable certificate parsing."))

    return findings, expiry_str, days_left


def _cert_domain_findings(
        domain: str,
        cert_details: dict | None) -> list[dict]:
    if not cert_details:
        return []
    names = []
    if cert_details.get("subject_cn"):
        names.append(cert_details["subject_cn"])
    names.extend(cert_details.get("san_dns", []))
    matched = any(_hostname_matches(domain, name) for name in names if name)
    if matched:
        return [
            _make_finding(
                "Info",
                "Minor",
                "Certificate Matches Target Domain",
                "No immediate security issue identified",
                f"The certificate covers the scanned domain '{domain}'.",
                "No action required.")]
    return [
        _make_finding(
            "High",
            "Major",
            "Certificate Does Not Match Target Domain",
            "Certificate trust and hostname validation risk",
            f"The certificate does not appear to cover the scanned domain '{domain}'.",
            "Deploy a certificate whose SAN or CN matches the target domain.")]


def _tls_version_findings(tls_version: str | None) -> list[dict]:
    if tls_version in DEPRECATED_TLS_VERSIONS:
        return [
            _make_finding(
                "Critical",
                "Major",
                "Deprecated TLS Version Detected",
                "Weak transport encryption",
                f"Server negotiated deprecated protocol version {tls_version}.",
                "Disable SSLv3, TLS 1.0, and TLS 1.1. Allow only TLS 1.2 and TLS 1.3.")]
    if tls_version == "TLSv1.2":
        return [
            _make_finding(
                "Info",
                "Minor",
                "TLS 1.2 Detected",
                "No immediate security issue identified",
                "Server negotiated TLS 1.2.",
                "Consider enabling TLS 1.3 alongside TLS 1.2.")]
    return []


def _cipher_findings(
        cipher_name: str | None,
        cipher_bits: int | None) -> list[dict]:
    if not cipher_name:
        return []
    weak_hits = [
        kw for kw in WEAK_CIPHER_KEYWORDS if kw in cipher_name.upper()]
    if weak_hits:
        return [
            _make_finding(
                "High",
                "Major",
                "Weak Cipher Suite Detected",
                "Weak transport encryption",
                f"Negotiated cipher '{cipher_name}' contains weak component(s): {', '.join(weak_hits)}",
                "Disable weak ciphers. Prefer AEAD suites such as AES-GCM or ChaCha20-Poly1305.")]
    if cipher_bits is not None and cipher_bits < 128:
        return [
            _make_finding(
                "High",
                "Major",
                "Weak Cipher Key Length Detected",
                "Insufficient encryption strength",
                f"Negotiated cipher '{cipher_name}' uses only {cipher_bits}-bit encryption.",
                "Enforce cipher suites with at least 128-bit encryption strength.")]
    return []


def _redirect_findings(
        redirect_result: dict | None,
        redirect_error: str | None,
        domain: str) -> list[dict]:
    if redirect_error:
        error_type = redirect_result.get(
            "error_type") if redirect_result else None
        if error_type == "ConnectTimeout":
            return [
                _make_finding(
                    "Medium",
                    "Major",
                    "HTTP Redirect Check Timed Out",
                    "Secure transport enforcement could not be confirmed",
                    f"Redirect evaluation for http://{domain} timed out.",
                    "Retest from a stable network and verify whether HTTP traffic is redirected to HTTPS.")]
        return [
            _make_finding(
                "Medium",
                "Major",
                "HTTP Redirect Check Failed",
                "Secure transport enforcement could not be confirmed",
                f"Redirect evaluation could not be completed: {redirect_error}",
                "Retest and verify HTTP-to-HTTPS redirect behaviour manually.")]
    state = redirect_result.get("state")
    final_url = redirect_result.get("final_url")
    hops = redirect_result.get("hops", 0)
    if state in ("direct_https", "eventual_https"):
        return [
            _make_finding(
                "Info",
                "Minor",
                "HTTP to HTTPS Redirect in Place",
                "No immediate security issue identified",
                f"http://{domain} upgrades to HTTPS after {hops} hop(s) → {final_url}",
                "No action required.")]
    if state == "no_redirect":
        return [
            _make_finding(
                "High",
                "Major",
                "No HTTP to HTTPS Redirect Detected",
                "Insecure transport exposure",
                f"http://{domain} served content without redirecting users to HTTPS.",
                "Force all HTTP traffic to HTTPS using permanent redirects.")]
    if state == "redirect_non_https":
        return [
            _make_finding(
                "High",
                "Major",
                "HTTP Redirect Does Not Upgrade to HTTPS",
                "Insecure transport exposure",
                f"http://{domain} redirects but does not reach HTTPS (final: {final_url}).",
                "Configure HTTP requests to redirect directly to the HTTPS version of the site.")]
    if state == "redirect_loop":
        return [
            _make_finding(
                "Medium",
                "Major",
                "HTTP Redirect Loop Detected",
                "Secure transport enforcement could not be confirmed",
                f"Redirect evaluation entered a loop (final: {final_url}).",
                "Inspect redirect rules and remove looping or conflicting redirects.")]
    return [
        _make_finding(
            "Medium",
            "Major",
            "HTTP Redirect Status Inconclusive",
            "Secure transport enforcement could not be confirmed",
            f"Redirect evaluation ended in unexpected state '{state}' (final: {final_url}).",
            "Inspect redirect behaviour manually and verify HTTPS enforcement.")]


def _hsts_findings(
        hsts_result: dict | None,
        hsts_error: str | None) -> list[dict]:
    if hsts_error:
        return [
            _make_finding(
                "Medium",
                "Major",
                "HSTS Status Could Not Be Confirmed",
                "Transport security hardening could not be verified",
                f"HSTS evaluation could not be completed: {hsts_error}",
                "Retest and verify the Strict-Transport-Security header manually on HTTPS responses.")]
    state = hsts_result.get("state")
    if state == "present":
        return [
            _make_finding(
                "Info",
                "Minor",
                "HSTS Header Present",
                "No immediate security issue identified",
                f"Strict-Transport-Security found on {hsts_result.get('found_on')}: {hsts_result.get('hsts')}",
                "No action required.")]
    if state == "missing":
        return [
            _make_finding(
                "Medium",
                "Major",
                "HSTS Header Missing",
                "Potential SSL stripping or downgrade risk",
                "No Strict-Transport-Security header was found on any HTTPS response.",
                "Add Strict-Transport-Security with an appropriate max-age and includeSubDomains.")]
    return [
        _make_finding(
            "Medium",
            "Major",
            "HSTS Status Inconclusive",
            "Transport security hardening could not be verified",
            "HSTS state could not be determined reliably.",
            "Verify HTTPS reachability and validate HSTS configuration manually.")]

# =========================
# Main scanner
# =========================


def ssl_scan(target: str) -> dict:
    domain = normalize_target(target)
    findings: list[dict] = []
    errors: dict = {}

    tls_result, tls_error = probe_tls(domain)
    if tls_error:
        errors["tls_probe_error"] = tls_error

    tls_version = cipher_name = cipher_bits = None
    cert_details = None

    if tls_result:
        tls_version = tls_result["tls_version"]
        cipher_tuple = tls_result.get("cipher")
        if cipher_tuple and len(cipher_tuple) == 3:
            cipher_name, _, cipher_bits = cipher_tuple
        cert_details, cert_error = decode_certificate(tls_result["der_cert"])
        if cert_error:
            errors["cert_decode_error"] = cert_error

    cert_findings, cert_expiry_str, days_left = _cert_expiry_findings(
        cert_details, tls_ok=bool(tls_result))
    findings.extend(cert_findings)

    findings.extend(_cert_domain_findings(domain, cert_details))
    findings.extend(_tls_version_findings(tls_version))
    findings.extend(_cipher_findings(cipher_name, cipher_bits))

    redirect_result, redirect_error = check_http_to_https_redirect(domain)
    if redirect_error:
        errors["redirect_error"] = redirect_error
    findings.extend(
        _redirect_findings(
            redirect_result,
            redirect_error,
            domain))

    hsts_result, hsts_error = check_hsts(domain)
    if hsts_error:
        errors["hsts_error"] = hsts_error
    findings.extend(_hsts_findings(hsts_result, hsts_error))

    major_count = sum(1 for f in findings if f["level"] == "Major")
    minor_count = sum(1 for f in findings if f["level"] == "Minor")

    return {
        "module": "ssl_tls_analysis",
        "findings": findings,
        "info": {
            "target": domain,
            "total_findings": len(findings),
            "major_threats": major_count,
            "minor_threats": minor_count,
            "tls_version": tls_version,
            "cipher": cipher_name,
            "cipher_bits": cipher_bits,
            "cert_subject": cert_details.get("subject_cn") if cert_details else None,
            "cert_issuer": cert_details.get("issuer_cn") if cert_details else None,
            "cert_expiry": cert_expiry_str,
            "days_until_expiry": days_left,
            "san": cert_details.get("san_dns", []) if cert_details else [],
            "redirect_state": redirect_result.get("state") if redirect_result else None,
            "redirect_final_url": redirect_result.get("final_url") if redirect_result else None,
            "redirect_hops": redirect_result.get("hops") if redirect_result else None,
            "redirect_chain": redirect_result.get("chain") if redirect_result else None,
            "hsts_state": hsts_result.get("state") if hsts_result else None,
            "hsts": hsts_result.get("hsts") if hsts_result else None,
            "hsts_found_on": hsts_result.get("found_on") if hsts_result else None,
            "errors": errors,
        },
    }
