"""
network_intel.py - Real-time network, DNS, SSL/TLS, and HTTP infrastructure intelligence for PhishGuard.
Performs live DNS resolution, reverse IP lookups, SSL certificate validation, redirect chain tracking,
and security header inspection to deliver realistic threat intelligence.
"""

import socket
import ssl
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

# Free hosting, serverless PaaS, and dynamic DNS providers frequently abused by threat actors
SUSPICIOUS_PAAS_PROVIDERS: Dict[str, str] = {
    "pages.dev": "Cloudflare Pages (PaaS)",
    "workers.dev": "Cloudflare Workers",
    "firebaseapp.com": "Google Firebase App",
    "web.app": "Google Firebase Web App",
    "duckdns.org": "DuckDNS Dynamic DNS",
    "ngrok-free.app": "ngrok Tunneling Service",
    "ngrok.io": "ngrok Tunneling Service",
    "vercel.app": "Vercel Hosting",
    "netlify.app": "Netlify Hosting",
    "glitch.me": "Glitch Web Hosting",
    "surge.sh": "Surge Static Hosting",
    "000webhostapp.com": "000webhost Free Hosting",
    "weebly.com": "Weebly Free Site Builder",
    "wixsite.com": "Wix Free Site Builder",
    "blogspot.com": "Blogger Free Hosting",
    "s3.amazonaws.com": "Amazon S3 Raw Storage Bucket",
    "storage.googleapis.com": "Google Cloud Storage Bucket",
    "onrender.com": "Render PaaS",
    "loca.lt": "Localtunnel Gateway",
}

# Known URL shorteners that conceal destination URLs
URL_SHORTENERS: set = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "shorturl.at", "rebrand.ly", "rb.gy", "tiny.cc", "goo.gl"
}


def resolve_dns(hostname: str) -> Dict[str, Any]:
    """
    Performs live DNS A/AAAA resolution and reverse DNS lookup to identify
    IP addresses and hosting infrastructure.
    """
    clean_host = hostname.split(":")[0].strip("[]")
    
    result = {
        "resolved": False,
        "ips": [],
        "primary_ip": None,
        "reverse_dns": None,
        "dns_status": "UNRESOLVED",
        "error": None,
    }

    if not clean_host:
        result["dns_status"] = "EMPTY_HOST"
        return result

    try:
        # Resolve all IPv4 addresses
        _, _, ip_list = socket.gethostbyname_ex(clean_host)
        if ip_list:
            result["resolved"] = True
            result["ips"] = ip_list
            result["primary_ip"] = ip_list[0]
            result["dns_status"] = "RESOLVED"

            # Reverse DNS lookup on the primary IP to infer ISP / hosting provider
            try:
                rev_host, _, _ = socket.gethostbyaddr(ip_list[0])
                result["reverse_dns"] = rev_host
            except Exception:
                result["reverse_dns"] = "PTR record unavailable"

    except socket.gaierror as e:
        result["dns_status"] = "NXDOMAIN (Non-Existent / Inactive)"
        result["error"] = f"DNS resolution failed: {e.strerror or str(e)}"
    except socket.herror as e:
        result["dns_status"] = "HOST_ERROR"
        result["error"] = f"Host lookup error: {str(e)}"
    except Exception as e:
        result["dns_status"] = "RESOLUTION_FAILED"
        result["error"] = str(e)

    return result


def inspect_ssl(hostname: str, port: int = 443, timeout: float = 2.5) -> Dict[str, Any]:
    """
    Connects to the server over TLS to extract certificate authenticity, issuer,
    expiration, and subject alternative names (SANs).
    """
    clean_host = hostname.split(":")[0].strip("[]")
    
    result = {
        "has_ssl": False,
        "issuer_org": None,
        "issuer_cn": None,
        "subject_cn": None,
        "not_after": None,
        "days_remaining": None,
        "san_domains": [],
        "is_expired": False,
        "ssl_status": "NO_SSL",
        "error": None,
    }

    if not clean_host:
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result["has_ssl"] = True
                    result["ssl_status"] = "VALID_SSL"

                    # Parse Issuer info
                    issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                    result["issuer_org"] = issuer_dict.get("organizationName")
                    result["issuer_cn"] = issuer_dict.get("commonName")

                    # Parse Subject info
                    subject_dict = dict(x[0] for x in cert.get("subject", ()))
                    result["subject_cn"] = subject_dict.get("commonName")

                    # Parse Expiration
                    not_after_str = cert.get("notAfter")
                    result["not_after"] = not_after_str
                    if not_after_str:
                        try:
                            # Format: 'Dec 21 18:38:32 2026 GMT'
                            exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                            remaining = (exp_date - datetime.utcnow()).days
                            result["days_remaining"] = remaining
                            if remaining < 0:
                                result["is_expired"] = True
                                result["ssl_status"] = "EXPIRED_CERT"
                        except Exception:
                            pass

                    # Parse SANs (Subject Alternative Names)
                    sans = cert.get("subjectAltName", ())
                    result["san_domains"] = [val for typ, val in sans if typ.lower() == "dns"][:10]

    except ssl.SSLCertVerificationError as e:
        result["ssl_status"] = "UNTRUSTED / SELF-SIGNED"
        result["error"] = f"SSL Verification failed: {e.verify_message or str(e)}"
    except ssl.SSLError as e:
        result["ssl_status"] = "SSL_ERROR"
        result["error"] = f"TLS handshake failed: {str(e)}"
    except (socket.timeout, TimeoutError):
        result["ssl_status"] = "CONNECTION_TIMEOUT"
        result["error"] = "SSL connection timed out."
    except Exception as e:
        result["ssl_status"] = "CONNECT_FAILED"
        result["error"] = f"Could not establish TLS connection: {str(e)}"

    return result


def probe_http(url: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Sends a non-intrusive HEAD/GET HTTP request to observe response codes,
    detect redirect chains (shortener unmasking), and inspect security headers.
    """
    result = {
        "is_alive": False,
        "status_code": None,
        "final_url": url,
        "redirect_count": 0,
        "redirect_history": [],
        "server_header": None,
        "has_hsts": False,
        "has_x_frame_options": False,
        "latency_ms": None,
        "error": None,
    }

    start_time = time.time()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    try:
        # Use httpx with short timeout and redirect following
        with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
            try:
                resp = client.head(url)
            except Exception:
                # Some servers reject HEAD requests; fallback to a stream GET
                resp = client.get(url, headers=headers)

            latency = int((time.time() - start_time) * 1000)
            result["latency_ms"] = latency
            result["is_alive"] = True
            result["status_code"] = resp.status_code
            result["final_url"] = str(resp.url)
            result["redirect_count"] = len(resp.history)
            result["redirect_history"] = [str(r.url) for r in resp.history]

            resp_headers = resp.headers
            result["server_header"] = resp_headers.get("server")
            result["has_hsts"] = "strict-transport-security" in resp_headers
            result["has_x_frame_options"] = "x-frame-options" in resp_headers or "content-security-policy" in resp_headers

    except httpx.ConnectTimeout:
        result["error"] = "HTTP connection timed out (Server unresponsive)."
    except httpx.ConnectError:
        result["error"] = "Connection refused or host unreachable."
    except Exception as e:
        result["error"] = f"HTTP Probe error: {str(e)}"

    return result


def analyze_infrastructure_intelligence(
    url: str,
    hostname: str,
    heuristic_details: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Orchestrates live DNS, SSL, and HTTP infrastructure analysis.
    Computes an infrastructure risk score and generates forensic red flags.
    """
    clean_host = hostname.split(":")[0].strip("[]").lower()
    infra_red_flags: List[str] = []
    infra_risk_points = 0

    # 1. Real-time DNS Resolution
    dns_data = resolve_dns(clean_host)
    if not dns_data["resolved"]:
        if "NXDOMAIN" in dns_data.get("dns_status", ""):
            infra_red_flags.append("Domain does not resolve in public DNS (NXDOMAIN). Host may be newly created or already taken down by abuse response.")
            infra_risk_points += 25
        else:
            infra_red_flags.append(f"DNS resolution failure: {dns_data.get('error', 'Unresolved')}")
            infra_risk_points += 15

    # 2. Free Hosting / PaaS Provider Abuse Detection
    is_paas = False
    paas_name = None
    for domain_suffix, provider_label in SUSPICIOUS_PAAS_PROVIDERS.items():
        if clean_host.endswith(domain_suffix):
            is_paas = True
            paas_name = provider_label
            detected_brands = heuristic_details.get("detected_brands", [])
            matched_kw = heuristic_details.get("matched_keywords", [])

            if detected_brands or len(matched_kw) >= 2:
                infra_red_flags.append(
                    f"Hosted on free cloud service '{provider_label}' ({domain_suffix}) while targeting sensitive keywords/brands ({', '.join(detected_brands or matched_kw[:2])}). Classic free-tier phishing infrastructure."
                )
                infra_risk_points += 40
            else:
                infra_red_flags.append(f"Hosted on public serverless/free domain platform: {provider_label}.")
                infra_risk_points += 10
            break

    # 3. URL Shortener Redirection Evasion Check
    is_shortener = clean_host in URL_SHORTENERS
    if is_shortener:
        infra_red_flags.append(f"Known URL shortener service ({clean_host}) used to conceal true destination.")
        infra_risk_points += 20

    # 4. SSL / TLS Certificate Live Inspection (if HTTPS or standard web)
    ssl_data = inspect_ssl(clean_host)
    if ssl_data["has_ssl"]:
        # Check if certificate issuer matches targeted brand
        detected_brands = heuristic_details.get("detected_brands", [])
        issuer_str = (ssl_data.get("issuer_org") or ssl_data.get("issuer_cn") or "").lower()
        
        # If target brand is claimed but certificate is generic Let's Encrypt / ZeroSSL
        if detected_brands:
            brand = detected_brands[0].lower()
            if brand not in issuer_str and not any(brand in san.lower() for san in ssl_data.get("san_domains", [])):
                infra_red_flags.append(
                    f"SSL Certificate Mismatch: Claimed brand '{brand.title()}' does not appear in certificate issuer ('{ssl_data.get('issuer_org') or ssl_data.get('issuer_cn')}') or SAN domains."
                )
                infra_risk_points += 25

        if ssl_data.get("days_remaining") is not None and ssl_data["days_remaining"] < 14:
            infra_red_flags.append(f"Short SSL certificate lifespan ({ssl_data['days_remaining']} days remaining). Common in ephemeral phishing setups.")
            infra_risk_points += 10

        if ssl_data.get("is_expired"):
            infra_red_flags.append("SSL/TLS Certificate is EXPIRED. Connection is insecure.")
            infra_risk_points += 30
    elif ssl_data.get("ssl_status") in ("UNTRUSTED / SELF-SIGNED", "SSL_ERROR"):
        infra_red_flags.append(f"Untrusted or invalid SSL certificate: {ssl_data.get('error', 'Certificate verification failed')}.")
        infra_risk_points += 35

    # 5. Live HTTP Response & Redirect Tracker
    http_data = probe_http(url)
    probed_url = url
    http_fallback_used = False
    https_probe_error = None
    if (
        heuristic_details.get("scheme_was_missing")
        and not http_data.get("is_alive")
        and not ssl_data.get("has_ssl")
    ):
        https_probe_error = http_data.get("error")
        parsed_url = urlsplit(url)
        http_fallback_url = urlunsplit(
            ("http", parsed_url.netloc, parsed_url.path, parsed_url.query, parsed_url.fragment)
        )
        fallback_data = probe_http(http_fallback_url)
        if fallback_data.get("is_alive"):
            http_data = fallback_data
            probed_url = http_fallback_url
            http_fallback_used = True
            infra_red_flags.append(
                "HTTPS could not be verified; the site responded over the HTTP fallback."
            )
            infra_risk_points += 15

    http_redirected_to_https = (
        http_data.get("is_alive")
        and http_data.get("redirect_count", 0) > 0
        and urlsplit(probed_url).scheme.lower() == "http"
        and urlsplit(http_data.get("final_url", "")).scheme.lower() == "https"
    )
    https_version_available = False
    https_probe_data = None
    if urlsplit(url).scheme.lower() == "http" and not http_redirected_to_https:
        parsed_url = urlsplit(url)
        https_url = urlunsplit(
            ("https", parsed_url.netloc, parsed_url.path, parsed_url.query, parsed_url.fragment)
        )
        https_probe_data = probe_http(https_url)
        https_version_available = (
            https_probe_data.get("is_alive")
            and urlsplit(https_probe_data.get("final_url", "")).scheme.lower() == "https"
        )

    if http_data["redirect_count"] >= 2:
        infra_red_flags.append(f"Multiple redirect hops ({http_data['redirect_count']} redirects) observed leading to '{http_data['final_url']}'.")
        infra_risk_points += 15

    if http_data.get("is_alive") and not http_data.get("has_hsts") and heuristic_details.get("matched_keywords"):
        infra_red_flags.append("Missing Strict-Transport-Security (HSTS) header on page requesting sensitive credentials.")
        infra_risk_points += 8

    final_infra_score = min(infra_risk_points, 100)

    return {
        "dns": dns_data,
        "ssl": ssl_data,
        "http": http_data,
        "http_redirected_to_https": http_redirected_to_https,
        "https_version_available": https_version_available,
        "https_probe": https_probe_data,
        "http_fallback_used": http_fallback_used,
        "https_probe_error": https_probe_error,
        "is_paas_abuse": is_paas,
        "paas_provider": paas_name,
        "is_shortener": is_shortener,
        "infra_risk_score": final_infra_score,
        "infra_red_flags": infra_red_flags,
    }
