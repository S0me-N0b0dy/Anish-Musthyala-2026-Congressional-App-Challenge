"""
threat_engine.py - Multi-Vector Threat Intelligence Engine for PhishGuard.
Integrates Lexical Heuristics, Live DNS/Network Telemetry, SSL/TLS Cryptography,
and Gemini AI Forensics into a cohesive cyber threat intelligence assessment.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from heuristics import analyze_heuristics
from network_intel import analyze_infrastructure_intelligence
from gemini_analyzer import analyze_with_gemini


def is_clean_github_repository_url(
    url: str,
    heuristic_res: Dict[str, Any],
    infra_res: Dict[str, Any],
) -> bool:
    """Identify clean GitHub repository URLs where path text is not host identity."""
    parsed = urlsplit(url)
    path_parts = [part for part in parsed.path.split("/") if part]
    return (
        parsed.hostname == "github.com"
        and len(path_parts) == 2
        and heuristic_res.get("heuristic_score", 100) < 30
        and not heuristic_res.get("details", {}).get("detected_brands")
        and infra_res.get("infra_risk_score", 100) < 20
    )


def account_for_verified_https(
    heuristic_res: Dict[str, Any],
    infra_res: Dict[str, Any],
) -> Dict[str, Any]:
    """Remove the HTTP-only penalty when a live probe confirms an HTTPS destination."""
    insecure_http_flag = "Insecure HTTP protocol used instead of encrypted HTTPS."
    if (
        not (
            infra_res.get("http_redirected_to_https")
            or infra_res.get("https_version_available")
        )
        or insecure_http_flag not in heuristic_res.get("red_flags", [])
    ):
        return heuristic_res

    adjusted = dict(heuristic_res)
    adjusted["red_flags"] = [
        flag for flag in heuristic_res["red_flags"] if flag != insecure_http_flag
    ]
    adjusted["heuristic_score"] = max(0, heuristic_res.get("heuristic_score", 0) - 15)
    score = adjusted["heuristic_score"]
    adjusted["heuristic_level"] = (
        "High Risk" if score >= 70 else "Suspicious" if score >= 30 else "Safe"
    )
    return adjusted


def synthesize_standalone_assessment(
    url: str,
    heuristic_res: Dict[str, Any],
    infra_res: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Synthesizes a realistic, multi-vector threat intelligence assessment
    when running in local / standalone mode (without Gemini API key or as fallback).
    Combines lexical, infrastructure, DNS, and cryptographic evidence.
    """
    h_score = heuristic_res.get("heuristic_score", 0)
    i_score = infra_res.get("infra_risk_score", 0)
    det = heuristic_res.get("details", {})
    dns_info = infra_res.get("dns", {})
    ssl_info = infra_res.get("ssl", {})
    http_info = infra_res.get("http", {})

    detected_brands = det.get("detected_brands", [])
    has_brand = len(detected_brands) > 0
    target_brand = detected_brands[0].title() if has_brand else None
    
    # Check if SSL cert confirms brand authenticity (e.g. Google Trust Services for Google)
    issuer_str = (ssl_info.get("issuer_org") or ssl_info.get("issuer_cn") or "").lower()
    brand_verified_by_cert = False
    if has_brand and ssl_info.get("has_ssl"):
        b_lower = detected_brands[0].lower()
        if b_lower in issuer_str or any(b_lower in san.lower() for san in ssl_info.get("san_domains", [])):
            brand_verified_by_cert = True

    # Unified Red Flags compilation
    combined_red_flags: List[str] = []
    combined_red_flags.extend(heuristic_res.get("red_flags", []))
    combined_red_flags.extend(infra_res.get("infra_red_flags", []))

    # Weighting and score adjustment
    base_score = int(0.55 * h_score + 0.45 * i_score)

    # Special threat amplification logic
    is_impersonating = False
    spoof_technique = None

    if has_brand and not brand_verified_by_cert:
        is_impersonating = True
        spoof_technique = "Brand name detected on domain unverified by official SSL certificate"
        if h_score >= 40 or i_score >= 20:
            base_score = max(base_score, 85)
        else:
            base_score = max(base_score, 70)
    elif brand_verified_by_cert and h_score < 25:
        # Legitimate brand verified by SSL (e.g. google.com with Google Trust Services)
        base_score = min(base_score, 15)

    if "NXDOMAIN" in dns_info.get("dns_status", "") and (has_brand or h_score >= 35):
        base_score = max(base_score, 80)
        combined_red_flags.append(f"Domain '{det.get('domain')}' is inactive in DNS (NXDOMAIN). Typical of burned, taken-down, or pre-registered phishing campaigns.")

    final_score = max(0, min(100, base_score))

    # Classification
    if final_score >= 70:
        level = "High Risk"
        headline = f"Probable Phishing Campaign targeting {target_brand}" if has_brand else "Critical Cyber Threat / Deceptive URL"
        summary = (
            f"Multi-vector intelligence flagged this URL with a severe threat rating ({final_score}/100). "
            f"Evidence indicates deliberate brand impersonation ({target_brand}), deceptive domain layout, or hostile infrastructure."
            if has_brand else
            f"Multi-vector intelligence flagged this URL with a severe threat rating ({final_score}/100) due to "
            f"{len(combined_red_flags)} structural and network anomalies."
        )
        recommendation = "Do NOT visit or interact with this URL. High probability of credential harvesting, malware delivery, or social engineering."
    elif final_score >= 30:
        level = "Suspicious"
        headline = f"Suspicious Activity / Potential {target_brand} Spoof" if has_brand else "Suspicious Infrastructure & Domain Anomalies"
        summary = (
            f"Security scan identified anomalous structural and infrastructure characteristics (Risk Index: {final_score}/100). "
            f"The domain exhibits deceptive traits or unverified ownership."
        )
        recommendation = "Exercise caution. Verify the domain's SSL certificate and do not submit passwords or financial credentials."
    else:
        level = "Safe"
        headline = f"Verified Legitimate Domain ({target_brand or det.get('domain')})" if brand_verified_by_cert else f"Low Risk Domain ({det.get('domain')})"
        summary = (
            f"Multi-vector threat analysis confirmed benign characteristics (Threat Index: {final_score}/100). "
            f"DNS resolution is active ({dns_info.get('primary_ip', 'Active')}) and cryptographic certificates confirm legitimate ownership."
            if ssl_info.get("has_ssl") else
            f"No malicious or deceptive structural anomalies were detected (Threat Index: {final_score}/100)."
        )
        recommendation = "Domain appears legitimate. Follow standard safe browsing practices."

    return {
        "risk_level": level,
        "risk_score": final_score,
        "verdict_headline": headline,
        "summary": summary,
        "red_flags": combined_red_flags,
        "brand_impersonation": {
            "is_impersonating": is_impersonating,
            "targeted_brand": target_brand if is_impersonating else None,
            "spoofing_technique": spoof_technique,
            "brand_verified_by_cert": brand_verified_by_cert,
        },
        "social_engineering_tactics": [
            "Brand lookalike impersonation" if has_brand else "Deceptive link structure",
            "Urgent action / security lure" if any("login" in f.lower() or "verify" in f.lower() for f in combined_red_flags) else "Unverified destination"
        ] if final_score >= 40 else [],
        "recommendation": recommendation,
        "mode": "standalone_telemetry",
    }


def execute_threat_intelligence_pipeline(
    url: str,
    api_key: Optional[str] = None,
    model_name: str = "gemini-2.5-flash",
) -> Dict[str, Any]:
    """
    Main orchestration entrypoint for URL threat intelligence.
    Runs:
    1. Heuristic Pre-processing
    2. Live Network, DNS, SSL, and HTTP Infrastructure Telemetry
    3. AI Threat Forensics (if API key present) OR Multi-Vector Standalone Intelligence
    """
    # 1. Heuristics
    heuristic_res = analyze_heuristics(url)
    if not heuristic_res.get("valid", True):
        return {
            "valid": False,
            "error": heuristic_res.get("error", "Malformed URL"),
        }

    hostname = heuristic_res.get("details", {}).get("hostname", "")

    # 2. Live Infrastructure Telemetry
    infra_res = analyze_infrastructure_intelligence(
        url=heuristic_res.get("normalized_url", url),
        hostname=hostname,
        heuristic_details=heuristic_res.get("details", {})
    )
    heuristic_res = account_for_verified_https(heuristic_res, infra_res)

    # 3. Decision Pipeline: Gemini AI vs Standalone Multi-Vector
    has_api_key = bool(api_key and api_key.strip())
    ai_report = None
    engine_used = "standalone_multivector"

    if has_api_key:
        ai_res = analyze_with_gemini(
            url=url,
            heuristic_results=heuristic_res,
            api_key=api_key.strip(),
            infra_results=infra_res,
            model_name=model_name,
        )
        if ai_res and ai_res.get("success") and ai_res.get("report"):
            ai_report = ai_res["report"]
            engine_used = "gemini_multimodal"

    if ai_report and (
        infra_res.get("http_redirected_to_https")
        or infra_res.get("https_version_available")
    ):
        ai_report = dict(ai_report)
        original_flags = ai_report.get("red_flags", [])
        remaining_flags = [
            flag for flag in ai_report.get("red_flags", [])
            if "insecure http" not in flag.lower()
            and "unencrypted http" not in flag.lower()
        ]
        if len(remaining_flags) < len(original_flags):
            score = max(0, int(ai_report.get("risk_score", 0)) - 15)
            ai_report["risk_score"] = score
            ai_report["risk_level"] = (
                "High Risk" if score >= 70 else "Suspicious" if score >= 30 else "Safe"
            )
        elif (
            not remaining_flags
            and heuristic_res.get("heuristic_score", 0) == 0
            and infra_res.get("infra_risk_score", 0) == 0
            and not ai_report.get("brand_impersonation", {}).get("is_impersonating")
        ):
            ai_report["risk_score"] = 0
            ai_report["risk_level"] = "Safe"
        ai_report["red_flags"] = remaining_flags
        final_assessment = ai_report
        final_assessment["mode"] = "gemini_ai"
    elif ai_report and is_clean_github_repository_url(url, heuristic_res, infra_res):
        final_assessment = synthesize_standalone_assessment(
            url=url,
            heuristic_res=heuristic_res,
            infra_res=infra_res,
        )
        engine_used = "standalone_multivector"
    elif ai_report:
        final_assessment = ai_report
        final_assessment["mode"] = "gemini_ai"
    else:
        final_assessment = synthesize_standalone_assessment(
            url=url,
            heuristic_res=heuristic_res,
            infra_res=infra_res,
        )

    return {
        "valid": True,
        "target_url": url,
        "normalized_url": heuristic_res.get("normalized_url", url),
        "engine_used": engine_used,
        "assessment": final_assessment,
        "heuristic_res": heuristic_res,
        "infra_res": infra_res,
    }
