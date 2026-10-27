"""
verify_app.py - Verification script for PhishGuard URL Threat Intelligence.
Tests:
1. Heuristic engine coverage & edge case handling
2. Live Infrastructure Intelligence (DNS, SSL, HTTP)
3. Multi-Vector Threat Engine synthesis
4. Gemini analyzer interface & structured schema validation
5. Streamlit server response & availability
"""

import urllib.request
from heuristics import analyze_heuristics
from network_intel import analyze_infrastructure_intelligence
from threat_engine import execute_threat_intelligence_pipeline
from gemini_analyzer import PhishGuardAIReport, analyze_with_gemini


def verify_heuristics():
    print("\n--- Verifying Heuristics Engine ---")
    test_cases = [
        ("https://www.google.com", "Safe", 0, 30),
        ("https://github.com/login", "Safe", 0, 30),
        ("http://paypa1-security.com", "Suspicious", 30, 85),
        ("http://paypal.com.secure-update-alert.xyz/auth", "High Risk", 70, 100),
        ("http://192.168.1.1/banking/login", "High Risk", 60, 100),
        ("http://apple.com@evil-site.top/login", "High Risk", 70, 100),
    ]

    for url, expected_level, min_score, max_score in test_cases:
        res = analyze_heuristics(url)
        assert res["valid"], f"URL {url} marked invalid!"
        score = res["heuristic_score"]
        level = res["heuristic_level"]
        assert min_score <= score <= max_score, f"{url}: Expected score {min_score}-{max_score}, got {score}"
        print(f"  [OK] {url:<55} -> Level: {level:<10} Score: {score}")

    print("Heuristics verification passed!")


def verify_infrastructure_intelligence():
    print("\n--- Verifying Infrastructure Intelligence (DNS, SSL, HTTP) ---")
    h = analyze_heuristics("https://www.google.com")
    infra = analyze_infrastructure_intelligence("https://www.google.com", h["details"]["hostname"], h["details"])
    assert infra["dns"]["resolved"] is True
    assert len(infra["dns"]["ips"]) > 0
    assert infra["ssl"]["has_ssl"] is True
    assert "Google" in (infra["ssl"]["issuer_org"] or "")
    assert infra["http"]["is_alive"] is True
    print(f"  [OK] DNS resolved: {infra['dns']['primary_ip']}")
    print(f"  [OK] SSL Issuer: {infra['ssl']['issuer_org']}")
    print(f"  [OK] HTTP Status: {infra['http']['status_code']} ({infra['http']['latency_ms']}ms)")
    print("Infrastructure intelligence verification passed!")


def verify_multi_vector_pipeline():
    print("\n--- Verifying Multi-Vector Threat Engine ---")
    res_safe = execute_threat_intelligence_pipeline("https://www.google.com", api_key=None)
    assert res_safe["valid"] is True
    assert res_safe["assessment"]["risk_level"] == "Safe"
    assert res_safe["assessment"]["risk_score"] < 25
    print(f"  [OK] Benign URL verification: {res_safe['assessment']['verdict_headline']} (Score: {res_safe['assessment']['risk_score']})")

    res_phish = execute_threat_intelligence_pipeline("http://paypa1-security.com", api_key=None)
    assert res_phish["valid"] is True
    assert res_phish["assessment"]["risk_level"] in ("Suspicious", "High Risk")
    assert res_phish["assessment"]["risk_score"] >= 65
    print(f"  [OK] Typosquat URL verification: {res_phish['assessment']['verdict_headline']} (Score: {res_phish['assessment']['risk_score']})")


def verify_gemini_interface():
    print("\n--- Verifying Gemini Analyzer Interface & Schema ---")
    res_no_key = analyze_with_gemini(
        url="http://paypa1.com",
        heuristic_results=analyze_heuristics("http://paypa1.com"),
        api_key="",
    )
    assert not res_no_key["success"]
    assert res_no_key["error_type"] == "MISSING_KEY"
    print("  [OK] Handled missing API key gracefully.")

    mock_payload = {
        "risk_level": "High Risk",
        "risk_score": 95,
        "verdict_headline": "PayPa1 Phishing & Credential Harvest",
        "summary": "This site uses typosquatting ('paypa1' with digit '1') to harvest credentials.",
        "red_flags": [
            "Character substitution '1' for 'l'",
            "Unencrypted HTTP connection",
            "Sensitive login keyword"
        ],
        "brand_impersonation": {
            "is_impersonating": True,
            "targeted_brand": "PayPal",
            "spoofing_technique": "Typosquatting"
        },
        "social_engineering_tactics": [
            "Urgent account verification",
            "Lookalike domain mimicry"
        ],
        "recommendation": "Do not enter passwords. Close the page immediately."
    }

    report = PhishGuardAIReport(**mock_payload)
    assert report.risk_score == 95
    assert report.risk_level == "High Risk"
    assert report.brand_impersonation.targeted_brand == "PayPal"
    print("  [OK] PhishGuardAIReport schema validates structured output accurately.")


def verify_server_health():
    print("\n--- Verifying Streamlit Web Server Status ---")
    req = urllib.request.Request("http://localhost:8501", headers={"User-Agent": "PhishGuard-Verifier/1.0"})
    with urllib.request.urlopen(req, timeout=5) as response:
        status = response.status
        content_type = response.headers.get("Content-Type", "")
        assert status == 200, f"Expected status 200, got {status}"
        assert "text/html" in content_type, f"Expected text/html, got {content_type}"
        print(f"  [OK] Streamlit server is responding: HTTP {status} ({content_type})")


if __name__ == "__main__":
    verify_heuristics()
    verify_infrastructure_intelligence()
    verify_multi_vector_pipeline()
    verify_gemini_interface()
    verify_server_health()
    print("\nAll application verifications completed successfully!")
