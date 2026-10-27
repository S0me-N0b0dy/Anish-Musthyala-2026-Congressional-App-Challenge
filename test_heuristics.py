"""
Unit test suite for heuristics module in PhishGuard.
Tests edge cases, legitimate sites, typosquatting, and malicious URL patterns.
"""

from heuristics import analyze_heuristics
import network_intel
import threat_engine
from threat_engine import synthesize_standalone_assessment


def test_scheme_less_url_defaults_to_https_without_missing_scheme_penalty():
    without_scheme = analyze_heuristics("google.com")
    with_https = analyze_heuristics("https://www.google.com")

    assert without_scheme["normalized_url"] == "https://google.com"
    assert without_scheme["details"]["scheme_was_missing"] is True
    assert without_scheme["heuristic_score"] == 0
    assert without_scheme["heuristic_score"] == with_https["heuristic_score"]


def test_scheme_less_url_uses_labeled_http_fallback_only_after_https_fails(monkeypatch):
    probes = []
    monkeypatch.setattr(
        network_intel,
        "resolve_dns",
        lambda _: {"resolved": True, "ips": [], "primary_ip": None, "dns_status": "RESOLVED", "error": None},
    )
    monkeypatch.setattr(
        network_intel,
        "inspect_ssl",
        lambda _: {"has_ssl": False, "ssl_status": "CONNECTION_TIMEOUT"},
    )

    def probe_http(url):
        probes.append(url)
        return {
            "is_alive": url.startswith("http://"),
            "status_code": 200 if url.startswith("http://") else None,
            "final_url": url,
            "redirect_count": 0,
            "error": None if url.startswith("http://") else "HTTPS probe failed",
            "has_hsts": False,
        }

    monkeypatch.setattr(network_intel, "probe_http", probe_http)

    result = network_intel.analyze_infrastructure_intelligence(
        "https://example.com/path",
        "example.com",
        {"scheme_was_missing": True, "matched_keywords": []},
    )

    assert probes == ["https://example.com/path", "http://example.com/path"]
    assert result["http_fallback_used"] is True
    assert result["http"]["final_url"] == "http://example.com/path"
    assert any("HTTPS could not be verified" in flag for flag in result["infra_red_flags"])


def test_http_url_redirecting_to_https_is_marked_verified(monkeypatch):
    monkeypatch.setattr(
        network_intel,
        "resolve_dns",
        lambda _: {"resolved": True, "ips": [], "primary_ip": None, "dns_status": "RESOLVED", "error": None},
    )
    monkeypatch.setattr(
        network_intel,
        "inspect_ssl",
        lambda _: {"has_ssl": True, "ssl_status": "VALID_SSL", "days_remaining": 90},
    )
    monkeypatch.setattr(
        network_intel,
        "probe_http",
        lambda _: {
            "is_alive": True,
            "status_code": 200,
            "final_url": "https://www.google.com/",
            "redirect_count": 1,
            "redirect_history": ["http://google.com"],
            "has_hsts": True,
            "error": None,
        },
    )

    result = network_intel.analyze_infrastructure_intelligence(
        "http://google.com",
        "google.com",
        {"scheme_was_missing": False, "matched_keywords": []},
    )

    assert result["http_redirected_to_https"] is True


def test_verified_https_removes_only_http_heuristic_penalty():
    heuristic_res = analyze_heuristics("http://google.com")
    infra_res = {
        "https_version_available": True,
        "infra_risk_score": 0,
        "dns": {"resolved": True, "dns_status": "RESOLVED", "primary_ip": "192.0.2.1"},
        "ssl": {"has_ssl": True, "issuer_org": "Example CA", "san_domains": ["www.google.com"]},
        "http": {"final_url": "https://www.google.com/", "redirect_count": 1},
        "infra_red_flags": [],
    }

    adjusted = threat_engine.account_for_verified_https(heuristic_res, infra_res)
    assessment = synthesize_standalone_assessment("http://google.com", adjusted, infra_res)

    assert adjusted["heuristic_score"] == 0
    assert adjusted["red_flags"] == []
    assert assessment["risk_score"] == 0


def test_http_url_probes_https_version_when_no_https_redirect_is_observed(monkeypatch):
    probes = []
    monkeypatch.setattr(
        network_intel,
        "resolve_dns",
        lambda _: {"resolved": True, "ips": [], "primary_ip": None, "dns_status": "RESOLVED", "error": None},
    )
    monkeypatch.setattr(
        network_intel,
        "inspect_ssl",
        lambda _: {"has_ssl": True, "ssl_status": "VALID_SSL", "days_remaining": 90},
    )

    def probe_http(url):
        probes.append(url)
        final_url = "http://www.google.com/" if url.startswith("http://") else url
        return {
            "is_alive": True,
            "status_code": 200,
            "final_url": final_url,
            "redirect_count": 1 if url == "http://google.com" else 0,
            "redirect_history": ["http://google.com"] if url == "http://google.com" else [],
            "has_hsts": False,
            "error": None,
        }

    monkeypatch.setattr(network_intel, "probe_http", probe_http)

    result = network_intel.analyze_infrastructure_intelligence(
        "http://google.com",
        "google.com",
        {"scheme_was_missing": False, "matched_keywords": []},
    )

    assert probes == ["http://google.com", "https://google.com"]
    assert result["http_redirected_to_https"] is False
    assert result["https_version_available"] is True


def test_pipeline_removes_gemini_http_penalty_after_verified_https_redirect(monkeypatch):
    url = "http://google.com"
    heuristic_res = analyze_heuristics(url)
    infra_res = {
        "https_version_available": True,
        "infra_risk_score": 0,
        "dns": {"resolved": True, "dns_status": "RESOLVED", "primary_ip": "192.0.2.1"},
        "ssl": {"has_ssl": True, "issuer_org": "Example CA", "san_domains": ["www.google.com"]},
        "http": {"final_url": "https://www.google.com/", "redirect_count": 1},
        "infra_red_flags": [],
    }
    gemini_report = {
        "risk_level": "Safe",
        "risk_score": 8,
        "verdict_headline": "Safe website",
        "summary": "Redirects to HTTPS.",
        "red_flags": ["Insecure HTTP protocol used before redirecting to HTTPS."],
        "brand_impersonation": {"is_impersonating": False, "targeted_brand": None},
        "social_engineering_tactics": [],
        "recommendation": "Proceed safely.",
    }

    monkeypatch.setattr(threat_engine, "analyze_heuristics", lambda _: heuristic_res)
    monkeypatch.setattr(
        threat_engine,
        "analyze_infrastructure_intelligence",
        lambda **_: infra_res,
    )

    def analyze_with_gemini(**kwargs):
        assert kwargs["heuristic_results"]["heuristic_score"] == 0
        return {"success": True, "report": gemini_report}

    monkeypatch.setattr(threat_engine, "analyze_with_gemini", analyze_with_gemini)

    result = threat_engine.execute_threat_intelligence_pipeline(url, api_key="test-key")

    assert result["assessment"]["risk_score"] == 0
    assert result["assessment"]["risk_level"] == "Safe"
    assert result["assessment"]["red_flags"] == []

    gemini_report["red_flags"] = []
    result = threat_engine.execute_threat_intelligence_pipeline(url, api_key="test-key")

    assert result["assessment"]["risk_score"] == 0
    assert result["assessment"]["risk_level"] == "Safe"


def test_safe_urls():
    safe_urls = [
        "https://www.google.com",
        "https://github.com/microsoft/vscode",
        "https://accounts.google.com/signin",
        "https://www.apple.com/shop",
        "https://www.paypal.com/signin",
    ]
    for url in safe_urls:
        res = analyze_heuristics(url)
        assert res["valid"], f"Should be valid: {url}"
        assert res["heuristic_level"] in ("Safe", "Suspicious"), f"URL {url} got score {res['heuristic_score']} ({res['heuristic_level']})"
        print(f"[PASS] Safe URL: {url} -> Score: {res['heuristic_score']} ({res['heuristic_level']})")


def test_brand_name_in_repository_path_is_not_impersonation():
    url = "https://github.com/microsoft/vscode"
    heuristic_res = analyze_heuristics(url)

    assert heuristic_res["valid"]
    assert "microsoft" not in heuristic_res["details"]["detected_brands"]
    assert heuristic_res["heuristic_score"] < 30

    assessment = synthesize_standalone_assessment(
        url,
        heuristic_res,
        {
            "infra_risk_score": 0,
            "dns": {"resolved": True, "dns_status": "RESOLVED", "primary_ip": "192.0.2.1"},
            "ssl": {
                "has_ssl": True,
                "issuer_org": "DigiCert Inc",
                "san_domains": ["github.com"],
            },
            "http": {},
            "infra_red_flags": [],
        },
    )

    assert assessment["risk_score"] < 30
    assert assessment["brand_impersonation"]["is_impersonating"] is False


def test_gemini_cannot_override_clean_github_repository_assessment(monkeypatch):
    url = "https://github.com/microsoft/vscode"
    heuristic_res = analyze_heuristics(url)
    infra_res = {
        "infra_risk_score": 0,
        "dns": {"resolved": True, "dns_status": "RESOLVED", "primary_ip": "192.0.2.1"},
        "ssl": {
            "has_ssl": True,
            "issuer_org": "DigiCert Inc",
            "san_domains": ["github.com"],
        },
        "http": {},
        "infra_red_flags": [],
    }
    gemini_report = {
        "risk_level": "High Risk",
        "risk_score": 85,
        "verdict_headline": "Microsoft impersonation",
        "summary": "Brand appears in the GitHub path.",
        "red_flags": ["Microsoft brand used on unrelated domain"],
        "brand_impersonation": {
            "is_impersonating": True,
            "targeted_brand": "Microsoft",
            "spoofing_technique": "Brand in URL path",
        },
        "social_engineering_tactics": [],
        "recommendation": "Avoid.",
    }
    monkeypatch.setattr(threat_engine, "analyze_heuristics", lambda _: heuristic_res)
    monkeypatch.setattr(
        threat_engine,
        "analyze_infrastructure_intelligence",
        lambda **_: infra_res,
    )
    monkeypatch.setattr(
        threat_engine,
        "analyze_with_gemini",
        lambda **_: {"success": True, "report": gemini_report},
    )

    result = threat_engine.execute_threat_intelligence_pipeline(url, api_key="test-key")

    assert result["assessment"]["risk_score"] < 30
    assert result["assessment"]["brand_impersonation"]["is_impersonating"] is False
    assert result["engine_used"] == "standalone_multivector"


def test_brand_name_in_suspicious_subdomain_is_still_flagged():
    res = analyze_heuristics("https://microsoft.github.com.example.com/login")

    assert res["valid"]
    assert "microsoft" in res["details"]["detected_brands"]
    assert res["heuristic_score"] >= 30


def test_typosquatting_urls():
    typosquat_urls = [
        ("http://paypa1-security.com/login", "paypa1"),
        ("http://micr0s0ft-support.xyz", "micr0s0ft"),
        ("http://amaz0n-delivery-check.com", "amaz0n"),
    ]
    for url, brand_typo in typosquat_urls:
        res = analyze_heuristics(url)
        assert res["valid"]
        assert res["heuristic_score"] >= 30, f"{url} should have elevated score, got {res['heuristic_score']}"
        assert any("substitution" in flag.lower() or "typosquatting" in flag.lower() or "brand" in flag.lower() for flag in res["red_flags"])
        print(f"[PASS] Typosquat URL: {url} -> Score: {res['heuristic_score']} ({res['heuristic_level']}) Flags: {len(res['red_flags'])}")


def test_subdomain_spoofing():
    url = "http://paypal.com.account-verification-alert.com/login.php"
    res = analyze_heuristics(url)
    assert res["valid"]
    assert res["heuristic_score"] >= 60, f"Expected high score, got {res['heuristic_score']}"
    assert any("subdomain" in flag.lower() for flag in res["red_flags"])
    print(f"[PASS] Subdomain Spoof: {url} -> Score: {res['heuristic_score']} ({res['heuristic_level']})")


def test_ip_address_host():
    url = "http://192.168.1.100/chase/online/login.html"
    res = analyze_heuristics(url)
    assert res["valid"]
    assert res["details"]["is_ip"] is True
    assert res["heuristic_score"] >= 40
    print(f"[PASS] IP Address: {url} -> Score: {res['heuristic_score']} ({res['heuristic_level']})")


def test_at_symbol_spoofing():
    url = "http://apple.com@security-check-portal.top/auth"
    res = analyze_heuristics(url)
    assert res["valid"]
    assert any("@" in flag for flag in res["red_flags"])
    print(f"[PASS] '@' Spoofing: {url} -> Score: {res['heuristic_score']} ({res['heuristic_level']})")


if __name__ == "__main__":
    print("Running Heuristics Test Suite...")
    test_safe_urls()
    test_brand_name_in_repository_path_is_not_impersonation()
    test_brand_name_in_suspicious_subdomain_is_still_flagged()
    test_typosquatting_urls()
    test_subdomain_spoofing()
    test_ip_address_host()
    test_at_symbol_spoofing()
    print("All heuristic tests passed successfully!")
