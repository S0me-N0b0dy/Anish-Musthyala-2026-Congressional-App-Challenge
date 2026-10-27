"""
gemini_analyzer.py - AI URL security and threat evaluation using Google Gemini API.
Uses the official google-genai SDK to analyze brand impersonation, deceptive paths,
and social engineering tactics with structured outputs.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from google import genai
from google.genai import types
from google.genai.errors import APIError
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class BrandImpersonationDetails(BaseModel):
    is_impersonating: bool = Field(
        description="True if the URL attempts to impersonate, mimic, or spoof an established brand, organization, or service."
    )
    targeted_brand: Optional[str] = Field(
        None,
        description="The brand or institution targeted (e.g., 'PayPal', 'Apple', 'Chase', 'Google', or None if not applicable)."
    )
    spoofing_technique: Optional[str] = Field(
        None,
        description="Deception mechanism used (e.g., 'Typosquatting', 'Subdomain spoofing', 'Deceptive path', 'TLD substitution', 'None')."
    )


class PhishGuardAIReport(BaseModel):
    risk_level: str = Field(
        description="Must be one of: 'Safe', 'Suspicious', or 'High Risk'."
    )
    risk_score: int = Field(
        description="Numerical risk rating from 0 (completely legitimate) to 100 (confirmed phishing/scam)."
    )
    verdict_headline: str = Field(
        description="A concise threat title (e.g., 'Probable PayPal Credential Harvesting Page', 'Legitimate Documentation Portal')."
    )
    summary: str = Field(
        description="A clear 2-3 sentence overview explaining what the URL is and why it received this assessment."
    )
    red_flags: List[str] = Field(
        description="A bulleted list of specific threat indicators, deceptive patterns, or anomalies identified."
    )
    brand_impersonation: BrandImpersonationDetails
    social_engineering_tactics: List[str] = Field(
        description="List of social engineering tactics (e.g., 'Urgent security alert', 'Account suspension threat', 'Credential harvesting')."
    )
    recommendation: str = Field(
        description="A short, user-friendly recommendation advising whether to proceed, avoid, or report."
    )


SYSTEM_INSTRUCTION = """You are a senior cybersecurity threat intelligence analyst and anti-phishing specialist for "PhishGuard".
Your objective is to examine suspicious or unfamiliar URLs and determine whether they represent legitimate websites, deceptive traps, brand spoofing campaigns, or phishing infrastructure.

You will be provided with:
1. The raw and normalized URL.
2. A breakdown of domain components (protocol, root domain, second-level domain, top-level domain, subdomains, path, query).
3. Findings from a rule-based structural heuristic scanner (typosquatting, character substitutions, suspicious TLDs, length anomalies, IP usage).

Carefully evaluate:
- If the input omits a scheme, the scanner normalizes it to HTTPS. The omitted scheme alone is not evidence of risk; assess the normalized URL and observed connection results.
- Brand impersonation: Is an established trademark or company name used in a misleading hostname or lookalike domain to fool users? A brand name in a URL path alone is not evidence of impersonation; paths on third-party platforms (for example, github.com/organization/project) can identify user-generated content and do not establish the site's identity.
- Deceptive paths & trickery: Are terms like "login", "update", "verify", "secure", "billing", or "webscr" used to harvest credentials?
- Typosquatting / Homoglyphs: Are numbers swapped for letters (e.g. 0 for o, 1 for l), or are there close-edit misspellings?
- Legitimate context: Note that popular subdomains of legitimate platforms (e.g. docs.github.com, accounts.google.com) are legitimate and should NOT be falsely labeled as phishing.

Calibrate your risk score and risk level:
- "Safe" (0 - 29): Legitimate, verified domains of established companies or benign personal/developer websites with no deception.
- "Suspicious" (30 - 69): Unusual structure, aggressive tracking, questionable marketing domains, unencrypted sensitive actions, or ambiguous brands.
- "High Risk" (70 - 100): Clear brand impersonation, typosquatting of major institutions, credential harvesting patterns, or malicious phishing infrastructure.

Always output valid JSON conforming strictly to the required schema.
"""


def analyze_with_gemini(
    url: str,
    heuristic_results: Dict[str, Any],
    api_key: str,
    infra_results: Optional[Dict[str, Any]] = None,
    model_name: str = "gemini-2.5-flash",
) -> Dict[str, Any]:
    """
    Submits the URL, structural heuristics, and live infrastructure telemetry to Gemini API.
    Returns a standardized dictionary with the threat intelligence report.
    """
    if not api_key or not api_key.strip():
        return {
            "success": False,
            "error_type": "MISSING_KEY",
            "message": "Gemini API Key is required for deep AI threat analysis.",
            "report": None,
        }

    try:
        # Initialize Google GenAI client
        client = genai.Client(api_key=api_key.strip())

        # Construct prompt payload with live infrastructure telemetry
        infra_section = ""
        if infra_results:
            dns_info = infra_results.get("dns", {})
            ssl_info = infra_results.get("ssl", {})
            http_info = infra_results.get("http", {})
            infra_section = f"""
Live Infrastructure & Network Telemetry:
- DNS Resolution: {dns_info.get('dns_status')} (IPs: {dns_info.get('ips', [])})
- Reverse DNS / Host Provider: {dns_info.get('reverse_dns', 'Unknown')}
- SSL Certificate Status: {ssl_info.get('ssl_status')}
- SSL Certificate Issuer: {ssl_info.get('issuer_org') or ssl_info.get('issuer_cn') or 'None'}
- SSL Days Until Expiration: {ssl_info.get('days_remaining')}
- HTTP Probe Response: Status {http_info.get('status_code')}, Redirect Hops: {http_info.get('redirect_count')}
- Final Landing Destination: {http_info.get('final_url')}
- Verified HTTP-to-HTTPS redirect: {infra_results.get('http_redirected_to_https', False)}
- HTTPS version of the submitted HTTP URL is reachable: {infra_results.get('https_version_available', False)}
- HTTPS probe destination: {(infra_results.get('https_probe') or {}).get('final_url')}
- Do not treat an HTTP starting URL as an insecure final destination when the probe confirms a secure HTTPS destination. Do not claim an HTTP-to-HTTPS redirect unless that redirect was actually observed.
- Infrastructure Anomalies Detected: {json.dumps(infra_results.get('infra_red_flags', []), indent=2)}
"""

        prompt_content = f"""Please perform an in-depth phishing and cyber threat evaluation of the following URL:

Target URL: {url}
Normalized URL: {heuristic_results.get('normalized_url', url)}

Pre-processing Heuristic Scanner Findings:
- Baseline Heuristic Risk Score: {heuristic_results.get('heuristic_score', 0)} / 100
- Baseline Heuristic Level: {heuristic_results.get('heuristic_level', 'Unknown')}
- Structural Red Flags Detected: {json.dumps(heuristic_results.get('red_flags', []), indent=2)}
- Parsed Domain Breakdown: {json.dumps(heuristic_results.get('details', {}), indent=2)}
{infra_section}
Evaluate the correlation between claimed brands, domain structure, and live infrastructure.
Provide your security verdict and structured analysis conforming strictly to the schema.
"""

        # Set up generation configuration with structured JSON output
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            temperature=0.1,  # Low temperature for deterministic security scoring
            response_mime_type="application/json",
            response_schema=PhishGuardAIReport,
        )

        # Call Gemini model (try selected model, fallback if needed)
        models_to_try = [model_name]
        if model_name != "gemini-1.5-flash":
            models_to_try.append("gemini-1.5-flash")

        last_error = None
        response = None

        for m in models_to_try:
            try:
                response = client.models.generate_content(
                    model=m,
                    contents=prompt_content,
                    config=config,
                )
                if response and response.text:
                    break
            except Exception as e:
                last_error = e
                logger.warning(f"Model {m} failed: {e}. Trying fallback if available.")

        if not response or not response.text:
            raise last_error or RuntimeError("Empty response received from Gemini API.")

        # Parse JSON into dict
        parsed_data = json.loads(response.text)

        # Normalize risk_level capitalization
        risk_lvl = parsed_data.get("risk_level", "Suspicious").strip().title()
        if risk_lvl not in ("Safe", "Suspicious", "High Risk"):
            risk_score = parsed_data.get("risk_score", 50)
            if risk_score >= 70:
                risk_lvl = "High Risk"
            elif risk_score >= 30:
                risk_lvl = "Suspicious"
            else:
                risk_lvl = "Safe"
        parsed_data["risk_level"] = risk_lvl

        # Clamp risk score
        parsed_data["risk_score"] = max(0, min(100, int(parsed_data.get("risk_score", 0))))

        return {
            "success": True,
            "error_type": None,
            "message": "AI analysis complete.",
            "report": parsed_data,
        }

    except APIError as e:
        error_msg = f"Gemini API Error: {getattr(e, 'message', str(e))}"
        return {
            "success": False,
            "error_type": "API_ERROR",
            "message": error_msg,
            "report": None,
        }
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error_type": "PARSE_ERROR",
            "message": f"Failed to parse Gemini JSON output: {str(e)}",
            "report": None,
        }
    except Exception as e:
        return {
            "success": False,
            "error_type": "UNKNOWN_ERROR",
            "message": f"Analysis error: {str(e)}",
            "report": None,
        }
