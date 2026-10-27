"""
heuristics.py - URL structural and heuristic pre-processing module for PhishGuard.
Extracts basic structural red flags, domain properties, typosquatting patterns,
and computes a baseline risk score before consulting Gemini AI.
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

# Common targets frequently impersonated in phishing attacks
TARGET_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "accounts.google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "dropbox": ["dropbox.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "roblox": ["roblox.com"],
    "telegram": ["telegram.org", "t.me"],
    "yahoo": ["yahoo.com"],
    "linkedin": ["linkedin.com"],
    "revolut": ["revolut.com"],
    "venmo": ["venmo.com"],
    "ebay": ["ebay.com"],
    "walmart": ["walmart.com"],
    "spotify": ["spotify.com"],
}

# Suspicious / High-Abuse TLDs frequently observed in phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "work", "buzz", "cc", "tk", "ml", "ga", "cf", "gq",
    "fit", "rest", "icu", "sbs", "surf", "click", "link", "live", "loan",
    "cam", "monster", "vip", "cfd", "online", "site", "bid", "pw"
}

# Phishing / Social engineering keywords
SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "signin", "log-in", "sign-in", "verify", "verification",
    "update", "security", "secure", "account", "banking", "wallet",
    "confirm", "password", "credential", "auth", "recover", "suspended",
    "billing", "invoice", "support", "token", "passcode", "unlock",
    "limited", "kyc", "authenticate", "resolution", "alert"
]

# Common character substitution / leetspeak map
LEET_REPLACEMENTS: Dict[str, List[str]] = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["4", "@"],
    "s": ["5", "$"],
    "b": ["8"],
    "w": ["vv"],
    "m": ["rn"],
}


def normalize_url(raw_url: str) -> Tuple[str, bool]:
    """
    Cleans and normalizes user input.
    Returns (normalized_url, scheme_was_missing).
    """
    url = raw_url.strip()
    scheme_missing = False
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        # Prefer an encrypted connection when the user omits the scheme.
        url = "https://" + url
        scheme_missing = True
    return url, scheme_missing


def is_ip_address(host: str) -> bool:
    """Check if the hostname is an IPv4 or IPv6 address."""
    # Strip port if present
    clean_host = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def detect_character_substitution(text: str) -> List[str]:
    """Detects deliberate character substitutions like digits for letters (e.g. paypa1, micr0s0ft)."""
    substitutions_found = []
    # Test against each target brand
    lower_text = text.lower()
    for brand in TARGET_BRANDS:
        # Check if brand is already verbatim
        if brand in lower_text:
            continue

        # Reverse leet transformations on lower_text to see if brand appears
        normalized = lower_text
        normalized = normalized.replace("0", "o")
        normalized = normalized.replace("1", "l")
        normalized = normalized.replace("3", "e")
        normalized = normalized.replace("4", "a")
        normalized = normalized.replace("5", "s")
        normalized = normalized.replace("8", "b")
        normalized = normalized.replace("vv", "w")
        normalized = normalized.replace("rn", "m")

        if brand in normalized and brand not in lower_text:
            substitutions_found.append(f"Character substitution detected for brand '{brand}'")

    return substitutions_found


def split_domain(hostname: str) -> Dict[str, str]:
    """
    Extracts subdomain, second-level domain (SLD), and TLD from hostname.
    Handles standard domains and basic multi-part ccTLDs (.co.uk, .com.au, etc.).
    """
    clean_host = hostname.split(":")[0].lower().strip(".")
    if is_ip_address(clean_host):
        return {"subdomain": "", "sld": clean_host, "tld": "", "domain": clean_host}

    parts = clean_host.split(".")
    if len(parts) == 1:
        return {"subdomain": "", "sld": parts[0], "tld": "", "domain": parts[0]}

    # Check for known two-part TLD suffixes
    two_part_tlds = {"co.uk", "gov.uk", "org.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "co.nz"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_part_tlds:
        tld = f"{parts[-2]}.{parts[-1]}"
        sld = parts[-3]
        subdomain = ".".join(parts[:-3])
        domain = f"{sld}.{tld}"
    else:
        tld = parts[-1]
        sld = parts[-2]
        subdomain = ".".join(parts[:-2])
        domain = f"{sld}.{tld}"

    return {
        "subdomain": subdomain,
        "sld": sld,
        "tld": tld,
        "domain": domain
    }


def analyze_heuristics(raw_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive structural heuristic checks on a given URL.
    Returns a dictionary with risk score (0-100), risk level, list of red flags,
    and granular structural breakdown.
    """
    normalized_url, scheme_missing = normalize_url(raw_url)
    red_flags: List[str] = []
    score = 0

    try:
        parsed = urlsplit(normalized_url)
    except Exception as e:
        return {
            "valid": False,
            "error": f"Failed to parse URL: {str(e)}",
            "heuristic_score": 100,
            "heuristic_level": "High Risk",
            "red_flags": ["Malformed URL syntax cannot be parsed safely."],
            "details": {}
        }

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url_lower = normalized_url.lower()

    if not hostname:
        return {
            "valid": False,
            "error": "URL does not contain a valid hostname.",
            "heuristic_score": 100,
            "heuristic_level": "High Risk",
            "red_flags": ["Missing valid hostname or domain."],
            "details": {}
        }

    # 1. Scheme checks
    scheme = parsed.scheme.lower()
    if scheme == "http":
        red_flags.append("Insecure HTTP protocol used instead of encrypted HTTPS.")
        score += 15

    # 2. IP Address as Hostname
    has_ip = is_ip_address(hostname)
    if has_ip:
        red_flags.append(f"Direct IP address used as hostname ({hostname}) instead of a verified domain name.")
        score += 35

    # 3. Domain decomposition
    domain_info = split_domain(hostname)
    subdomain = domain_info["subdomain"]
    sld = domain_info["sld"]
    tld = domain_info["tld"]
    domain = domain_info["domain"]

    # 4. Length checks
    url_len = len(normalized_url)
    domain_len = len(hostname)

    if url_len > 120:
        red_flags.append(f"Excessive overall URL length ({url_len} characters) often used to conceal deceptive query strings or tokens.")
        score += 20
    elif url_len > 75:
        red_flags.append(f"Elevated URL length ({url_len} characters).")
        score += 10

    if domain_len > 35:
        red_flags.append(f"Extremely long domain name ({domain_len} characters) typically indicates keyword stuffing.")
        score += 15
    elif domain_len > 25:
        red_flags.append(f"Elevated domain name length ({domain_len} characters).")
        score += 5

    # 5. Hyphen frequency in hostname
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        red_flags.append(f"High number of hyphens ({hyphen_count}) in hostname, a common tactic to glue legitimate brand words together.")
        score += 25
    elif hyphen_count >= 2:
        red_flags.append(f"Multiple hyphens ({hyphen_count}) in hostname.")
        score += 10

    # 6. Subdomain analysis
    subdomain_parts = [p for p in subdomain.split(".") if p]
    subdomain_count = len(subdomain_parts)
    if subdomain_count >= 3:
        red_flags.append(f"Suspicious deep subdomain nesting ({subdomain_count} levels: '{subdomain}') used to mimic trusted service layouts.")
        score += 20
    elif subdomain_count >= 2:
        red_flags.append(f"Multiple subdomain levels detected ('{subdomain}').")
        score += 8

    # 7. Brand Impersonation in the Hostname
    detected_brands: List[str] = []
    brand_impersonations: List[str] = []

    for brand, legit_domains in TARGET_BRANDS.items():
        # URL paths can be arbitrary content on a third-party host, so only
        # hostname claims count as evidence of brand impersonation.
        brand_in_sub = brand in subdomain.lower()
        brand_in_sld = brand in sld.lower()

        # Is the current domain actually an authorized domain for that brand?
        is_legit_domain = any(domain == legit or domain.endswith("." + legit) for legit in legit_domains)

        if brand_in_sub and not is_legit_domain:
            detected_brands.append(brand)
            brand_impersonations.append(f"Brand '{brand}' appears in subdomain ('{subdomain}'), but registered domain is '{domain}'.")
            score += 35
        elif brand_in_sld and not is_legit_domain:
            # Brand is inside SLD but not the official domain (e.g., paypal-verify.com)
            detected_brands.append(brand)
            brand_impersonations.append(f"Target brand '{brand}' used in non-official registered domain '{domain}'.")
            score += 30

    red_flags.extend(brand_impersonations)

    # 8. Typosquatting / Character Substitution Check
    substitutions = detect_character_substitution(hostname)
    if substitutions:
        red_flags.extend(substitutions)
        score += 35

    # Levenshtein distance check against target brands
    for brand in TARGET_BRANDS:
        if sld and sld != brand and len(sld) >= 4:
            dist = levenshtein_distance(sld, brand)
            if dist == 1:
                red_flags.append(f"Probable typosquatting: domain '{sld}' is an edit distance of 1 from known brand '{brand}'.")
                score += 40
            elif dist == 2 and len(brand) >= 6:
                red_flags.append(f"Potential typosquatting: domain '{sld}' is highly similar to brand '{brand}'.")
                score += 20

    # 9. Suspicious TLD check
    if tld in SUSPICIOUS_TLDS:
        red_flags.append(f"High-abuse top-level domain (.{tld}) commonly associated with low-cost spam and phishing operations.")
        score += 20

    # 10. '@' symbol check (userinfo credential spoofing)
    if "@" in normalized_url:
        red_flags.append("Contains '@' symbol: browsers treat text before '@' as user credentials, tricking users about the actual destination.")
        score += 40

    # 11. Non-standard ports
    if parsed.port and parsed.port not in (80, 443):
        red_flags.append(f"Unusual non-standard web port ({parsed.port}) specified.")
        score += 15

    # 12. Phishing & sensitive keywords in path or subdomain
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if len(matched_keywords) >= 3:
        red_flags.append(f"Multiple high-risk security keywords in URL: {', '.join(matched_keywords[:4])}.")
        score += 20
    elif len(matched_keywords) >= 1 and (hyphen_count >= 1 or brand_impersonations or has_ip or scheme == "http"):
        red_flags.append(f"Sensitive security keywords ({', '.join(matched_keywords[:3])}) coupled with suspicious URL structure.")
        score += 15

    # 13. Double slash in path or consecutive dots
    if "//" in path:
        red_flags.append("Double slash '//' detected in URL path, frequently used for open redirect evasion.")
        score += 15
    if ".." in hostname or ".." in path:
        red_flags.append("Consecutive dots ('..') detected, suggesting directory traversal or domain obfuscation.")
        score += 25

    # Cap heuristic score at 100 and determine risk level
    final_score = min(score, 100)
    if final_score >= 70:
        heuristic_level = "High Risk"
    elif final_score >= 30:
        heuristic_level = "Suspicious"
    else:
        heuristic_level = "Safe"

    return {
        "valid": True,
        "normalized_url": normalized_url,
        "heuristic_score": final_score,
        "heuristic_level": heuristic_level,
        "red_flags": red_flags,
        "details": {
            "scheme": scheme,
            "hostname": hostname,
            "domain": domain,
            "sld": sld,
            "tld": tld,
            "subdomain": subdomain,
            "subdomain_levels": subdomain_count,
            "path": path,
            "query": query,
            "port": parsed.port,
            "is_ip": has_ip,
            "url_length": url_len,
            "domain_length": domain_len,
            "hyphen_count": hyphen_count,
            "matched_keywords": matched_keywords,
            "detected_brands": list(set(detected_brands)),
            "scheme_was_missing": scheme_missing,
        }
    }
