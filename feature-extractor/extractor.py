"""
Feature Extractor Module
========================
Maintainer: 譚天皓
Responsibility: Parse URLs and extract phishing heuristic features.

Design principle:
- Each feature is an independent, testable function.
- To ADD a new feature: implement a function returning FeatureResult,
  then register it in FEATURE_REGISTRY at the bottom of this file.
- No external API calls in this module (keep it fast & offline).
"""

from __future__ import annotations
import re
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Callable
from urllib.parse import urlparse

# ── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class FeatureResult:
    name: str
    value: bool | int | float | str
    risk_weight: float          # 0.0 (safe) → 1.0 (very suspicious)
    description: str            # Human-readable explanation

@dataclass
class ExtractionReport:
    url: str
    features: list[FeatureResult] = field(default_factory=list)
    total_risk_score: float = 0.0   # Weighted sum, 0–100
    risk_level: str = "Low"         # Low / Medium / High

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "features": [asdict(f) for f in self.features],
            "total_risk_score": round(self.total_risk_score, 2),
            "risk_level": self.risk_level,
        }


# ── Individual Feature Functions ─────────────────────────────────────────────
# Each function signature: (parsed_url: ParseResult, raw_url: str) → FeatureResult

def is_ip_hostname(hostname: str) -> bool:
    """Helper to check if a hostname is a bare IP address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def check_ip_in_url(parsed, raw_url: str) -> FeatureResult:
    """Flag if the hostname is a bare IPv4/IPv6 address."""
    hostname = parsed.hostname or ""
    is_ip = is_ip_hostname(hostname)
    return FeatureResult(
        name="ip_in_url",
        value=is_ip,
        risk_weight=0.9 if is_ip else 0.0,
        description="Hostname is a raw IP address — legitimate sites use domain names.",
    )


def check_url_length(parsed, raw_url: str) -> FeatureResult:
    """URLs > 75 chars are suspicious; > 100 chars are highly suspicious."""
    length = len(raw_url)
    if length > 100:
        weight = 0.7
    elif length > 75:
        weight = 0.4
    else:
        weight = 0.0
    return FeatureResult(
        name="url_length",
        value=length,
        risk_weight=weight,
        description=f"URL length is {length} characters. Attackers use long URLs to obscure paths.",
    )


def check_shortening_service(parsed, raw_url: str) -> FeatureResult:
    """Detect common URL shortening services that mask destinations."""
    SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "short.link", "rb.gy",
    }
    hostname = (parsed.hostname or "").lower()
    flagged = hostname in SHORTENERS
    return FeatureResult(
        name="url_shortener",
        value=flagged,
        risk_weight=0.7 if flagged else 0.0,
        description="URL shorteners are frequently used to hide malicious destinations.",
    )


def check_at_symbol(parsed, raw_url: str) -> FeatureResult:
    """@ in URL causes browser to ignore everything before it."""
    has_at = "@" in raw_url
    return FeatureResult(
        name="at_symbol_in_url",
        value=has_at,
        risk_weight=0.85 if has_at else 0.0,
        description="'@' in URL redirects browser to the post-@ domain, bypassing apparent domain.",
    )


def check_double_slash_redirect(parsed, raw_url: str) -> FeatureResult:
    """'//' appearing in the path (after scheme) signals redirect tricks."""
    path = parsed.path or ""
    has_redirect = "//" in path
    return FeatureResult(
        name="double_slash_redirect",
        value=has_redirect,
        risk_weight=0.6 if has_redirect else 0.0,
        description="Double slashes in path indicate a potential open redirect.",
    )


def check_subdomain_count(parsed, raw_url: str) -> FeatureResult:
    """Count subdomain depth; > 3 levels is suspicious."""
    hostname = parsed.hostname or ""
    if is_ip_hostname(hostname):
        return FeatureResult(
            name="subdomain_count",
            value=0,
            risk_weight=0.0,
            description="Hostname is an IP address; subdomain checks are not applicable.",
        )
    parts = hostname.split(".")
    # Subtract 2 for domain + TLD
    subdomain_count = max(0, len(parts) - 2)
    if subdomain_count >= 3:
        weight = 0.75
    elif subdomain_count == 2:
        weight = 0.35
    else:
        weight = 0.0
    return FeatureResult(
        name="subdomain_count",
        value=subdomain_count,
        risk_weight=weight,
        description=f"{subdomain_count} subdomain level(s). Stacked subdomains often mimic trusted brands.",
    )


def check_dash_in_domain(parsed, raw_url: str) -> FeatureResult:
    """Dashes in domain (e.g. paypal-login.com) are a common phishing trick."""
    hostname = parsed.hostname or ""
    if is_ip_hostname(hostname):
        return FeatureResult(
            name="dash_in_domain",
            value=False,
            risk_weight=0.0,
            description="Hostname is an IP address; dash checks are not applicable.",
        )
    # Only check the registered domain (exclude subdomains)
    parts = hostname.split(".")
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    has_dash = "-" in registered
    return FeatureResult(
        name="dash_in_domain",
        value=has_dash,
        risk_weight=0.55 if has_dash else 0.0,
        description="Dashes in the registered domain often fabricate legitimacy (e.g., paypal-secure.com).",
    )


def check_https_keyword_abuse(parsed, raw_url: str) -> FeatureResult:
    """
    Detect deceptive security keywords embedded in the domain/path
    (e.g., http://https-paypal-login.com or /secure-login/).
    """
    SUSPICIOUS_KEYWORDS = ["https", "secure", "login", "verify", "update", "account", "banking"]
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in hostname or kw in path]
    weight = min(0.1 * len(found), 0.8) if found else 0.0
    return FeatureResult(
        name="https_keyword_abuse",
        value=", ".join(found) if found else "none",
        risk_weight=weight,
        description=f"Suspicious keywords found: {found}. Attackers embed these to appear trustworthy.",
    )


def check_non_standard_port(parsed, raw_url: str) -> FeatureResult:
    """Non-standard ports (not 80/443) are unusual for legitimate web services."""
    port = parsed.port
    suspicious = port is not None and port not in (80, 443, None)
    return FeatureResult(
        name="non_standard_port",
        value=port if port else "default",
        risk_weight=0.5 if suspicious else 0.0,
        description=f"Port {port} — legitimate sites rarely use non-standard ports.",
    )


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]


def check_typosquatting(parsed, raw_url: str) -> FeatureResult:
    """Detect typosquatting of popular brands (e.g. go0gle.com, paypa1.com)."""
    hostname = (parsed.hostname or "").lower()
    if is_ip_hostname(hostname):
        return FeatureResult(
            name="typosquatting",
            value="none",
            risk_weight=0.0,
            description="Hostname is an IP address; typosquatting checks are not applicable.",
        )

    # Extract the domain name part (e.g. 'go0gle' from 'go0gle.com')
    parts = hostname.split(".")
    if len(parts) >= 2:
        domain_name = parts[-2]
    else:
        domain_name = hostname
        
    POPULAR_BRANDS = [
        "google", "paypal", "facebook", "apple", "microsoft", 
        "netflix", "amazon", "github", "yahoo", "instagram", 
        "twitter", "linkedin", "steam", "coinbase", "binance"
    ]
    
    # Helper for lookalike replacement normalization
    lookalike_map = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
        '8': 'b', '9': 'g', 'vv': 'w', 'rn': 'm', 'cl': 'd'
    }
    
    normalized_domain = domain_name
    for lookalike, original in lookalike_map.items():
        normalized_domain = normalized_domain.replace(lookalike, original)
        
    is_typo = False
    matched_brand = ""
    min_dist = 999
    
    for brand in POPULAR_BRANDS:
        # If it matches exactly, it is the real brand (e.g. google.com)
        if domain_name == brand:
            return FeatureResult(
                name="typosquatting",
                value="exact_match",
                risk_weight=0.0,
                description=f"Domain matches official brand: {brand}.",
            )
            
        # Check if it is a direct lookalike replacement (e.g. go0gle -> google)
        if normalized_domain == brand and domain_name != brand:
            is_typo = True
            matched_brand = brand
            min_dist = 1
            break
            
        # Check Levenshtein distance on normalized domain
        dist = levenshtein_distance(normalized_domain, brand)
        # Also check Levenshtein distance on raw domain name
        dist_raw = levenshtein_distance(domain_name, brand)
        
        current_min = min(dist, dist_raw)
        if current_min > 0 and current_min <= 2:
            is_typo = True
            matched_brand = brand
            min_dist = min(min_dist, current_min)
            
    if is_typo:
        weight = 0.85 if min_dist == 1 else 0.6
        return FeatureResult(
            name="typosquatting",
            value=f"lookalike_{matched_brand}",
            risk_weight=weight,
            description=f"Domain '{domain_name}' is a close lookalike of the famous brand '{matched_brand}' (typosquatting).",
        )
        
    return FeatureResult(
        name="typosquatting",
        value="none",
        risk_weight=0.0,
        description="No typosquatting of popular brands detected.",
    )


# ── Feature Registry ──────────────────────────────────────────────────────────
# To add a new feature: append its function here. Order affects nothing.

FEATURE_REGISTRY: list[Callable] = [
    check_ip_in_url,
    check_url_length,
    check_shortening_service,
    check_at_symbol,
    check_double_slash_redirect,
    check_subdomain_count,
    check_dash_in_domain,
    check_https_keyword_abuse,
    check_non_standard_port,
    check_typosquatting,
]


# ── Main Extractor ────────────────────────────────────────────────────────────

def extract_features(url: str) -> ExtractionReport:
    """
    Run all registered feature checks on a URL and return an ExtractionReport.
    
    Args:
        url: Raw URL string (with or without scheme)
    
    Returns:
        ExtractionReport with feature list, total score, and risk level
    """
    # Normalize: ensure scheme is present for urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    report = ExtractionReport(url=url)

    for checker in FEATURE_REGISTRY:
        try:
            result = checker(parsed, url)
            report.features.append(result)
        except Exception as e:
            # Graceful degradation — one bad checker doesn't crash the pipeline
            report.features.append(FeatureResult(
                name=checker.__name__,
                value="error",
                risk_weight=0.0,
                description=f"Feature check failed: {e}",
            ))

    # Compute total risk score (0–100)
    max_possible = 3.0
    raw_score = sum(f.risk_weight for f in report.features)
    report.total_risk_score = min((raw_score / max_possible) * 100, 100.0)

    # Classify risk level
    score = report.total_risk_score
    if score >= 50:
        report.risk_level = "High"
    elif score >= 25:
        report.risk_level = "Medium"
    else:
        report.risk_level = "Low"

    return report


# ── CLI Quick Test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    test_urls = [
        "https://www.google.com",
        "http://125.98.3.123/login.html",
        "http://https-paypal-login.verify-account-update.com/login.php",
        "https://bit.ly/3xYz",
        "http://secure-paypal.login.verify.update.com:8080/account@phish",
    ]
    for url in test_urls:
        r = extract_features(url)
        print(f"\n{'='*60}")
        print(f"URL    : {url}")
        print(f"Risk   : {r.risk_level} ({r.total_risk_score:.1f}/100)")
        for f in r.features:
            if f.risk_weight > 0:
                print(f"  ⚠  {f.name}: {f.value} (weight={f.risk_weight})")
