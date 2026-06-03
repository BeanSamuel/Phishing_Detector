"""
Unit Tests — Feature Extractor
Maintainer: 譚天皓
Run: pytest feature-extractor/tests/ -v
"""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from extractor import (
    extract_features,
    check_ip_in_url,
    check_url_length,
    check_at_symbol,
    check_subdomain_count,
    check_https_keyword_abuse,
)
from urllib.parse import urlparse


def parsed(url):
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url)


# ── Individual feature tests ──────────────────────────────────────────────────

def test_ip_detection_true():
    r = check_ip_in_url(parsed("http://125.98.3.123/login"), "http://125.98.3.123/login")
    assert r.value is True
    assert r.risk_weight > 0

def test_ip_detection_false():
    r = check_ip_in_url(parsed("https://google.com"), "https://google.com")
    assert r.value is False
    assert r.risk_weight == 0.0

def test_long_url_high():
    url = "http://a.com/" + "x" * 110
    r = check_url_length(parsed(url), url)
    assert r.risk_weight >= 0.7

def test_long_url_safe():
    url = "https://google.com/search?q=test"
    r = check_url_length(parsed(url), url)
    assert r.risk_weight == 0.0

def test_at_symbol_flagged():
    url = "http://legit.com@evil.com/path"
    r = check_at_symbol(parsed(url), url)
    assert r.value is True

def test_subdomain_count_high():
    url = "http://login.verify.paypal.fake.com/page"
    r = check_subdomain_count(parsed(url), url)
    assert r.value >= 3

def test_https_keyword_abuse_found():
    url = "http://https-paypal-secure-login.com/verify"
    r = check_https_keyword_abuse(parsed(url), url)
    assert r.risk_weight > 0


# ── Integration tests ─────────────────────────────────────────────────────────

def test_benign_url_low_risk():
    report = extract_features("https://www.google.com")
    assert report.risk_level == "Low"
    assert report.total_risk_score < 25

def test_obvious_phish_high_risk():
    report = extract_features("http://https-paypal-login.verify-account-update.com/login.php")
    assert report.risk_level in ("Medium", "High")

def test_ip_url_high_risk():
    report = extract_features("http://192.168.1.1/admin/login")
    # IP alone should give Medium+
    assert report.total_risk_score >= 20

def test_report_has_all_features():
    report = extract_features("https://example.com")
    assert len(report.features) > 0
    assert report.total_risk_score >= 0

def test_url_without_scheme():
    # Should not crash
    report = extract_features("google.com")
    assert report.risk_level in ("Low", "Medium", "High")
