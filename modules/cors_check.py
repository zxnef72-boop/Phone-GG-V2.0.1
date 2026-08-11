"""
CORS misconfiguration checker — detek konfigurasi CORS yang terlalu permisif.
Memeriksa: wildcard origin, null origin, reflection, credentials with wildcard.
"""
from __future__ import annotations
import requests

ORIGINS_TO_TEST = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
    "https://sub.target.com",
    "http://localhost",
    "https://localhost",
]


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def check_cors(url: str, timeout: int = 2) -> dict:
    target = _normalize_url(url)

    result = {
        "url": target,
        "findings": [],
        "vulnerable": False,
        "severity": "info",
    }

    for origin in ORIGINS_TO_TEST:
        try:
            # OPTIONS preflight
            resp = requests.options(target, timeout=timeout, headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization,Content-Type",
            }, allow_redirects=False)

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            acah = resp.headers.get("Access-Control-Allow-Headers", "")

            finding = {
                "origin_tested": origin,
                "acao": acao,
                "acac": acac,
                "acam": acam,
                "acah": acah,
                "status": resp.status_code,
            }

            # Check for vulnerabilities
            issues = []
            if acao == "*":
                issues.append("Wildcard Access-Control-Allow-Origin — semua origin diizinkan")
                if acac.lower() == "true":
                    issues.append("KRITIKAL: Wildcard origin + credentials — CORS misconfiguration parah!")
                    result["severity"] = "critical"
                    result["vulnerable"] = True
                elif not result["vulnerable"]:
                    result["severity"] = "high"
                    result["vulnerable"] = True

            if acao == origin and origin not in ("null",):
                if "evil.com" in origin or "attacker" in origin:
                    issues.append("Origin reflection detected — server merefleksikan origin attacker")
                    result["severity"] = "high"
                    result["vulnerable"] = True

            if acao == "null":
                issues.append("Null origin diizinkan — bisa dieksploitasi via sandbox iframe")
                if not result["vulnerable"] or result["severity"] == "info":
                    result["severity"] = "medium"
                    result["vulnerable"] = True

            if acac.lower() == "true" and acao and acao != "*":
                if "evil.com" in acao or "attacker" in acao:
                    issues.append("Credentials allowed dengan origin attacker — sangat berbahaya")
                    result["severity"] = "critical"
                    result["vulnerable"] = True

            finding["issues"] = issues
            if issues:
                result["findings"].append(finding)

        except requests.RequestException:
            continue

    # Also check with GET
    try:
        resp = requests.get(target, timeout=timeout, headers={
            "Origin": "https://evil.com",
        }, allow_redirects=False)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            result["findings"].append({
                "origin_tested": "https://evil.com (GET)",
                "acao": acao,
                "acac": acac,
                "issues": ["Wildcard origin + credentials di GET request"],
            })
            result["vulnerable"] = True
            result["severity"] = "critical"
    except requests.RequestException:
        pass

    if not result["findings"]:
        result["summary"] = "Tidak ditemukan misconfiguration CORS."
    else:
        result["summary"] = f"Ditemukan {len(result['findings'])} potensi masalah CORS."

    return result
