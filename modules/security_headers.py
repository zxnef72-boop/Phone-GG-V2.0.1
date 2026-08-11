"""
Security headers analyzer — cek HTTP security headers (CSP, HSTS, X-Frame-Options, dll).
Beri skor & grade, plus rekomendasi perbaikan.
"""
from __future__ import annotations
import requests

REQUIRED_HEADERS = {
    "Strict-Transport-Security": {"required": True, "weight": 15,
        "desc": "HSTS — paksa HTTPS"},
    "Content-Security-Policy": {"required": True, "weight": 25,
        "desc": "CSP — mitigasi XSS, injection"},
    "X-Frame-Options": {"required": True, "weight": 10,
        "desc": "Clickjacking protection"},
    "X-Content-Type-Options": {"required": True, "weight": 10,
        "desc": "MIME-type sniffing protection"},
    "Referrer-Policy": {"required": False, "weight": 10,
        "desc": "Kontrol referrer info"},
    "Permissions-Policy": {"required": False, "weight": 10,
        "desc": "Kontrol fitur browser (camera, mic, dll)"},
    "Cross-Origin-Opener-Policy": {"required": False, "weight": 5,
        "desc": "Isolasi window dari cross-origin"},
    "Cross-Origin-Embedder-Policy": {"required": False, "weight": 5,
        "desc": "Kontrol cross-origin resource loading"},
    "Cross-Origin-Resource-Policy": {"required": False, "weight": 5,
        "desc": "Kontrol siapa yang bisa load resource ini"},
    "X-XSS-Protection": {"required": False, "weight": 5,
        "desc": "Legacy XSS filter (deprecated tapi masih relevan)"},
}

MAX_SCORE = sum(h["weight"] for h in REQUIRED_HEADERS.values())


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def analyze_security_headers(url: str, timeout: int = 2) -> dict:
    target = _normalize_url(url)

    try:
        resp = requests.get(target, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
        final_url = resp.url
        all_headers = {k.lower(): v for k, v in resp.headers.items()}

        security_headers = {}
        score = 0
        recommendations = []

        for name, info in REQUIRED_HEADERS.items():
            value = all_headers.get(name.lower(), "")
            found = bool(value)
            if found:
                score += info["weight"]
            elif info["required"]:
                recommendations.append(f"TAMBAH {name}: {info['desc']}")

            security_headers[name] = {
                "found": found,
                "value": value if found else None,
                "required": info["required"],
                "description": info["desc"],
            }

        # Grade
        pct = (score / MAX_SCORE) * 100
        if pct >= 90:
            grade = "A"
        elif pct >= 75:
            grade = "B"
        elif pct >= 60:
            grade = "C"
        elif pct >= 40:
            grade = "D"
        else:
            grade = "F"

        # Extra checks
        if "content-security-policy" in all_headers:
            csp = all_headers["content-security-policy"]
            if "unsafe-inline" in csp.lower():
                recommendations.append("CSP mengandung 'unsafe-inline' — kurang aman terhadap XSS")
            if "unsafe-eval" in csp.lower():
                recommendations.append("CSP mengandung 'unsafe-eval' — berisiko eval injection")

        if "strict-transport-security" in all_headers:
            hsts = all_headers["strict-transport-security"]
            if "max-age=0" in hsts or "max-age=1" in hsts:
                recommendations.append("HSTS max-age terlalu rendah — set minimal 31536000 (1 tahun)")

        if not recommendations:
            recommendations = ["Semua header keamanan utama sudah terpasang dengan baik."]

        return {
            "url": target,
            "final_url": final_url,
            "score": score,
            "max_score": MAX_SCORE,
            "percentage": round(pct, 1),
            "grade": grade,
            "security_headers": security_headers,
            "recommendations": recommendations,
        }
    except requests.RequestException as e:
        return {"url": target, "error": str(e)}
    except Exception as e:
        return {"url": target, "error": str(e)}
