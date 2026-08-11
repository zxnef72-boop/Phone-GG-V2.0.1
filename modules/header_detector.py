# ============================================
# PhoneGG Tool
# Author: NefZx
# ============================================
"""
HTTP Header & Tech Detector
Analisis header HTTP dan deteksi teknologi web sederhana
"""
from __future__ import annotations
import re
import requests

# Pola deteksi teknologi dari header
TECH_PATTERNS = {
    "Cloudflare": [r"cloudflare", r"cf-ray", r"__cf_bm"],
    "NGINX": [r"nginx"],
    "Apache": [r"apache"],
    "IIS": [r"microsoft-iis", r"IIS"],
    "LiteSpeed": [r"litespeed"],
    "Caddy": [r"caddy"],
    "Express": [r"X-Powered-By: Express"],
    "PHP": [r"X-Powered-By: PHP", r"PHPSESSID"],
    "Python": [r"X-Powered-By: Python"],
    "Node.js": [r"X-Powered-By: Node", r"node\.js"],
    "Ruby": [r"X-Powered-By: Ruby"],
    "Java": [r"JSESSIONID", r"X-Powered-By: Servlet"],
    "ASP.NET": [r"X-Powered-By: ASP\.NET", r"__VIEWSTATE"],
    "Go": [r"X-Powered-By: Go"],
    "Django": [r"csrfmiddlewaretoken"],
    "Flask": [r"X-Powered-By: Werkzeug"],
    "Laravel": [r"laravel_session"],
    "Rails": [r"X-CSRF-Token"],
    "FastAPI": [r"X-Powered-By: FastAPI"],
    "Gin": [r"X-Powered-By: Gin"],
    "Spring Boot": [r"X-Application-Context"],
}

# Header penting yang akan dianalisis
IMPORTANT_HEADERS = [
    "Server",
    "X-Powered-By",
    "Content-Type",
    "Content-Length",
    "Cache-Control",
    "Last-Modified",
    "ETag",
    "Accept-Ranges",
    "Connection",
    "Transfer-Encoding",
]

# Security headers
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _detect_tech_from_headers(headers: dict) -> list:
    detected = []
    headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    
    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, headers_text, re.IGNORECASE):
                if tech not in detected:
                    detected.append(tech)
                break
    
    return detected


def analyze_headers(url: str, timeout: int = 5) -> dict:
    target = _normalize_url(url)
    
    try:
        resp = requests.get(target, timeout=timeout, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
        
        final_url = resp.url
        status_code = resp.status_code
        all_headers = dict(resp.headers)
        
        # Ekstrak header penting
        important_headers = {}
        for header in IMPORTANT_HEADERS:
            value = resp.headers.get(header)
            if value:
                important_headers[header] = value
        
        # Ekstrak security headers
        security_headers = {}
        for header in SECURITY_HEADERS:
            value = resp.headers.get(header)
            if value:
                security_headers[header] = value
        
        # Deteksi teknologi
        detected_tech = _detect_tech_from_headers(all_headers)
        
        # Kategorisasi status code
        status_category = ""
        if 200 <= status_code < 300:
            status_category = "Success (2xx)"
        elif 300 <= status_code < 400:
            status_category = "Redirect (3xx)"
        elif 400 <= status_code < 500:
            status_category = "Client Error (4xx)"
        elif 500 <= status_code < 600:
            status_category = "Server Error (5xx)"
        
        return {
            "url": target,
            "final_url": final_url,
            "status_code": status_code,
            "status_category": status_category,
            "important_headers": important_headers,
            "security_headers": security_headers,
            "detected_technologies": detected_tech,
            "response_time_ms": round(resp.elapsed.total_seconds() * 1000, 2),
            "total_headers": len(all_headers),
        }
    except requests.exceptions.Timeout:
        return {"url": target, "error": "Timeout - server tidak merespon"}
    except requests.exceptions.ConnectionError:
        return {"url": target, "error": "Connection Error - tidak dapat terhubung"}
    except requests.RequestException as e:
        return {"url": target, "error": f"Request Error: {str(e)}"}
    except Exception as e:
        return {"url": target, "error": f"Error: {str(e)}"}
