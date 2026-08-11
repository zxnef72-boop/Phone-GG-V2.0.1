# ============================================
# PhoneGG Tool
# Author: NefZx
# ============================================
"""
Link & Script Scraper/Extractor
Extract semua link dan script dari HTML, highlight link sensitif
"""
from __future__ import annotations
import re
import requests
from urllib.parse import urljoin
from typing import Dict


# Pola link sensitif/mencurigakan
SENSITIVE_PATTERNS = {
    "Telegram API": [r"api\.telegram\.org"],
    "Telegram Web": [r"t\.me/", r"telegram\.org"],
    "Discord Webhook": [r"discord\.com/api/webhooks", r"discordapp\.com/api/webhooks"],
    "WhatsApp API": [r"wa\.me", r"api\.whatsapp\.com"],
    "Facebook Pixel": [r"connect\.facebook\.net.*fbevents"],
    "Google Analytics": [r"google-analytics\.com", r"googletagmanager\.com"],
    "External JS": [r"\.js(\?|$)", r"cdn\..*\.js"],
    "Analytics/Tracking": [r"analytics", r"tracking", r"telemetry"],
}


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _check_sensitive(link: str) -> Dict:
    """Cek apakah link mengandung pola sensitif"""
    sensitive_info = {"is_sensitive": False, "categories": []}
    
    for category, patterns in SENSITIVE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, link, re.IGNORECASE):
                sensitive_info["is_sensitive"] = True
                if category not in sensitive_info["categories"]:
                    sensitive_info["categories"].append(category)
                break
    
    return sensitive_info


def extract_links_and_scripts(url: str, timeout: int = 5) -> dict:
    target = _normalize_url(url)
    
    try:
        resp = requests.get(target, timeout=timeout, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
        
        if resp.status_code != 200:
            return {"url": target, "error": f"Status code {resp.status_code}"}
        
        html = resp.text
        base_url = resp.url
        
        # Extract semua script src
        script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        scripts = re.findall(script_pattern, html, re.IGNORECASE)
        
        # Extract semua link href
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
        links = re.findall(link_pattern, html, re.IGNORECASE)
        
        # Normalize dan categorize scripts
        script_results = []
        for script in scripts:
            full_url = urljoin(base_url, script)
            sensitive = _check_sensitive(full_url)
            script_results.append({
                "original": script,
                "full_url": full_url,
                "is_sensitive": sensitive["is_sensitive"],
                "categories": sensitive["categories"]
            })
        
        # Normalize dan categorize links
        link_results = []
        for link in links:
            full_url = urljoin(base_url, link)
            sensitive = _check_sensitive(full_url)
            link_results.append({
                "original": link,
                "full_url": full_url,
                "is_sensitive": sensitive["is_sensitive"],
                "categories": sensitive["categories"]
            })
        
        # Hitung statistik
        total_scripts = len(script_results)
        total_links = len(link_results)
        sensitive_scripts = [s for s in script_results if s["is_sensitive"]]
        sensitive_links = [l for l in link_results if l["is_sensitive"]]
        
        return {
            "url": target,
            "final_url": base_url,
            "status_code": resp.status_code,
            "scripts": {
                "total": total_scripts,
                "sensitive_count": len(sensitive_scripts),
                "items": script_results
            },
            "links": {
                "total": total_links,
                "sensitive_count": len(sensitive_links),
                "items": link_results
            },
            "summary": {
                "total_items": total_scripts + total_links,
                "total_sensitive": len(sensitive_scripts) + len(sensitive_links),
                "has_sensitive": (len(sensitive_scripts) + len(sensitive_links)) > 0
            }
        }
    except requests.exceptions.Timeout:
        return {"url": target, "error": "Timeout - server tidak merespon"}
    except requests.exceptions.ConnectionError:
        return {"url": target, "error": "Connection Error - tidak dapat terhubung"}
    except requests.RequestException as e:
        return {"url": target, "error": f"Request Error: {str(e)}"}
    except Exception as e:
        return {"url": target, "error": f"Error: {str(e)}"}


def extract_by_category(url: str, category: str = "all", timeout: int = 5) -> dict:
    """Extract dengan filter kategori tertentu"""
    result = extract_links_and_scripts(url, timeout)
    
    if "error" in result:
        return result
    
    if category == "sensitive":
        sensitive_scripts = [s for s in result["scripts"]["items"] if s["is_sensitive"]]
        sensitive_links = [l for l in result["links"]["items"] if l["is_sensitive"]]
        
        return {
            "url": result["url"],
            "final_url": result["final_url"],
            "category": "sensitive_only",
            "scripts": sensitive_scripts,
            "links": sensitive_links,
            "total_sensitive": len(sensitive_scripts) + len(sensitive_links)
        }
    elif category == "scripts":
        return {
            "url": result["url"],
            "final_url": result["final_url"],
            "category": "scripts_only",
            "scripts": result["scripts"]["items"],
            "total": result["scripts"]["total"]
        }
    elif category == "links":
        return {
            "url": result["url"],
            "final_url": result["final_url"],
            "category": "links_only",
            "links": result["links"]["items"],
            "total": result["links"]["total"]
        }
    
    return result
