"""
Wayback Machine lookup — cari snapshot historis URL via web.archive.org API.
Berguna untuk melihat versi lama halaman, endpoint yang sudah dihapus, dll.
"""
from __future__ import annotations
import requests
from urllib.parse import quote

def get_snapshots(url: str, limit: int = 20) -> dict:
    """Ambil daftar snapshot dari Wayback Machine."""
    try:
        api_url = f"https://web.archive.org/cdx/search/cdx?url={quote(url)}&output=json&limit={limit}&collapse=timestamp:8"
        resp = requests.get(api_url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200 or not resp.text.strip():
            return {"url": url, "snapshots": [], "total": 0}

        data = resp.json()
        if len(data) < 2:
            return {"url": url, "snapshots": [], "total": 0}

        # Row 0 = headers
        headers = data[0]
        snapshots = []
        for row in data[1:]:
            entry = dict(zip(headers, row))
            ts = entry.get("timestamp", "")
            if ts:
                formatted = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]}"
                entry["formatted_date"] = formatted
                entry["wayback_url"] = f"https://web.archive.org/web/{ts}/{entry.get('original', url)}"
            snapshots.append(entry)

        return {"url": url, "snapshots": snapshots, "total": len(snapshots)}
    except Exception as e:
        return {"url": url, "error": str(e), "snapshots": [], "total": 0}

def get_all_urls_for_domain(domain: str, limit: int = 100) -> dict:
    """Ambil semua URL yang pernah di-crawl oleh Wayback untuk domain tertentu."""
    try:
        api_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}&collapse=urlkey"
        resp = requests.get(api_url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200 or not resp.text.strip():
            return {"domain": domain, "urls": [], "total": 0}

        data = resp.json()
        if len(data) < 2:
            return {"domain": domain, "urls": [], "total": 0}

        headers = data[0]
        urls = []
        seen = set()
        for row in data[1:]:
            entry = dict(zip(headers, row))
            original = entry.get("original", "")
            if original and original not in seen:
                seen.add(original)
                urls.append({
                    "url": original,
                    "first_seen": entry.get("timestamp", ""),
                    "status": entry.get("statuscode", ""),
                    "mime": entry.get("mimetype", ""),
                })

        return {"domain": domain, "urls": urls, "total": len(urls)}
    except Exception as e:
        return {"domain": domain, "error": str(e), "urls": [], "total": 0}
