"""
Page/redirect status checker — HTTP status, redirect chain, soft-404,
response time, dan info sertifikat SSL.
"""
from __future__ import annotations
import random
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
]


def _get_ssl_info(hostname: str, timeout: int = 5) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        expires, days_left = None, None
        if not_after:
            expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expires = expires_dt.isoformat()
            days_left = (expires_dt - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        return {
            "valid": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "N/A")),
            "subject": subject.get("commonName", "N/A"),
            "expires": expires,
            "days_left": days_left,
            "san": [v for item in cert.get("subjectAltName", []) for v in (item[1],) if isinstance(item, tuple)],
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def check_url_status(url: str, timeout: int = 10) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        resp = requests.get(url, timeout=2, headers=headers, allow_redirects=True)
        final_url = resp.url
        status = resp.status_code
        redirect_chain = [r.url for r in resp.history] + [final_url]
        response_time_ms = round(resp.elapsed.total_seconds() * 1000, 1)

        is_404 = False
        recommendation = ""
        if status == 404:
            is_404 = True
            recommendation = "Aman: Halaman benar-benar tidak ditemukan (404)."
        elif status == 200:
            content = resp.text.lower()
            if "404" in content or "not found" in content or "tidak ditemukan" in content:
                recommendation = ("PERHATIAN: Status 200 tapi konten menampilkan 404 (soft-404). "
                                   "Gunakan status 404 yang benar.")
            else:
                recommendation = "Halaman dapat diakses (status 200)."
        elif status in (301, 302, 303, 307, 308):
            recommendation = f"Redirect ke: {final_url} (status {status})."
        elif status >= 500:
            recommendation = f"Error {status}: Masalah di server."
        elif status >= 400:
            recommendation = f"Error {status}: Periksa konfigurasi/permission."
        else:
            recommendation = f"Status {status}: {resp.reason}"

        if response_time_ms > 3000:
            recommendation += " | Response lambat (>3s), pertimbangkan optimasi."

        ssl_info = None
        parsed = urlparse(final_url)
        if parsed.scheme == "https":
            ssl_info = _get_ssl_info(parsed.hostname, timeout=timeout)
            if ssl_info.get("valid") and ssl_info.get("days_left") is not None and ssl_info["days_left"] <= 14:
                recommendation += f" | SSL expire dalam {ssl_info['days_left']} hari."

        return {
            "url": url,
            "final_url": final_url,
            "status_code": status,
            "is_404": is_404,
            "redirect_chain": redirect_chain,
            "response_time_ms": response_time_ms,
            "ssl": ssl_info,
            "recommendation": recommendation,
            "headers": dict(resp.headers),
        }
    except requests.exceptions.Timeout:
        return {"url": url, "error": "Timeout", "recommendation": "Server tidak merespon."}
    except requests.exceptions.ConnectionError:
        return {"url": url, "error": "Connection Error", "recommendation": "Tidak dapat terhubung ke server."}
    except Exception as e:
        return {"url": url, "error": str(e), "recommendation": f"Error: {e}"}


def check_multiple_urls(urls: list, timeout: int = 10) -> list:
    return [check_url_status(u, timeout) for u in urls]
