# ============================================
# PhoneGG Tool
# Author: NefZx
# ============================================
"""
Scam / Site Reputation Checker
--------------------------------
Modul ini TIDAK melakukan bypass proteksi apa pun (bukan Cloudflare bypass,
bukan scraping konten yang diproteksi). Semua data diambil dari sumber
publik & legal:

  - WHOIS (umur domain, registrar, privasi WHOIS)
  - DNS records (dasar validitas infrastruktur)
  - Wayback Machine (histori historis domain — situs scam biasanya baru
    & tidak punya jejak historis)
  - HTTP response header publik (bukan bypass — cuma baca header yang
    memang dikirim server ke semua orang, sama seperti browser biasa)
  - Heuristik pola URL/redirect yang umum dipakai situs phishing

Skor akhir 0-100 (makin tinggi makin mencurigakan), dipakai buat kasih
rekomendasi ke USER SENDIRI sebelum dia transaksi / klik link — bukan buat
menyerang atau membongkar sistem orang lain.
"""
from __future__ import annotations
import re
import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List
from urllib.parse import urlparse

import requests

from .domain_info import get_domain_info
from .wayback_lookup import get_snapshots

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "s.id", "shorturl.at", "cutt.ly",
    "linktr.ee", "is.gd", "rebrand.ly", "shope.ee", "rb.gy",
}

SCAM_KEYWORDS = [
    r"verifikasi.{0,15}akun", r"akun.{0,10}diblokir", r"klaim.{0,10}hadiah",
    r"menang.{0,10}undian", r"transfer.{0,10}dulu", r"dp.{0,10}dulu",
    r"resi.{0,10}palsu", r"cs.{0,10}resmi", r"admin.{0,10}pusat",
    r"login-", r"secure-verify", r"-confirm-account", r"reset-password-",
]

FREE_HOSTING_HINTS = [
    "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "github.io", "vercel.app", "netlify.app", "web.app", "glitch.me",
    "repl.co", "firebaseapp.com",
]


def _normalize(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


def _domain_age_days(creation_date) -> int | None:
    if not creation_date:
        return None
    try:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, str):
            creation_date = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - creation_date).days
    except Exception:
        return None


def _check_ssl(hostname: str) -> Dict[str, Any]:
    """Cek sertifikat TLS publik — sama seperti yang dilihat browser, bukan bypass."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "valid": True,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "expires": not_after,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


def _fetch_public_response(url: str) -> Dict[str, Any]:
    """GET biasa ke halaman publik — request yang sama persis seperti browser
    mana pun bikin. Tidak menyentuh apa pun yang diproteksi."""
    try:
        resp = requests.get(
            url, timeout=5, allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"},
        )
        return {
            "ok": True,
            "status_code": resp.status_code,
            "final_url": resp.url,
            "redirected": resp.url != url,
            "server": resp.headers.get("Server", ""),
            "title": _extract_title(resp.text),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:150] if m else ""


def check_site_reputation(target: str) -> Dict[str, Any]:
    """
    Analisis reputasi domain/URL secara pasif & legal.
    Return dict berisi skor risiko + breakdown alasan, buat ditampilkan ke user.
    """
    url = _normalize(target)
    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0].lower()

    result: Dict[str, Any] = {
        "target": target,
        "hostname": hostname,
        "risk_score": 0,
        "risk_level": "UNKNOWN",
        "reasons": [],
        "positive_signals": [],
    }

    score = 0
    reasons: List[str] = []
    positives: List[str] = []

    # 1) Shortener check
    if hostname in SHORTENER_DOMAINS:
        score += 15
        reasons.append("Pakai layanan pemendek URL — tujuan asli disembunyikan.")

    # 2) Free hosting check
    if any(h in hostname for h in FREE_HOSTING_HINTS):
        score += 20
        reasons.append("Di-hosting di platform gratisan yang sering dipakai situs dadakan/phishing.")

    # 3) Keyword phishing di hostname/URL
    full_lower = url.lower()
    matched_kw = [kw for kw in SCAM_KEYWORDS if re.search(kw, full_lower)]
    if matched_kw:
        score += 15 * min(len(matched_kw), 2)
        reasons.append(f"URL mengandung pola umum phishing ({len(matched_kw)} pola terdeteksi).")

    # 4) WHOIS / umur domain
    dinfo = get_domain_info(hostname)
    result["domain_info"] = dinfo
    whois_data = dinfo.get("whois", {})
    age_days = _domain_age_days(whois_data.get("creation_date"))
    if age_days is not None:
        result["domain_age_days"] = age_days
        if age_days < 30:
            score += 30
            reasons.append(f"Domain baru banget — umur cuma {age_days} hari (< 1 bulan).")
        elif age_days < 180:
            score += 15
            reasons.append(f"Domain masih muda — umur {age_days} hari (< 6 bulan).")
        else:
            positives.append(f"Domain sudah berumur {age_days} hari, bukan domain dadakan.")
    else:
        score += 10
        reasons.append("Data WHOIS tidak tersedia / disembunyikan (privacy protection) — cek manual disarankan.")

    if not dinfo.get("mx") and not dinfo.get("a"):
        score += 10
        reasons.append("Tidak ada DNS record A/MX yang valid — infrastruktur mencurigakan.")

    # 5) Wayback history — situs scam biasanya tidak punya jejak lama
    try:
        wb = get_snapshots(hostname, limit=5)
        result["wayback_snapshots"] = wb.get("total", 0)
        if wb.get("total", 0) == 0:
            score += 15
            reasons.append("Tidak ada jejak historis di Wayback Machine — situs kemungkinan baru dibuat & belum pernah diaudit publik.")
        else:
            positives.append(f"Punya {wb.get('total')} snapshot historis di Wayback Machine.")
    except Exception:
        pass

    # 6) SSL check
    ssl_info = _check_ssl(hostname)
    result["ssl"] = ssl_info
    if not ssl_info.get("valid"):
        score += 15
        reasons.append("Sertifikat HTTPS tidak valid / tidak ada — koneksi tidak aman.")
    else:
        positives.append(f"HTTPS valid, diterbitkan oleh {ssl_info.get('issuer', 'CA tidak diketahui')}.")

    # 7) Respons publik + redirect
    resp_info = _fetch_public_response(url)
    result["response"] = resp_info
    if resp_info.get("ok") and resp_info.get("redirected"):
        reasons.append(f"URL melakukan redirect ke: {resp_info.get('final_url')}")

    score = max(0, min(100, score))
    result["risk_score"] = score
    if score >= 60:
        result["risk_level"] = "TINGGI (kemungkinan scam/phishing)"
    elif score >= 30:
        result["risk_level"] = "SEDANG (perlu hati-hati, cek manual)"
    else:
        result["risk_level"] = "RENDAH (belum ada tanda mencurigakan signifikan)"

    result["reasons"] = reasons
    result["positive_signals"] = positives
    result["recommendation"] = _build_recommendation(score)
    return result


def _build_recommendation(score: int) -> str:
    if score >= 60:
        return ("Hindari transaksi/login di situs ini. Jangan kirim data pribadi, OTP, "
                "atau uang. Kalau sudah terlanjur bayar, screenshot semua bukti & laporkan "
                "ke cekrekening.id (rekening bank) atau lapor.go.id (laporan resmi).")
    if score >= 30:
        return ("Cek ulang manual: cari nama toko/situs + kata 'penipuan' di Google, cek "
                "review di grup Facebook/forum, dan jangan bayar via transfer langsung ke "
                "rekening pribadi tanpa rekber/COD kalau bisa.")
    return ("Belum ditemukan tanda mencurigakan signifikan dari sisi teknis, tapi ini bukan "
            "jaminan 100% aman — tetap cek testimoni & riwayat penjual sebelum transaksi besar.")
