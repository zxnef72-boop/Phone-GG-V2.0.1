"""
Breach database search — cari email di multiple breach databases.
Sources: HaveIBeenPwned API, BreachDirectory, IntelX (public), Dehashed (link only).
"""
from __future__ import annotations
import os
import requests


def check_hibp(email: str) -> dict:
    """Cek HaveIBeenPwned API (butuh API key di env HIBP_API_KEY)."""
    api_key = os.environ.get("HIBP_API_KEY", "")
    try:
        headers = {"User-Agent": "PhoneGG-OSINT"}
        if api_key:
            headers["hibp-api-key"] = api_key
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        resp = requests.get(url, timeout=2, headers=headers)

        if resp.status_code == 404:
            return {"breached": False, "count": 0, "breaches": [], "source": "HIBP"}
        elif resp.status_code == 200:
            data = resp.json()
            breaches = [b.get("Name", b.get("Title", "")) for b in data]
            return {"breached": True, "count": len(breaches), "breaches": breaches, "source": "HIBP"}
        elif resp.status_code == 401:
            return {"breached": None, "error": "API key HIBP tidak valid", "source": "HIBP"}
        elif resp.status_code == 429:
            return {"breached": None, "error": "Rate limited HIBP", "source": "HIBP"}
        else:
            return {"breached": None, "error": f"HTTP {resp.status_code}", "source": "HIBP"}
    except Exception as e:
        return {"breached": None, "error": str(e), "source": "HIBP"}


def check_breachdirectory(email: str) -> dict:
    """Cek BreachDirectory (public endpoint, tanpa key)."""
    try:
        url = f"https://breachdirectory.io/api/v2/breaches?email={email}"
        resp = requests.get(url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and data:
                breaches = [b.get("name", b.get("title", "")) for b in data if isinstance(b, dict)]
                return {"breached": len(breaches) > 0, "count": len(breaches),
                        "breaches": breaches, "source": "BreachDirectory"}
            return {"breached": False, "count": 0, "breaches": [], "source": "BreachDirectory"}
        return {"breached": None, "error": f"HTTP {resp.status_code}", "source": "BreachDirectory"}
    except Exception as e:
        return {"breached": None, "error": str(e), "source": "BreachDirectory"}


def search_all_breaches_phone(phone: str) -> dict:
    """
    Search a phone number across breach/leak sources.

    Catatan jujur: HIBP dan BreachDirectory publik itu basisnya email,
    bukan nomor HP, jadi keduanya TIDAK dipanggil di sini (biar gak
    ngasih hasil palsu/asal nebak). Untuk nomor HP, sumber yang
    sungguhan mendukung pencarian by-phone adalah layanan link-based
    di bawah -- hasil akhirnya tetap perlu dicek manual oleh user.

    Args:
        phone: Nomor HP yang SUDAH dinormalisasi (mis. 62812xxxxxxx)

    Returns:
        Dictionary hasil pencarian per sumber, format senada dengan
        search_all_breaches() supaya bisa dipakai template yang sama.
    """
    results = {
        "phone": phone,
        "sources": {},
        "total_breaches": 0,
        "all_breaches": [],
    }

    # IntelX -- mendukung pencarian bebas termasuk nomor telepon
    results["sources"]["intelx"] = {
        "url": f"https://intelx.io/?s={phone}",
        "note": "Cek manual di IntelX (mendukung pencarian nomor HP)"
    }

    # LeakCheck -- salah satu yang paling umum dipakai untuk cari nomor HP
    results["sources"]["leakcheck"] = {
        "url": f"https://leakcheck.io/search?query={phone}",
        "note": "Cek manual di LeakCheck (mendukung pencarian nomor HP)"
    }

    # Dehashed -- mendukung field phone, tapi butuh subscription
    results["sources"]["dehashed"] = {
        "url": f"https://dehashed.com/search?query={phone}",
        "note": "Cek manual di Dehashed (butuh subscription, support nomor HP)"
    }

    # Snusbase -- butuh akun berbayar, tapi mendukung pencarian nomor HP
    results["sources"]["snusbase"] = {
        "url": "https://snusbase.com/",
        "note": "Cek manual di Snusbase (butuh akun, support pencarian nomor HP)"
    }

    return results


def search_all_breaches(email: str) -> dict:
    """Search email across multiple breach databases."""
    results = {
        "email": email,
        "sources": {},
        "total_breaches": 0,
        "all_breaches": set(),
    }

    hibp = check_hibp(email)
    results["sources"]["hibp"] = hibp
    if hibp.get("breached"):
        results["all_breaches"].update(hibp.get("breaches", []))

    bd = check_breachdirectory(email)
    results["sources"]["breachdirectory"] = bd
    if bd.get("breached"):
        results["all_breaches"].update(bd.get("breaches", []))

    # IntelX leak search (public, limited)
    try:
        url = f"https://intelx.io/?s={email}"
        results["sources"]["intelx"] = {"url": url, "note": "Cek manual di IntelX untuk hasil detail"}
    except Exception:
        pass

    # Dehashed (link only, butuh subscription)
    results["sources"]["dehashed"] = {
        "url": f"https://dehashed.com/search?value={email}",
        "note": "Cek manual di Dehashed (butuh subscription)"
    }

    results["all_breaches"] = sorted(results["all_breaches"])
    results["total_breaches"] = len(results["all_breaches"])
    return results
