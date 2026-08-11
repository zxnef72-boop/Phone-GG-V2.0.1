"""
IP geolocation & info — ambil data geolokasi, ASN, ISP dari IP address.
Menggunakan ip-api.com (gratis, no key) dan ipinfo.io.
"""
from __future__ import annotations
import requests


def get_ip_info(ip: str = "") -> dict:
    """Ambil info IP dari ip-api.com."""
    try:
        if ip:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        else:
            url = "http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        resp = requests.get(url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})
        data = resp.json()

        if data.get("status") == "success":
            return {
                "status": "success",
                "ip": data.get("query", ip),
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "region_code": data.get("region"),
                "city": data.get("city"),
                "postal": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "asname": data.get("asname"),
                "reverse_dns": data.get("reverse"),
                "is_mobile": data.get("mobile"),
                "is_proxy": data.get("proxy"),
                "is_hosting": data.get("hosting"),
            }
        return {"status": "error", "message": data.get("message", "Unknown error")}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def get_ipinfo(ip: str = "") -> dict:
    """Ambil info IP dari ipinfo.io."""
    try:
        url = f"https://ipinfo.io/{ip}/json" if ip else "https://ipinfo.io/json"
        resp = requests.get(url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})
        data = resp.json()
        return {
            "status": "success",
            "ip": data.get("ip"),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "loc": data.get("loc"),
            "org": data.get("org"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def resolve_domain_to_ip(domain: str) -> list:
    """Resolve domain ke list IP via DNS."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def full_ip_lookup(target: str) -> dict:
    """Full IP lookup: resolve domain kalau perlu, ambil info dari multiple sources."""
    result = {"target": target, "sources": {}}

    # Kalau target adalah domain, resolve ke IP
    if not target.replace(".", "").isdigit():
        ips = resolve_domain_to_ip(target)
        result["resolved_ips"] = ips
        if ips:
            for ip in ips[:3]:  # max 3 IPs
                result["sources"][ip] = {"ip_api": get_ip_info(ip), "ipinfo": get_ipinfo(ip)}
    else:
        result["sources"][target] = {"ip_api": get_ip_info(target), "ipinfo": get_ipinfo(target)}

    return result
