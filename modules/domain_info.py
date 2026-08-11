"""
Domain info — WHOIS + record DNS (MX, A, AAAA, TXT, NS, CNAME, SOA, CAA).
"""
from __future__ import annotations
from typing import Dict
import dns.resolver
import whois

RECORD_TYPES = ["MX", "A", "AAAA", "NS", "TXT", "SOA", "CAA", "CNAME"]


def _resolve_records(domain: str, record_type: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        if record_type == "MX":
            return sorted([str(r.exchange).rstrip(".") for r in answers])
        return [str(r).strip('"') for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
        return []


def get_domain_info(target: str) -> Dict:
    domain = target.split("@")[1].strip().lower() if "@" in target else target.strip().lower()
    domain = domain.rstrip("/")

    result = {"domain": domain, "whois": {}}
    for rt in RECORD_TYPES:
        result[rt.lower()] = []

    # WHOIS
    try:
        w = whois.whois(domain)
        if w and (w.domain_name or w.registrar):
            result["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers,
                "org": w.org,
                "country": w.country,
                "status": w.status,
            }
        else:
            result["whois"] = {"error": "Data WHOIS tidak tersedia untuk domain ini."}
    except Exception as e:
        result["whois"] = {"error": f"Gagal mengambil WHOIS: {e}"}

    # DNS records
    for rt in RECORD_TYPES:
        result[rt.lower()] = _resolve_records(domain, rt)

    # Email provider detection
    mx_joined = " ".join(result["mx"]).lower()
    if "google" in mx_joined or "gmail" in mx_joined:
        result["email_provider"] = "Google Workspace / Gmail"
    elif "outlook" in mx_joined or "protection.outlook" in mx_joined:
        result["email_provider"] = "Microsoft 365 / Outlook"
    elif "zoho" in mx_joined:
        result["email_provider"] = "Zoho Mail"
    elif "protonmail" in mx_joined or "proton" in mx_joined:
        result["email_provider"] = "ProtonMail"
    elif result["mx"]:
        result["email_provider"] = "Lainnya (lihat MX record)"
    else:
        result["email_provider"] = None

    return result
