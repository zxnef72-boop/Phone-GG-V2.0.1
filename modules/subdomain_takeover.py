"""
Subdomain takeover checker — cek apakah subdomain punya CNAME ke layanan
yang sudah tidak dipakai (dangling DNS), yang bisa di-claim attacker.
"""
from __future__ import annotations
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fingerprints untuk tiap layanan yang bisa di-takeover
TAKEOVER_FINGERPRINTS = {
    "github": {
        "cname": ["github.io", "github.com"],
        "indicators": ["There isn't a GitHub Pages site here", "For root URLs"],
        "vulnerable_text": "There isn't a GitHub Pages site here",
    },
    "heroku": {
        "cname": ["herokuapp.com", "herokussl.com"],
        "indicators": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        "vulnerable_text": "No such app",
    },
    "aws_s3": {
        "cname": ["s3.amazonaws.com"],
        "indicators": ["The specified bucket does not exist", "NoSuchBucket"],
        "vulnerable_text": "NoSuchBucket",
    },
    "cloudfront": {
        "cname": ["cloudfront.net"],
        "indicators": ["Bad request", "ERROR: The request could not be satisfied"],
        "vulnerable_text": "The request could not be satisfied",
    },
    "azure": {
        "cname": ["cloudapp.net", "cloudapp.azure.com"],
        "indicators": ["404 Web Site not found"],
        "vulnerable_text": "404 Web Site not found",
    },
    "tumblr": {
        "cname": ["tumblr.com"],
        "indicators": ["Whatever you were looking for doesn't currently exist"],
        "vulnerable_text": "doesn't currently exist",
    },
    "shopify": {
        "cname": ["myshopify.com"],
        "indicators": ["Sorry, this shop is currently unavailable"],
        "vulnerable_text": "shop is currently unavailable",
    },
    "wordpress": {
        "cname": ["wordpress.com"],
        "indicators": ["Do you want to register", "doesn't exist"],
        "vulnerable_text": "doesn't exist",
    },
    "surge": {
        "cname": ["surge.sh"],
        "indicators": ["project not found"],
        "vulnerable_text": "project not found",
    },
    "fastly": {
        "cname": ["fastly.net"],
        "indicators": ["Fastly error: unknown domain"],
        "vulnerable_text": "unknown domain",
    },
    "pantheon": {
        "cname": ["pantheonsite.io"],
        "indicators": ["The gods are wise", "The site you were looking for"],
        "vulnerable_text": "The site you were looking for",
    },
    "ghost": {
        "cname": ["ghost.io"],
        "indicators": ["The page you are looking for doesn't exist"],
        "vulnerable_text": "doesn't exist",
    },
    "netlify": {
        "cname": ["netlify.app", "netlify.com"],
        "indicators": ["Not Found - Request ID"],
        "vulnerable_text": "Not Found",
    },
    "vercel": {
        "cname": ["vercel.app", "now.sh"],
        "indicators": ["The deployment could not be found"],
        "vulnerable_text": "could not be found",
    },
}


def _get_cname(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
        if answers:
            return str(answers[0].target).rstrip(".")
    except Exception:
        return None
    return None


def _check_subdomain(subdomain: str) -> dict:
    cname = _get_cname(subdomain)
    if not cname:
        return {"subdomain": subdomain, "cname": None, "vulnerable": False, "status": "no_cname"}

    cname_lower = cname.lower()
    matched_service = None
    for service, fp in TAKEOVER_FINGERPRINTS.items():
        if any(cname_target in cname_lower for cname_target in fp["cname"]):
            matched_service = service
            break

    if not matched_service:
        return {"subdomain": subdomain, "cname": cname, "vulnerable": False, "status": "no_known_service"}

    # Cek apakah subdomain resolve ke halaman error
    try:
        url = f"http://{subdomain}"
        resp = requests.get(url, timeout=2, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        content_lower = resp.text.lower()
        vuln_text = TAKEOVER_FINGERPRINTS[matched_service]["vulnerable_text"].lower()

        if vuln_text in content_lower:
            return {
                "subdomain": subdomain,
                "cname": cname,
                "service": matched_service,
                "vulnerable": True,
                "status": "vulnerable",
                "evidence": TAKEOVER_FINGERPRINTS[matched_service]["vulnerable_text"],
                "http_status": resp.status_code,
            }
        return {
            "subdomain": subdomain,
            "cname": cname,
            "service": matched_service,
            "vulnerable": False,
            "status": "not_vulnerable",
            "http_status": resp.status_code,
        }
    except Exception as e:
        # Jika tidak bisa HTTP, cek DNS resolve error
        try:
            dns.resolver.resolve(subdomain, "A", lifetime=3)
            return {"subdomain": subdomain, "cname": cname, "service": matched_service,
                    "vulnerable": False, "status": "dns_resolves_but_http_failed", "error": str(e)}
        except Exception:
            return {
                "subdomain": subdomain,
                "cname": cname,
                "service": matched_service,
                "vulnerable": True,
                "status": "dns_not_resolving",
                "evidence": f"CNAME ke {cname} tapi tidak resolve A record — kemungkinan takeover",
            }


def check_takeover(subdomains: list, max_workers: int = 15) -> dict:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_subdomain, s): s for s in subdomains}
        for future in as_completed(futures):
            results.append(future.result())

    vulnerable = [r for r in results if r.get("vulnerable")]
    results.sort(key=lambda r: 0 if r.get("vulnerable") else 1)

    return {
        "total_checked": len(results),
        "total_vulnerable": len(vulnerable),
        "vulnerable": vulnerable,
        "all_results": results,
    }
