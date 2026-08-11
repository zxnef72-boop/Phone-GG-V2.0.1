"""
Subdomain enumeration — passive discovery via multiple sources:
crt.sh (Certificate Transparency), DNS brute-force, dan search engine dorks.
"""
from __future__ import annotations
import concurrent.futures
from typing import List
from urllib.parse import urlparse
import dns.resolver
import requests

# Common subdomain prefixes untuk brute-force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "ns", "dns", "dns1", "dns2", "api", "api1", "api2", "v1", "v2",
    "dev", "staging", "staging2", "test", "testing", "beta", "alpha", "qa",
    "uat", "sandbox", "preview", "demo", "old", "new", "backup", "backup2",
    "m", "mobile", "app", "apps", "portal", "admin", "admin2", "panel",
    "secure", "ssl", "vpn", "remote", "cloud", "shop", "store", "blog",
    "forum", "wiki", "docs", "doc", "help", "support", "status", "cdn",
    "assets", "static", "media", "img", "images", "video", "stream",
    "auth", "login", "sso", "oauth", "id", "identity", "account", "accounts",
    "crm", "erp", "hr", "finance", "billing", "pay", "payment", "checkout",
    "git", "gitlab", "github", "jenkins", "ci", "build", "deploy", "registry",
    "docker", "k8s", "kube", "consul", "grafana", "prometheus", "elastic",
    "kibana", "logstash", "splunk", "redis", "memcached", "rabbitmq",
    "internal", "intranet", "private", "corp", "office", "vpn", "ssh",
    "db", "database", "mysql", "postgres", "mongo", "mongo1", "mongo2",
    "phpmyadmin", "pma", "adminer", "es", "elastic1", "elastic2",
    "chat", "chatbot", "bot", "socket", "ws", "wss", "graphql", "gql",
    "rest", "soap", "rpc", "json", "xml", "feed", "rss", "webhook",
    "mx", "mx1", "mx2", "relay", "gateway", "proxy", "lb", "haproxy",
    "nginx", "apache", "web1", "web2", "web3", "app1", "app2", "app3",
    "node1", "node2", "node3", "server1", "server2", "server3",
    "monitor", "monitoring", "nagios", "zabbix", "uptime", "ping",
    "analytics", "track", "tracker", "pixel", "tag", "ads", "adserver",
    "push", "fcm", "apns", "notification", "notify", "alert", "alerts",
    "search", "solr", " Sphinx", "elastic",
    "ftp1", "ftp2", "sftp", "tftp", "file", "files", "download", "upload",
    "storage", "s3", "bucket", "minio", "ceph", "gluster",
    "vpn1", "vpn2", "wireguard", "openvpn", "pptp", "l2tp",
    "m1", "m2", "m3", "ml", "ai", "model", "inference", "predict",
    "train", "training", "data", "dataset", "pipeline", "etl",
    "warehouse", "lake", "datascience", "notebook", "jupyter",
    "airflow", "spark", "hadoop", "hive", "presto", "trino",
    "kafka", "zookeeper", "nifi", "flink", "storm",
    "registry1", "registry2", "harbor", "quay", "nexus",
    "sonar", "sonarqube", "snyk", "fortify", "checkmarx",
    "vault", "consul", "nomad", "terraform", "ansible", "puppet", "chef",
    "ldap", "ad", "dc", "domain", "kerberos", "radius",
    "sip", "voip", "pbx", "asterisk", "freeswitch",
    "meet", "jitsi", "zoom", "teams", "slack", "discord",
    "dashboard", "dashboards", "grafana1", "grafana2",
    "staging-api", "staging-app", "staging-web", "staging-db",
    "prod-api", "prod-app", "prod-web", "prod-db",
    "preprod", "preprod-api", "preprod-app",
    "canary", "blue", "green", "hot", "warm", "cold",
    "edge", "edge1", "edge2", "origin", "origin1", "origin2",
    "cache", "cache1", "cache2", "varnish", "squid",
    "waf", "firewall", "ids", "ips", "siem", "soc", "threat",
]


def _get_domain(target: str) -> str:
    if "://" in target:
        target = urlparse(target).netloc
    if "@" in target:
        target = target.split("@")[1]
    return target.strip().lower().rstrip("/")


def crtsh_enum(domain: str, timeout: int = 2) -> List[str]:
    """Cari subdomain via crt.sh Certificate Transparency logs."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lower().lstrip("*.")
                if line and domain in line and " " not in line:
                    subdomains.add(line)
        return sorted(subdomains)
    except Exception:
        return []


def dns_brute(domain: str, wordlist: List[str] = None, max_workers: int = 20) -> List[str]:
    """Brute-force subdomain via DNS resolution."""
    prefixes = wordlist if wordlist else COMMON_SUBDOMAINS
    found = set()

    def resolve(sub):
        try:
            subdomain = f"{sub}.{domain}"
            answers = dns.resolver.resolve(subdomain, "A", lifetime=3)
            if answers:
                return subdomain
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve, p): p for p in prefixes}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.add(result)

    return sorted(found)


def search_engine_dorks(domain: str) -> List[str]:
    """Cari subdomain via Google dork."""
    try:
        query = f"site:*.{domain} -site:www.{domain}"
        url = f"https://www.google.com/search?q={query}&num=50"
        resp = requests.get(url, timeout=2, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
        })
        import re
        pattern = rf'([\w.-]+\.{re.escape(domain)})'
        matches = re.findall(pattern, resp.text)
        return sorted(set(m.lower() for m in matches if m.lower() != domain))
    except Exception:
        return []


def enumerate_subdomains(target: str, use_crtsh: bool = True,
                          use_bruteforce: bool = True,
                          use_search: bool = True) -> dict:
    """Gabungkan semua metode enumeration."""
    domain = _get_domain(target)
    result = {"domain": domain, "subdomains": [], "sources": {}}

    if use_crtsh:
        crt = crtsh_enum(domain)
        result["sources"]["crtsh"] = crt

    if use_search:
        se = search_engine_dorks(domain)
        result["sources"]["search_engine"] = se

    if use_bruteforce:
        brute = dns_brute(domain)
        result["sources"]["dns_bruteforce"] = brute

    # Merge & deduplicate
    all_subs = set()
    for subs in result["sources"].values():
        all_subs.update(subs)
    result["subdomains"] = sorted(all_subs)
    result["total"] = len(result["subdomains"])
    return result
