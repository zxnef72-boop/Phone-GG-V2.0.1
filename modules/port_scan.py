"""
Port scanner — scan port umum via TCP connect.
Ringan, tidak butuh root, cocok untuk recon cepat.
"""
from __future__ import annotations
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from urllib.parse import urlparse

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC-1",
    5984: "CouchDB",
    6379: "Redis",
    6443: "K8s API",
    8080: "HTTP-Alt",
    8081: "HTTP-Alt2",
    8086: "InfluxDB",
    8088: "HTTP-Alt3",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt4",
    9000: "PHP-FPM",
    9042: "Cassandra",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "ES Transport",
    9418: "Git",
    11211: "Memcached",
    15672: "RabbitMQ",
    27017: "MongoDB",
    50000: "SAP",
}

# Extended aggressive port list
EXTENDED_PORTS = {
    1080: "SOCKS",
    1194: "OpenVPN",
    1812: "RADIUS",
    2049: "NFS",
    2222: "SSH-Alt",
    2483: "Oracle Alt",
    2484: "Oracle Alt TLS",
    3128: "Squid Proxy",
    3268: "LDAP",
    3269: "LDAPS",
    3478: "STUN/TURN",
    4040: "HTTP-Alt",
    4443: "HTTPS-Alt",
    4444: "Metasploit",
    4848: "GlassFish",
    5000: "HTTP-Alt",
    5001: "HTTP-Alt",
    5060: "SIP",
    5222: "XMPP",
    5269: "XMPP S2S",
    5353: "mDNS",
    5601: "Kibana",
    5666: "NRPE",
    5672: "RabbitMQ AMQP",
    5800: "VNC Web",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6000: "X11",
    636: "LDAPS",
    6443: "K8s API",
    6660: "IRC",
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    7000: "HTTP-Alt",
    7001: "WebLogic",
    7002: "WebLogic HTTPS",
    7070: "HTTP-Alt",
    7777: "HTTP-Alt",
    8000: "HTTP-Alt",
    8001: "HTTP-Alt",
    8002: "HTTP-Alt",
    8008: "HTTP-Alt",
    8009: "AJP",
    8010: "HTTP-Alt",
    8020: "HTTP-Alt",
    8042: "Hadoop",
    8082: "HTTP-Alt",
    8083: "HTTP-Alt",
    8084: "HTTP-Alt",
    8085: "HTTP-Alt",
    8087: "HTTP-Alt",
    8089: "Splunk",
    8090: "HTTP-Alt",
    8091: "HTTP-Alt",
    8161: "ActiveMQ",
    8181: "HTTP-Alt",
    8200: "HTTP-Alt",
    8333: "Bitcoin",
    8444: "HTTPS-Alt",
    8500: "HTTP-Alt",
    8530: "HTTP-Alt",
    8531: "HTTPS-Alt",
    8649: "Ganglia",
    8765: "HTTP-Alt",
    8800: "HTTP-Alt",
    8834: "Nessus",
    8880: "HTTP-Alt",
    8881: "HTTP-Alt",
    8882: "HTTP-Alt",
    8883: "HTTP-Alt",
    8884: "HTTP-Alt",
    8885: "HTTP-Alt",
    8886: "HTTP-Alt",
    8887: "HTTP-Alt",
    8889: "HTTP-Alt",
    9001: "Tor",
    9002: "HTTP-Alt",
    9003: "HTTP-Alt",
    9004: "HTTP-Alt",
    9005: "HTTP-Alt",
    9006: "HTTP-Alt",
    9007: "HTTP-Alt",
    9008: "HTTP-Alt",
    9009: "HTTP-Alt",
    9010: "HTTP-Alt",
    9011: "HTTP-Alt",
    9042: "Cassandra",
    9080: "HTTP-Alt",
    9090: "Prometheus",
    9091: "Prometheus",
    9092: "Kafka",
    9100: "Printer",
    9200: "Elasticsearch",
    9300: "ES Transport",
    9418: "Git",
    9990: "HTTP-Alt",
    9991: "HTTP-Alt",
    10000: "Webmin",
    10001: "Webmin",
    10250: "K8s kubelet",
    10255: "K8s kubelet read-only",
    11211: "Memcached",
    15672: "RabbitMQ",
    16080: "HTTP-Alt",
    18080: "HTTP-Alt",
    18081: "HTTP-Alt",
    20000: "HTTP-Alt",
    27015: "Steam",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
    50000: "SAP",
    50070: "Hadoop NameNode",
    50090: "Hadoop JobTracker",
}


def _get_hostname(target: str) -> str:
    if "://" in target:
        target = urlparse(target).netloc
    if "@" in target:
        target = target.split("@")[1]
    return target.split(":")[0].strip().lower().rstrip("/")


def _scan_port(host: str, port: int, timeout: float = 1.5) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port) or EXTENDED_PORTS.get(port, "Unknown")
                return {"port": port, "service": service, "state": "open"}
        return None
    except Exception:
        return None


def scan_ports(target: str, ports: List[int] = None, extended: bool = False,
               max_workers: int = 50, timeout: float = 1.5) -> dict:
    host = _get_hostname(target)

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"target": target, "host": host, "error": "Tidak bisa resolve hostname"}

    if ports:
        port_list = ports
    elif extended:
        port_list = sorted(set(list(COMMON_PORTS.keys()) + list(EXTENDED_PORTS.keys())))
    else:
        port_list = sorted(COMMON_PORTS.keys())

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_port, ip, p, timeout): p for p in port_list}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return {
        "target": target,
        "host": host,
        "ip": ip,
        "total_scanned": len(port_list),
        "open_ports": open_ports,
        "total_open": len(open_ports),
    }
