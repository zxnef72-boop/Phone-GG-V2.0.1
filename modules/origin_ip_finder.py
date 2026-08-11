# ============================================================
#  Origin IP Finder Module for PhoneGG
# ============================================================
import dns.resolver
import logging
import os
from typing import Dict, List, Tuple
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

class OriginIPFinder:
    def __init__(self):
        self.api_keys = {
            'shodan': os.environ.get('SHODAN_API_KEY'),
            'censys_id': os.environ.get('CENSYS_API_ID'),
            'censys_secret': os.environ.get('CENSYS_API_SECRET'),
            'securitytrails': os.environ.get('SECURITYTRAILS_API_KEY'),
        }
    
    def resolve_dns_records(self, domain: str) -> Dict[str, List[str]]:
        results = {'A': [], 'MX': [], 'TXT': [], 'CNAME': [], 'NS': []}
        try:
            try:
                answers = dns.resolver.resolve(domain, 'A')
                results['A'] = [rdata.address for rdata in answers]
            except: pass
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                results['MX'] = [f"{rdata.exchange} ({rdata.preference})" for rdata in answers]
            except: pass
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                results['TXT'] = [rdata.to_text().strip('"') for rdata in answers]
            except: pass
        except Exception as e:
            logger.error(f"DNS resolution failed: {e}")
        return results
    
    def extract_ips_from_mx_records(self, mx_records: List[str]) -> List[str]:
        ips = []
        for mx_record in mx_records:
            hostname = mx_record.split()[0].rstrip('.')
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                for rdata in answers:
                    ip = rdata.address
                    if ip not in ips:
                        ips.append(ip)
            except: pass
        return ips
    
    def extract_ips_from_txt_records(self, txt_records: List[str]) -> List[str]:
        ips = []
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        for txt_record in txt_records:
            found_ips = re.findall(ip_pattern, txt_record)
            for ip in found_ips:
                if self._is_valid_ip(ip) and ip not in ips:
                    ips.append(ip)
        return ips
    
    def _is_valid_ip(self, ip: str) -> bool:
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except: return False
    
    def check_cloudflare_ips(self, domain: str) -> Tuple[List[str], bool]:
        cloudflare_ranges = [
            '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
            '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
            '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
            '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
        ]
        try:
            answers = dns.resolver.resolve(domain, 'A')
            current_ips = [rdata.address for rdata in answers]
            is_cloudflare = any(self._ip_in_ranges(ip, cloudflare_ranges) for ip in current_ips)
            origin_ips = self._check_subdomains(domain) if is_cloudflare else []
            return origin_ips, is_cloudflare
        except Exception as e:
            logger.error(f"Cloudflare check failed: {e}")
            return [], False
    
    def _ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in ipaddress.ip_network(range_str) for range_str in ranges)
        except: return False
    
    def _check_subdomains(self, domain: str) -> List[str]:
        common_subdomains = ['direct', 'origin', 'real', 'cpanel', 'whm', 'mail', 'ftp', 'dev', 'staging', 'blog', 'www', 'api', 'admin']
        origin_ips = []
        for subdomain in common_subdomains:
            test_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(test_domain, 'A')
                for rdata in answers:
                    ip = rdata.address
                    if ip not in origin_ips:
                        origin_ips.append(ip)
            except: continue
        return origin_ips
    
    def find_origin_ip(self, target: str) -> Dict:
        if target.startswith(('http://', 'https://')):
            target = urlparse(target).netloc
        target = target.strip()
        
        results = {
            'target': target,
            'dns_records': {},
            'origin_candidates': [],
            'cloudflare_detected': False,
            'mail_server_ips': [],
            'confidence': 0,
            'findings': []
        }
        
        dns_records = self.resolve_dns_records(target)
        results['dns_records'] = dns_records
        
        if dns_records.get('MX'):
            mail_ips = self.extract_ips_from_mx_records(dns_records['MX'])
            results['mail_server_ips'] = mail_ips
            if mail_ips:
                results['findings'].append({'source': 'MX Records', 'ips': mail_ips, 'confidence': 0.6})
        
        if dns_records.get('TXT'):
            txt_ips = self.extract_ips_from_txt_records(dns_records['TXT'])
            if txt_ips:
                results['findings'].append({'source': 'TXT Records', 'ips': txt_ips, 'confidence': 0.4})
        
        cf_ips, is_cf = self.check_cloudflare_ips(target)
        results['cloudflare_detected'] = is_cf
        if cf_ips:
            results['findings'].append({'source': 'Cloudflare Bypass', 'ips': cf_ips, 'confidence': 0.8})
        
        all_ips = set()
        for finding in results['findings']:
            for ip in finding['ips']:
                all_ips.add(ip)
        for ip in dns_records.get('A', []):
            all_ips.add(ip)
        
        results['origin_candidates'] = list(all_ips)
        results['confidence'] = 0.75 if len(results['findings']) >= 2 else (results['findings'][0]['confidence'] if results['findings'] else 0.3)
        
        return results

_finder = None

def find_origin_ip(target: str) -> dict:
    global _finder
    if _finder is None:
        _finder = OriginIPFinder()
    return _finder.find_origin_ip(target)
