# ============================================================
#  Security Utilities for PhoneGG
#  SSRF Protection, Input Sanitization, and Security Headers
# ============================================================
import re
import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import Optional, Tuple

# RFC 1918 private IP ranges
PRIVATE_IP_RANGES = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
]

# Blocked hostnames and IPs
BLOCKED_HOSTS = {
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '169.254.169.254',  # AWS metadata
    'metadata.google.internal',  # GCP metadata
}

def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address is in private range (RFC 1918).
    
    Args:
        ip_str: IP address string
    
    Returns:
        True if IP is private, False otherwise
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        for private_range in PRIVATE_IP_RANGES:
            if ip in private_range:
                return True
        return False
    except (ipaddress.AddressValueError, ValueError):
        return False

def validate_url_target(target: str) -> Tuple[bool, Optional[str]]:
    """
    Validate URL target to prevent SSRF attacks.
    
    Args:
        target: URL or IP address string
    
    Returns:
        Tuple of (is_valid, error_message)
        - (True, None) if valid
        - (False, error_message) if invalid
    """
    if not target or not target.strip():
        return False, "Target tidak boleh kosong"
    
    target = target.strip()
    
    # Check if it's a hostname
    if target.lower() in BLOCKED_HOSTS:
        return False, "Target URL/IP tidak diizinkan (hostname diblokir)"
    
    # Check if it's an IP address
    try:
        ip = ipaddress.IPv4Address(target)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False, "Target URL/IP tidak diizinkan (IP private diblokir)"
        if str(ip) in BLOCKED_HOSTS:
            return False, "Target URL/IP tidak diizinkan (IP diblokir)"
    except (ipaddress.AddressValueError, ValueError):
        pass  # Not an IP, continue with URL validation
    
    # Parse as URL
    try:
        parsed = urlparse(target if target.startswith(('http://', 'https://')) else f'https://{target}')
        hostname = parsed.hostname or parsed.netloc.split(':')[0]
        
        # Check hostname against blocked list
        if hostname.lower() in BLOCKED_HOSTS:
            return False, "Target URL/IP tidak diizinkan (hostname diblokir)"
        
        # Check if hostname resolves to private IP
        try:
            ip = ipaddress.IPv4Address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, "Target URL/IP tidak diizinkan (IP private diblokir)"
        except (ipaddress.AddressValueError, ValueError):
            pass  # Not an IP, likely a domain name
        
        # Additional checks for suspicious patterns
        if re.search(r'[<>"\'\n\r]', target):
            return False, "Target mengandung karakter tidak valid"
        
        return True, None
        
    except Exception as e:
        return False, f"Target URL tidak valid: {str(e)}"

def sanitize_input(input_string: str, max_length: int = 255) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks.
    
    Args:
        input_string: Raw user input
        max_length: Maximum allowed length
    
    Returns:
        Sanitized string
    """
    if not input_string:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\'\n\r\t]', '', str(input_string))
    
    # Limit length
    sanitized = sanitized[:max_length]
    
    # Strip whitespace
    sanitized = sanitized.strip()
    
    return sanitized

def sanitize_username(username: str) -> str:
    """
    Sanitize username input (allow only alphanumeric and common characters).
    
    Args:
        username: Raw username input
    
    Returns:
        Sanitized username
    """
    if not username:
        return ""
    
    # Allow only alphanumeric, underscore, hyphen, and dot
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '', str(username))
    
    # Limit length
    sanitized = sanitized[:50]
    
    return sanitized.strip()

def get_security_headers() -> dict:
    """
    Get HTTP security headers for Flask responses.
    
    Returns:
        Dictionary of security headers
    """
    return {
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; img-src 'self' data: https: blob:; font-src 'self' data: https://cdnjs.cloudflare.com; connect-src 'self' https:;",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }

def apply_security_headers(response):
    """
    Apply security headers to Flask response object.
    
    Args:
        response: Flask response object
    
    Returns:
        Response with security headers applied
    """
    headers = get_security_headers()
    for key, value in headers.items():
        response.headers[key] = value
    # Cegah browser nyimpen cache halaman ber-sesi (dashboard, hasil lookup, dst)
    # supaya tombol "Back" setelah logout tidak menampilkan ulang halaman lama
    # dari cache lokal — HTML/JSON only, aset statis (CSS/JS/gambar) tidak kena.
    ctype = response.content_type or ""
    if "text/html" in ctype or "application/json" in ctype:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response