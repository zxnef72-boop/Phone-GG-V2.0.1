# ============================================================
#  HTTP Utilities for PhoneGG
#  Safe HTTP requests with timeout and error handling
# ============================================================
import requests
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

def safe_http_request(
    url: str,
    method: str = "GET",
    timeout: int = 2,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None
) -> Optional[requests.Response]:
    """
    Make HTTP request with timeout and error handling.
    
    Args:
        url: Target URL
        method: HTTP method (GET, POST, HEAD, etc.)
        timeout: Request timeout in seconds (default: 2)
        headers: Request headers
        params: URL parameters
        data: Form data
        json_data: JSON data
    
    Returns:
        Response object or None if request fails
    """
    try:
        response = requests.request(
            method=method,
            url=url,
            timeout=timeout,
            headers=headers,
            params=params,
            data=data,
            json=json_data
        )
        return response
    except requests.Timeout:
        logger.warning(f"Request timeout for {url}")
        return None
    except requests.RequestException as e:
        logger.warning(f"Request failed for {url}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error requesting {url}: {str(e)}")
        return None

def safe_get(url: str, timeout: int = 2, **kwargs) -> Optional[requests.Response]:
    """Safe GET request with timeout."""
    return safe_http_request(url, method="GET", timeout=timeout, **kwargs)

def safe_post(url: str, timeout: int = 2, **kwargs) -> Optional[requests.Response]:
    """Safe POST request with timeout."""
    return safe_http_request(url, method="POST", timeout=timeout, **kwargs)

def safe_head(url: str, timeout: int = 2, **kwargs) -> Optional[requests.Response]:
    """Safe HEAD request with timeout."""
    return safe_http_request(url, method="HEAD", timeout=timeout, **kwargs)