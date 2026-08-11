# ============================================================
#  PhoneGG Pen — Repeater Module v2.0
#  Kirim & modifikasi HTTP request custom (method, header, body)
#  ke target yang SUDAH DIBERI IZIN TERTULIS (authorized pentest).
#
#  Modul ini adalah tools generik pengirim HTTP request (mirip
#  Repeater di Burp Suite / Postman) — bukan exploit untuk target
#  tertentu. Perlindungan SSRF memakai security_utils.validate_url_target
#  yang sudah ada di project ini.
#
#  v2.0 Improvements:
#  - Enhanced streaming dengan chunk size optimization
#  - Better error recovery dan validation
#  - Improved response parsing untuk binary/text handling
#  - Connection pooling untuk performance
#  - Comprehensive timeout management
# ============================================================
import time
import logging
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from http.cookies import SimpleCookie

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from security_utils import validate_url_target

logger = logging.getLogger(__name__)

# ── Batasan keamanan & stabilitas ──
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MAX_HEADERS = 50
MAX_HEADER_LEN = 4096
MAX_BODY_BYTES = 1 * 1024 * 1024          # 1 MB — batas body yang dikirim
MAX_RESPONSE_BYTES = 2 * 1024 * 1024      # 2 MB — batas body respons yang dibaca
DEFAULT_TIMEOUT = 10                       # detik
MAX_TIMEOUT = 30
MAX_HISTORY = 50                           # jumlah entri riwayat request per sesi (in-memory)
CHUNK_SIZE = 8192                          # streaming chunk size
TOTAL_RETRIES = 2                          # connection retry attempts
BACKOFF_FACTOR = 0.3

# Header yang tidak boleh dioverride manual (dikelola oleh library HTTP / server)
BLOCKED_REQUEST_HEADERS = {
    "content-length", "host", "connection",
}


def _build_session() -> requests.Session:
    """Build session dengan connection pooling dan automatic retry."""
    session = requests.Session()
    try:
        # Try new urllib3 2.0+ parameter name
        retry_strategy = Retry(
            total=TOTAL_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
    except TypeError:
        # Fallback untuk older urllib3 versions
        retry_strategy = Retry(
            total=TOTAL_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"]
        )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def _safe_str(value, default: str = "") -> str:
    if value is None:
        return default
    try:
        text = str(value)
        return text if text else default
    except Exception:
        return default


def _validate_method(method) -> Tuple[Optional[str], Optional[str]]:
    m = _safe_str(method, "GET").strip().upper()
    if m not in ALLOWED_METHODS:
        return None, f"Method '{m}' tidak didukung. Gunakan salah satu: {', '.join(sorted(ALLOWED_METHODS))}"
    return m, None


def normalize_headers_for_display(raw_headers) -> Dict[str, str]:
    """
    Ubah headers dari format apapun (list of {"key","value"} ATAU dict biasa)
    jadi dict {key: value} yang aman ditampilkan/disimpan di history — tanpa
    validasi ketat (dipakai juga untuk mencatat percobaan request yang GAGAL,
    supaya formatnya tetap konsisten dengan entri yang berhasil).
    """
    result: Dict[str, str] = {}
    if raw_headers is None:
        return result
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            k_s = _safe_str(k).strip()
            if k_s:
                result[k_s] = _safe_str(v)
        return result
    if isinstance(raw_headers, list):
        for item in raw_headers:
            if isinstance(item, dict):
                k_s = _safe_str(item.get("key")).strip()
                if k_s:
                    result[k_s] = _safe_str(item.get("value"))
    return result


def _validate_headers(raw_headers) -> Tuple[Dict[str, str], Optional[str]]:
    """
    raw_headers diterima dalam bentuk list of {"key": ..., "value": ...}
    (sesuai UI key-value editor) ATAU dict biasa. Selalu dikembalikan sebagai dict.
    """
    headers: Dict[str, str] = {}

    if raw_headers is None:
        return headers, None

    pairs: List[Tuple[Any, Any]] = []
    if isinstance(raw_headers, dict):
        pairs = list(raw_headers.items())
    elif isinstance(raw_headers, list):
        for item in raw_headers:
            if isinstance(item, dict):
                pairs.append((item.get("key"), item.get("value")))
    else:
        return headers, "Format headers tidak valid (harus object atau array key-value)"

    if len(pairs) > MAX_HEADERS:
        return headers, f"Jumlah header melebihi batas maksimum ({MAX_HEADERS})"

    for key, value in pairs:
        key_s = _safe_str(key).strip()
        value_s = _safe_str(value)
        if not key_s:
            continue  # baris kosong dari UI, lewati saja
        if key_s.lower() in BLOCKED_REQUEST_HEADERS:
            continue  # header terkelola otomatis, jangan biarkan dioverride manual
        if len(key_s) > MAX_HEADER_LEN or len(value_s) > MAX_HEADER_LEN:
            return headers, f"Panjang header '{key_s}' melebihi batas"
        headers[key_s] = value_s

    return headers, None


def _build_cookie_header(cookies) -> Optional[str]:
    """
    Terima cookie jar dari frontend dalam bentuk dict {"name": "value"}
    dan susun jadi satu string header Cookie: "name1=value1; name2=value2".
    Tidak pernah melempar exception.
    """
    if not cookies or not isinstance(cookies, dict):
        return None
    parts = []
    for name, value in cookies.items():
        name_s = _safe_str(name).strip()
        value_s = _safe_str(value)
        if not name_s:
            continue
        parts.append(f"{name_s}={value_s}")
    return "; ".join(parts) if parts else None


def _extract_set_cookies(resp, request_url: str) -> List[Dict[str, Any]]:
    """
    Ekstrak semua header Set-Cookie dari response (bisa lebih dari satu),
    parse atribut domain/path/expires/secure/httponly/samesite-nya, supaya
    frontend bisa update cookie jar per-domain.
    """
    results: List[Dict[str, Any]] = []
    try:
        raw_values: List[str] = []
        # requests menyimpan banyak Set-Cookie via resp.raw (urllib3 HTTPHeaderDict)
        if getattr(resp, "raw", None) is not None and hasattr(resp.raw, "headers"):
            try:
                raw_values = resp.raw.headers.get_all("Set-Cookie") or []
            except AttributeError:
                # HTTPHeaderDict versi lama pakai getlist()
                try:
                    raw_values = resp.raw.headers.getlist("Set-Cookie") or []
                except Exception:
                    raw_values = []
        if not raw_values and resp.headers.get("Set-Cookie"):
            raw_values = [resp.headers.get("Set-Cookie")]

        default_domain = urlparse(request_url).hostname or ""

        for raw in raw_values:
            try:
                jar = SimpleCookie()
                jar.load(raw)
                for name, morsel in jar.items():
                    results.append({
                        "name": name,
                        "value": morsel.value,
                        "domain": morsel["domain"].lstrip(".") or default_domain,
                        "path": morsel["path"] or "/",
                        "expires": morsel["expires"] or None,
                        "secure": bool(morsel["secure"]),
                        "http_only": bool(morsel["httponly"]),
                        "same_site": morsel["samesite"] or None,
                        "raw": raw[:500],
                    })
            except Exception as e:
                logger.warning(f"[pen_repeater] Gagal parsing Set-Cookie: {e}")
                continue
    except Exception as e:
        logger.warning(f"[pen_repeater] _extract_set_cookies gagal: {e}")
    return results


def send_pen_request(
    url: str,
    method: str = "GET",
    headers=None,
    body: Optional[str] = None,
    timeout: Optional[int] = None,
    follow_redirects: bool = False,
    cookies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Kirim satu HTTP request custom dan kembalikan hasilnya dalam format
    yang aman untuk ditampilkan di UI (mirip panel Response di Burp Repeater).

    Fungsi ini TIDAK PERNAH melempar exception — semua kegagalan (validasi,
    koneksi, timeout, dsb) dikembalikan sebagai dict {"ok": False, "error": ...}.

    Args:
        url: Target URL (divalidasi lewat validate_url_target — SSRF-safe)
        method: HTTP method
        headers: dict atau list [{"key","value"}] header request
        body: string body request (dipakai untuk POST/PUT/PATCH)
        timeout: timeout detik (dibatasi MAX_TIMEOUT)
        follow_redirects: ikuti redirect 3xx atau tidak (default: False,
            supaya user bisa lihat response redirect mentah dulu — sama
            seperti perilaku default Burp Repeater)
        cookies: dict {"name": "value"} dari cookie jar frontend. Dipakai
            untuk membangun header Cookie otomatis — hanya jika user
            belum mengisi header 'Cookie' secara manual (manual override
            selalu menang).

    Returns:
        dict siap dikirim sebagai JSON ke frontend
    """
    try:
        # ── Validasi URL (reuse proteksi SSRF yang sudah ada di project) ──
        url_s = _safe_str(url).strip()
        if not url_s:
            return {"ok": False, "error": "URL tujuan wajib diisi"}
        if not url_s.startswith(("http://", "https://")):
            url_s = f"https://{url_s}"

        is_valid, ssrf_msg = validate_url_target(url_s)
        if not is_valid:
            return {"ok": False, "error": ssrf_msg or "URL tidak valid atau diblokir"}

        # ── Validasi method ──
        method_s, method_err = _validate_method(method)
        if method_err:
            return {"ok": False, "error": method_err}

        # ── Validasi headers ──
        headers_dict, header_err = _validate_headers(headers)
        if header_err:
            return {"ok": False, "error": header_err}

        # ── Cookie jar: hanya diterapkan kalau user belum set header Cookie manual ──
        has_manual_cookie_header = any(k.lower() == "cookie" for k in headers_dict.keys())
        if not has_manual_cookie_header:
            cookie_header = _build_cookie_header(cookies)
            if cookie_header:
                headers_dict["Cookie"] = cookie_header

        # ── Validasi body ──
        body_s = body if isinstance(body, str) else (_safe_str(body) if body else "")
        body_bytes = body_s.encode("utf-8", errors="replace")
        if len(body_bytes) > MAX_BODY_BYTES:
            return {"ok": False, "error": f"Body request melebihi batas maksimum ({MAX_BODY_BYTES // 1024} KB)"}

        # ── Validasi timeout ──
        try:
            timeout_s = int(timeout) if timeout else DEFAULT_TIMEOUT
        except (TypeError, ValueError):
            timeout_s = DEFAULT_TIMEOUT
        timeout_s = max(1, min(timeout_s, MAX_TIMEOUT))

        # ── Kirim request dengan session pooling ──
        session = _build_session()
        resp = None
        start = time.monotonic()
        raw_body = b""
        body_size = 0
        truncated = False
        
        try:
            resp = session.request(
                method=method_s,
                url=url_s,
                headers=headers_dict or None,
                data=body_bytes if method_s in {"POST", "PUT", "PATCH", "DELETE"} and body_bytes else None,
                timeout=(5, timeout_s),  # (connect, read) timeout
                allow_redirects=follow_redirects,
                stream=True,
            )
            
            # ── Baca body respons dengan batas ukuran (streaming-safe) ──
            try:
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                    if not chunk:
                        continue
                    body_size += len(chunk)
                    if body_size > MAX_RESPONSE_BYTES:
                        truncated = True
                        break
                    raw_body += chunk
            except Exception as e:
                logger.warning(f"[pen_repeater] Error reading response body: {e}")
                truncated = True
                
        except requests.exceptions.Timeout:
            return {"ok": False, "error": f"Request timeout setelah {timeout_s} detik"}
        except requests.exceptions.SSLError as e:
            return {"ok": False, "error": f"Kesalahan SSL/TLS: {str(e)[:100]}"}
        except requests.exceptions.ConnectionError as e:
            return {"ok": False, "error": f"Gagal konek ke target: {str(e)[:100]}"}
        except requests.exceptions.RequestException as e:
            return {"ok": False, "error": f"Request gagal: {str(e)[:100]}"}
        except Exception as e:
            logger.error(f"[pen_repeater] Unexpected error: {e}")
            return {"ok": False, "error": f"Kesalahan tidak terduga: {str(e)[:100]}"}
        finally:
            if resp:
                try:
                    resp.close()
                except Exception:
                    pass
            if session:
                try:
                    session.close()
                except Exception:
                    pass

        if resp is None:
            return {"ok": False, "error": "Response object tidak tersedia"}

        elapsed_ms = round((time.monotonic() - start) * 1000, 1)

        content_type = resp.headers.get("Content-Type", "")
        try:
            body_text = raw_body.decode("utf-8", errors="replace")
        except Exception:
            body_text = f"[Binary content: {len(raw_body)} bytes]"

        return {
            "ok": True,
            "request": {
                "method": method_s,
                "url": url_s,
                "headers": headers_dict,
                "body": body_s,
            },
            "response": {
                "status_code": resp.status_code,
                "reason": resp.reason or "No Reason",
                "headers": dict(resp.headers) if resp.headers else {},
                "content_type": content_type,
                "body": body_text,
                "body_truncated": truncated,
                "body_size_bytes": body_size,
                "elapsed_ms": elapsed_ms,
                "redirected": len(resp.history) > 0 if hasattr(resp, "history") else False,
                "final_url": resp.url or url_s,
                "set_cookies": _extract_set_cookies(resp, url_s),
            },
        }

    except Exception as e:
        # Lapisan pertahanan terakhir — jangan pernah biarkan exception
        # menjalar ke app.py.
        logger.error(f"[pen_repeater] send_pen_request gagal total: {e}")
        return {"ok": False, "error": f"Terjadi kesalahan internal: {e}"}


def parse_raw_request(raw_text: str) -> Dict[str, Any]:
    """
    Parsing request mentah gaya Burp (raw HTTP request text) menjadi
    method/url/headers/body — supaya user bisa paste request dari
    browser DevTools / proxy lain langsung ke Repeater.

    Format yang didukung:
        METHOD /path HTTP/1.1
        Host: example.com
        Header: value

        body...

    Tidak pernah melempar exception; mengembalikan {"ok": False, "error": ...}
    jika format tidak bisa diparsing.
    """
    try:
        if not isinstance(raw_text, str) or not raw_text.strip():
            return {"ok": False, "error": "Raw request kosong"}

        # Normalisasi line ending
        text = raw_text.replace("\r\n", "\n")
        lines = text.split("\n")

        if not lines:
            return {"ok": False, "error": "Raw request tidak valid"}

        # Baris pertama: METHOD path HTTP/x.x
        first_line = lines[0].strip()
        parts = first_line.split()
        if len(parts) < 2:
            return {"ok": False, "error": "Baris pertama tidak valid, format: METHOD /path HTTP/1.1"}

        method_s, method_err = _validate_method(parts[0])
        if method_err:
            return {"ok": False, "error": method_err}

        path = parts[1]

        # Parse headers sampai baris kosong
        headers: Dict[str, str] = {}
        idx = 1
        while idx < len(lines) and lines[idx].strip() != "":
            line = lines[idx]
            if ":" in line:
                k, v = line.split(":", 1)
                k_s, v_s = k.strip(), v.strip()
                if k_s and k_s.lower() not in BLOCKED_REQUEST_HEADERS and len(headers) < MAX_HEADERS:
                    headers[k_s] = v_s
            idx += 1

        # Sisanya adalah body
        body = "\n".join(lines[idx + 1:]) if idx + 1 < len(lines) else ""

        # Susun URL dari Host header + path
        host = headers.get("Host") or headers.get("host")
        if not host:
            return {"ok": False, "error": "Header 'Host' wajib ada di raw request untuk menentukan target URL"}

        scheme = "https"  # default aman; user bisa override lewat field URL di UI kalau perlu http://
        url = f"{scheme}://{host}{path}"

        return {
            "ok": True,
            "method": method_s,
            "url": url,
            "headers": headers,
            "body": body,
        }

    except Exception as e:
        logger.error(f"[pen_repeater] parse_raw_request gagal: {e}")
        return {"ok": False, "error": f"Gagal parsing raw request: {e}"}
