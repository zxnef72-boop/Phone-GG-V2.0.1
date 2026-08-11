"""
Social media username probe (Sherlock-style OSINT) v2.0

Checks whether a username is registered on a curated list of platforms by
combining two detection signals:

  1. HTTP status code  - the classic case where a platform returns a real
     404 (or 401/403/429 when a profile exists but the request is blocked).
  2. Response body text - many platforms return HTTP 200 for every request
     and instead render a generic "user not found" page (a "soft 404").
     For those, a known error string is matched against the response body.

Each platform entry in PLATFORMS declares which signal(s) to use, so the
checker behaves correctly per-site instead of assuming status codes alone.

v2.0 Improvements:
- Better concurrency dengan thread pool management
- Enhanced timeout handling dengan per-request tuning
- Improved error recovery dan retry logic
- Better connection pooling dengan size optimization
- Safer exception handling untuk network issues
"""
from __future__ import annotations

import time
import concurrent.futures
import logging
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ============================================================
#  Platform database
# ============================================================
# url          - profile URL template, must contain {username}
# category     - used for grouping in the UI
# error_type   - "status_code" (default), "message", or "status_and_message"
# error_msg    - string or list of strings (case-insensitive substring
#                match against the response body) that indicate the
#                profile does NOT exist, even on a 200 OK response
# reliable     - False marks platforms known to block/obfuscate plain HTTP
#                clients (heavy JS rendering, bot walls, login gates).
#                Results are still returned but should be shown as
#                lower-confidence in the UI.
#
# Only a subset of entries below have a verified error_msg populated.
# The rest default to status-code detection; add error_msg entries here
# as they get verified to improve accuracy over time.

PLATFORMS = {
    # Mainstream
    "Facebook":       {"url": "https://www.facebook.com/{username}", "category": "mainstream", "reliable": False},
    "Twitter/X":      {"url": "https://x.com/{username}", "category": "mainstream", "reliable": False},
    "Instagram":      {"url": "https://www.instagram.com/{username}", "category": "mainstream", "reliable": False},
    "LinkedIn":       {"url": "https://www.linkedin.com/in/{username}", "category": "mainstream", "reliable": False},
    "TikTok":         {"url": "https://www.tiktok.com/@{username}", "category": "mainstream"},
    "YouTube":        {"url": "https://www.youtube.com/@{username}", "category": "mainstream"},
    "Snapchat":       {"url": "https://www.snapchat.com/add/{username}", "category": "mainstream"},
    "Pinterest":      {"url": "https://www.pinterest.com/{username}", "category": "mainstream"},
    "Reddit": {
        "url": "https://www.reddit.com/user/{username}", "category": "mainstream",
        "error_type": "status_and_message",
        "error_msg": "nobody on reddit goes by that name",
    },
    "Tumblr":         {"url": "https://www.tumblr.com/{username}", "category": "mainstream"},
    "Medium":         {"url": "https://medium.com/@{username}", "category": "mainstream"},
    "Quora":          {"url": "https://www.quora.com/profile/{username}", "category": "mainstream"},
    "Flickr":         {"url": "https://www.flickr.com/people/{username}", "category": "mainstream"},
    "Vimeo":          {"url": "https://vimeo.com/{username}", "category": "mainstream"},
    "SoundCloud":     {"url": "https://soundcloud.com/{username}", "category": "mainstream"},
    "Spotify":        {"url": "https://open.spotify.com/user/{username}", "category": "mainstream"},
    "Twitch":         {"url": "https://www.twitch.tv/{username}", "category": "mainstream"},
    "Discord":        {"url": "https://discord.com/users/{username}", "category": "mainstream", "reliable": False},
    "Telegram":       {"url": "https://t.me/{username}", "category": "mainstream", "reliable": False},
    "VK":             {"url": "https://vk.com/{username}", "category": "mainstream"},
    # Developer
    "GitHub":         {"url": "https://github.com/{username}", "category": "developer"},
    "GitLab":         {"url": "https://gitlab.com/{username}", "category": "developer"},
    "Bitbucket":      {"url": "https://bitbucket.org/{username}/", "category": "developer"},
    "Stack Overflow": {"url": "https://stackoverflow.com/users/{username}", "category": "developer"},
    "Dev.to":         {"url": "https://dev.to/{username}", "category": "developer"},
    "HackerNews": {
        "url": "https://news.ycombinator.com/user?id={username}", "category": "developer",
        "error_type": "message",
        "error_msg": "no such user",
    },
    "CodePen":        {"url": "https://codepen.io/{username}", "category": "developer"},
    "Replit":         {"url": "https://replit.com/@{username}", "category": "developer"},
    "Kaggle":         {"url": "https://www.kaggle.com/{username}", "category": "developer"},
    # Gaming
    "Steam": {
        "url": "https://steamcommunity.com/id/{username}", "category": "gaming",
        "error_type": "message",
        "error_msg": "the specified profile could not be found",
    },
    "Roblox":         {"url": "https://www.roblox.com/user.aspx?username={username}", "category": "gaming"},
    "Xbox":           {"url": "https://account.xbox.com/profile?gamertag={username}", "category": "gaming", "reliable": False},
    "PSN":            {"url": "https://psnprofiles.com/{username}", "category": "gaming"},
    "Epic Games":     {"url": "https://store.epicgames.com/u/{username}", "category": "gaming", "reliable": False},
    # Design/Portfolio
    "Behance":        {"url": "https://www.behance.net/{username}", "category": "design"},
    "Dribbble":       {"url": "https://dribbble.com/{username}", "category": "design"},
    "DeviantArt":     {"url": "https://www.deviantart.com/{username}", "category": "design"},
    "ArtStation":     {"url": "https://www.artstation.com/{username}", "category": "design"},
    "Figma":          {"url": "https://www.figma.com/@{username}", "category": "design", "reliable": False},
    # Writing/Blogging
    "WordPress":      {"url": "https://{username}.wordpress.com", "category": "blogging"},
    "Blogger":        {"url": "https://{username}.blogspot.com", "category": "blogging"},
    "Substack":       {"url": "https://{username}.substack.com", "category": "blogging"},
    "Wattpad":        {"url": "https://www.wattpad.com/user/{username}", "category": "blogging"},
    "Goodreads":      {"url": "https://www.goodreads.com/{username}", "category": "blogging"},
    # Niche
    "Keybase":        {"url": "https://keybase.io/{username}", "category": "niche"},
    "Patreon":        {"url": "https://www.patreon.com/{username}", "category": "niche"},
    "BuyMeACoffee":   {"url": "https://www.buymeacoffee.com/{username}", "category": "niche"},
    "Ko-fi":          {"url": "https://ko-fi.com/{username}", "category": "niche"},
    "Linktree":       {"url": "https://linktr.ee/{username}", "category": "niche"},
    "Mastodon":       {"url": "https://mastodon.social/@{username}", "category": "niche"},
    "Bluesky":        {"url": "https://bsky.app/profile/{username}", "category": "niche", "reliable": False},
    "Threads":        {"url": "https://www.threads.net/@{username}", "category": "niche", "reliable": False},
    # Indonesian
    "Kaskus":         {"url": "https://www.kaskus.co.id/@{username}", "category": "indonesian"},
    "Detik Forum":    {"url": "https://forum.detik.com/member.php?u={username}", "category": "indonesian"},
    # Crypto
    "Coinbase":       {"url": "https://www.coinbase.com/{username}", "category": "crypto", "reliable": False},
    "Binance":        {"url": "https://www.binance.com/en/u/{username}", "category": "crypto", "reliable": False},
    # Dating
    "Tinder":         {"url": "https://www.tinder.com/@{username}", "category": "dating", "reliable": False},
    "Bumble":         {"url": "https://bumble.com/app/{username}", "category": "dating", "reliable": False},
    # Other
    "About.me":       {"url": "https://about.me/{username}", "category": "other"},
    "Gravatar":       {"url": "https://gravatar.com/{username}", "category": "other"},
    "Wikipedia":      {"url": "https://en.wikipedia.org/wiki/User:{username}", "category": "other"},
    "Last.fm":        {"url": "https://www.last.fm/user/{username}", "category": "other"},
    "Bandcamp":       {"url": "https://{username}.bandcamp.com", "category": "other"},
    "Mixcloud":       {"url": "https://www.mixcloud.com/{username}", "category": "other"},
    "Product Hunt":   {"url": "https://www.producthunt.com/@{username}", "category": "other"},
    "AngelList":      {"url": "https://angel.co/u/{username}", "category": "other"},
    "Crunchbase":     {"url": "https://www.crunchbase.com/person/{username}", "category": "other"},
    "Freelancer":     {"url": "https://www.freelancer.com/u/{username}", "category": "freelance"},
    "Fiverr":         {"url": "https://www.fiverr.com/{username}", "category": "freelance"},
    "Upwork":         {"url": "https://www.upwork.com/freelancers/{username}", "category": "freelance"},
}

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

REQUEST_TIMEOUT = 8       # seconds (connect=4, read=8)
BODY_READ_LIMIT = 200_000 # bytes; enough for a soft-404 phrase, cheap to fetch
CONNECT_TIMEOUT = 4       # seconds for initial connection
READ_TIMEOUT = 8          # seconds for reading response
MAX_RETRIES = 2           # retry attempts untuk transient failures
BACKOFF_FACTOR = 0.2      # exponential backoff multiplier

STATUS_FOUND = "found"
STATUS_NOT_FOUND = "not_found"
STATUS_MAYBE = "maybe"      # blocked / rate-limited, existence unconfirmed
STATUS_UNKNOWN = "unknown"  # unexpected response, inconclusive
STATUS_ERROR = "error"      # network/connection failure


def _build_session(pool_size: int) -> requests.Session:
    """Shared session dengan connection pooling dan automatic retry.
    
    Pool disize ke worker count supaya concurrent requests reuse 
    TCP/TLS connections efficiently.
    """
    session = requests.Session()
    
    # Retry strategy untuk transient network failures
    try:
        # Try new urllib3 2.0+ parameter name
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"]
        )
    except TypeError:
        # Fallback untuk older urllib3 versions
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "POST"]
        )
    
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=pool_size,
        pool_maxsize=pool_size
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(DEFAULT_HEADERS)
    return session


def _read_partial_body(resp: requests.Response, limit: int = BODY_READ_LIMIT) -> str:
    """Read only the first `limit` bytes of a streamed response, then stop -
    enough to find an error phrase without downloading a full page/asset."""
    chunks, total = [], 0
    for chunk in resp.iter_content(chunk_size=8192):
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    return b"".join(chunks).decode(resp.encoding or "utf-8", errors="ignore")


def _matches_error_msg(body: str, error_msg) -> bool:
    if not error_msg or not body:
        return False
    needles = [error_msg] if isinstance(error_msg, str) else list(error_msg)
    body_lower = body.lower()
    return any(needle.lower() in body_lower for needle in needles)


def _check_single(session: requests.Session, platform: str, cfg: dict, username: str) -> dict:
    """Check single platform dengan timeout tuning dan error recovery."""
    try:
        url = cfg["url"].format(username=username)
    except (KeyError, TypeError) as e:
        logger.warning(f"[social_probe] Invalid URL template for {platform}: {e}")
        return {"platform": platform, "url": "", "category": "error", "reliable": False, 
                "status": STATUS_ERROR, "http_code": None, "response_ms": None, "error": "invalid_url"}
    
    category = cfg.get("category", "other")
    reliable = cfg.get("reliable", True)
    error_type = cfg.get("error_type", "status_code")
    error_msg = cfg.get("error_msg")
    needs_body = error_type in ("message", "status_and_message")

    base = {"platform": platform, "url": url, "category": category, "reliable": reliable}
    started = time.monotonic()
    resp = None
    
    try:
        method = "GET" if needs_body else "HEAD"
        # Use tuple timeout: (connect, read)
        timeout = (CONNECT_TIMEOUT, READ_TIMEOUT)
        
        resp = session.request(
            method, url,
            timeout=timeout,
            allow_redirects=True,
            stream=True
        )

        # Server reject HEAD; retry once with GET
        if resp.status_code == 405 and method == "HEAD":
            resp.close()
            resp = None
            method = "GET"
            resp = session.request(
                method, url,
                timeout=timeout,
                allow_redirects=True,
                stream=True
            )

        body = _read_partial_body(resp) if needs_body else ""
        code = resp.status_code
        resp.close()
        resp = None
        elapsed_ms = round((time.monotonic() - started) * 1000)

        # Determine status berdasarkan response code dan body
        if code == 404:
            status = STATUS_NOT_FOUND
        elif code in (401, 403, 429):
            status = STATUS_MAYBE
        elif 200 <= code < 300:
            soft_404 = error_type in ("message", "status_and_message") and _matches_error_msg(body, error_msg)
            status = STATUS_NOT_FOUND if soft_404 else STATUS_FOUND
        else:
            status = STATUS_UNKNOWN

        return {**base, "status": status, "http_code": code, "response_ms": elapsed_ms}

    except requests.Timeout:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        return {**base, "status": STATUS_ERROR, "http_code": None, "response_ms": elapsed_ms, "error": "timeout"}
    except requests.ConnectionError as e:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        logger.debug(f"[social_probe] Connection error for {platform}: {type(e).__name__}")
        return {**base, "status": STATUS_ERROR, "http_code": None, "response_ms": elapsed_ms, "error": "connection_error"}
    except requests.RequestException as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        logger.debug(f"[social_probe] Request error for {platform}: {type(exc).__name__}")
        return {**base, "status": STATUS_ERROR, "http_code": None, "response_ms": elapsed_ms, "error": type(exc).__name__}
    except Exception as e:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        logger.warning(f"[social_probe] Unexpected error for {platform}: {e}")
        return {**base, "status": STATUS_ERROR, "http_code": None, "response_ms": elapsed_ms, "error": "unknown"}
    finally:
        if resp:
            try:
                resp.close()
            except Exception:
                pass


def check_username_detailed(username: str, max_workers: int = 20, platforms: Optional[dict] = None) -> dict:
    """
    Probe every configured platform concurrently and return a structured
    result ready to serialize as JSON for a web UI.

    Returns:
        {
          "username": str,
          "summary": {"total", "found", "not_found", "maybe", "unknown", "error"},
          "results": [
            {"platform", "status", "http_code", "url", "category",
             "reliable", "response_ms"}, ...
          ]
        }
    """
    targets = platforms or PLATFORMS
    session = _build_session(pool_size=max_workers)
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_check_single, session, name, cfg, username): name
                for name, cfg in targets.items()
            }
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
    finally:
        session.close()

    results.sort(key=lambda r: (r["category"], r["platform"]))
    summary = {"total": len(results)}
    for s in (STATUS_FOUND, STATUS_NOT_FOUND, STATUS_MAYBE, STATUS_UNKNOWN, STATUS_ERROR):
        summary[s] = sum(1 for r in results if r["status"] == s)

    return {"username": username, "summary": summary, "results": results}


def check_username(username: str, max_workers: int = 20) -> dict:
    """Backward-compatible shortcut: {platform: status}."""
    detailed = check_username_detailed(username, max_workers=max_workers)
    return {r["platform"]: r["status"] for r in detailed["results"]}
