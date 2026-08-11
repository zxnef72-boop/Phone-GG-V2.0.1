"""
Browser automation module — Playwright wrapper untuk screenshot,
page content extraction, dan automated interaction.

Catatan stabilitas: modul ini TIDAK dipakai oleh route manapun di app.py
saat ini, tapi tetap dibuat bulletproof — Playwright browser binary sering
belum ter-install di server produksi (`playwright install chromium`), dan
tanpa penanganan error, import/pemanggilan fungsi ini bisa menyebabkan
500 Internal Server Error yang membingungkan kalau suatu saat dipakai.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except Exception as e:  # ImportError kalau paket belum terinstall sama sekali
    _PLAYWRIGHT_AVAILABLE = False
    _PLAYWRIGHT_IMPORT_ERROR = str(e)
    logger.warning(f"Playwright tidak tersedia: {e}")


def _unavailable(url: str, error: str) -> dict:
    return {"url": url, "status": "error", "error": error}


def screenshot_page(url: str, output_path: str = "screenshot.png",
                    width: int = 1280, height: int = 720,
                    full_page: bool = True, wait_ms: int = 2000) -> dict:
    """Buka URL, tunggu render, screenshot. Tidak pernah raise — selalu
    mengembalikan dict dengan status ok/error."""
    if not _PLAYWRIGHT_AVAILABLE:
        return _unavailable(url, f"Playwright belum terinstall: {_PLAYWRIGHT_IMPORT_ERROR}")
    if not url or not isinstance(url, str):
        return _unavailable(url, "URL tidak valid")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": width, "height": height})
                page.goto(url, wait_until="networkidle", timeout=30000)
                page.wait_for_timeout(wait_ms)
                page.screenshot(path=output_path, full_page=full_page)
                title = page.title()
                return {"url": url, "title": title, "screenshot": output_path, "status": "ok"}
            finally:
                browser.close()
    except Exception as e:
        logger.error(f"screenshot_page gagal untuk {url}: {str(e)}")
        return _unavailable(url, f"Gagal mengambil screenshot: {str(e)}")


def extract_page_content(url: str, wait_ms: int = 2000) -> dict:
    """Buka URL, ambil text content + links. Tidak pernah raise."""
    if not _PLAYWRIGHT_AVAILABLE:
        return _unavailable(url, f"Playwright belum terinstall: {_PLAYWRIGHT_IMPORT_ERROR}")
    if not url or not isinstance(url, str):
        return _unavailable(url, "URL tidak valid")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(url, wait_until="networkidle", timeout=30000)
                page.wait_for_timeout(wait_ms)
                title = page.title()
                text = page.inner_text("body")
                links = page.eval_on_selector_all("a[href]", """
                    els => els.map(e => ({href: e.href, text: e.innerText.trim()}))
                """)
                return {"url": url, "title": title, "text": text[:5000],
                        "links": links[:100], "status": "ok"}
            finally:
                browser.close()
    except Exception as e:
        logger.error(f"extract_page_content gagal untuk {url}: {str(e)}")
        return _unavailable(url, f"Gagal mengekstrak konten: {str(e)}")


def run_browser(url: str) -> dict:
    """Legacy: buka URL di browser visible (headed). Tidak pernah raise."""
    if not _PLAYWRIGHT_AVAILABLE:
        return _unavailable(url, f"Playwright belum terinstall: {_PLAYWRIGHT_IMPORT_ERROR}")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            try:
                page = browser.new_page()
                page.goto(url)
                title = page.title()
                return {"url": url, "title": title, "status": "ok"}
            finally:
                browser.close()
    except Exception as e:
        logger.error(f"run_browser gagal untuk {url}: {str(e)}")
        return _unavailable(url, f"Gagal membuka browser: {str(e)}")
