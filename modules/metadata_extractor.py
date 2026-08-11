"""
Metadata extractor — ambil metadata dari file publik (EXIF gambar, PDF info, dll).
Berguna untuk OSINT: koordinat GPS dari foto, info kamera, timestamp, dll.
"""
from __future__ import annotations
import io
import requests
from urllib.parse import urlparse


def extract_image_metadata(url: str) -> dict:
    """Download gambar dan extract EXIF/metadata via Pillow."""
    try:
        resp = requests.get(url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return {"url": url, "error": f"HTTP {resp.status_code}"}

        from PIL import Image
        from PIL.ExifTags import TAGS

        img = Image.open(io.BytesIO(resp.content))
        info = {
            "url": url,
            "format": img.format,
            "size": img.size,
            "mode": img.mode,
            "info_keys": list(img.info.keys()),
        }

        # EXIF data
        exif = img._getexif() if hasattr(img, "_getexif") else None
        if exif:
            exif_data = {}
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    value = value.hex()
                exif_data[tag] = value
            info["exif"] = exif_data

            # GPS info
            gps_info = exif_data.get("GPSInfo")
            if gps_info:
                info["gps"] = _parse_gps(gps_info)

        return info
    except ImportError:
        return {"url": url, "error": "Pillow not installed (pip install Pillow)"}
    except Exception as e:
        return {"url": url, "error": str(e)}


def _parse_gps(gps_info: dict) -> dict | None:
    """Parse GPSInfo dari EXIF ke lat/lon decimal."""
    try:
        def convert_to_degrees(value):
            d, m, s = value
            return float(d) + float(m) / 60.0 + float(s) / 3600.0

        lat = convert_to_degrees(gps_info[2])
        lat_ref = gps_info[1]
        if lat_ref == "S":
            lat = -lat

        lon = convert_to_degrees(gps_info[4])
        lon_ref = gps_info[3]
        if lon_ref == "W":
            lon = -lon

        return {"latitude": lat, "longitude": lon,
                "maps_url": f"https://maps.google.com/?q={lat},{lon}"}
    except Exception:
        return None


def extract_pdf_metadata(url: str) -> dict:
    """Download PDF dan extract metadata via PyPDF2."""
    try:
        resp = requests.get(url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return {"url": url, "error": f"HTTP {resp.status_code}"}

        from PyPDF2 import PdfReader
        reader = PdfReader(io.BytesIO(resp.content))
        meta = reader.metadata
        info = {
            "url": url,
            "pages": len(reader.pages),
            "metadata": {},
        }
        if meta:
            for key, value in meta.items():
                info["metadata"][key] = str(value)
        return info
    except ImportError:
        return {"url": url, "error": "PyPDF2 not installed (pip install PyPDF2)"}
    except Exception as e:
        return {"url": url, "error": str(e)}


def extract_metadata(url: str) -> dict:
    """Auto-detect file type dan extract metadata sesuai."""
    parsed = urlparse(url)
    path = parsed.path.lower()

    if any(path.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".tiff", ".webp", ".bmp"]):
        return extract_image_metadata(url)
    elif path.endswith(".pdf"):
        return extract_pdf_metadata(url)
    else:
        return {"url": url, "error": "Format file tidak didukung. Mendukung: jpg, png, tiff, webp, pdf"}
