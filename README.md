# PhoneGG — OSINT Toolkit

OSINT (Open Source Intelligence) toolkit berbasis Flask untuk investigasi nomor HP, email, username, domain, dan web target.

## Fitur

| Fitur | Deskripsi |
|-------|-----------|
| Phone Lookup | Validasi nomor ID, cek WhatsApp, operator, Google dork multi-platform |
| Email Lookup | HIBP breach check, Gravatar, domain WHOIS+DNS, email reputation, dork multi-platform |
| Username Search | 60+ platform social media check |
| Dork Generator | Google/Bing/DDG dork untuk phone & email (30+ query templates) |
| Vuln Scanner | Domain vulnerability scan (butuh nuclei eksternal) |
| Dir Enumeration | 150+ path umum dengan risk categorization & soft-404 detection |
| 404 Checker | HTTP status, redirect chain, SSL cert info, soft-404 |
| Security Headers | CSP, HSTS, X-Frame-Options, dll + skor & grade |
| Tech Detect | CMS, framework, web server, CDN, analytics, JS library fingerprinting |
| **Subdomain Enum** | crt.sh + DNS brute-force + search engine dorks (200+ prefixes) |
| **Wayback Lookup** | Historical snapshots via web.archive.org |
| **Port Scanner** | TCP connect scan (50+ common ports, extended 100+) |
| **CORS Checker** | Misconfiguration detection (wildcard, reflection, null origin, credentials) |
| **Subdomain Takeover** | CNAME + dangling DNS check (14 services) |
| **Breach Search** | HIBP + BreachDirectory + IntelX + Dehashed links |
| **IP Geolocation** | ip-api.com + ipinfo.io, ASN, ISP, proxy detection |
| **Metadata Extractor** | EXIF/GPS dari gambar, PDF metadata |

## Instalasi

```bash
chmod +x install.sh
./install.sh
```

Atau manual:
```bash
pip install -r requirements.txt
cp .env.example .env # isi API key
```

## Menjalankan

```bash
python3 app.py
# Web: http://localhost:5000
# API Docs: http://localhost:5000/apidocs/
```

## API Endpoints

Semua API endpoint butuh header `X-API-Key`.

| Method | Endpoint | Parameter |
|--------|----------|-----------|
| POST | `/api/v1/phone` | `{"number": "0812xxx"}` |
| POST | `/api/v1/email` | `{"email": "a@b.com"}` |
| POST | `/api/v1/username` | `{"username": "target"}` |
| POST | `/api/v1/vuln` | `{"target": "domain.com", "severity": "medium"}` |
| POST | `/api/v1/dir` | `{"target": "https://domain.com"}` |
| POST | `/api/v1/dork` | `{"target": "...", "type": "phone\|email"}` |
| POST | `/api/v1/check404` | `{"url": "https://..."}` |
| POST | `/api/v1/security-headers` | `{"url": "https://..."}` |
| POST | `/api/v1/tech-detect` | `{"url": "https://..."}` |
| POST | `/api/v1/subdomain` | `{"target": "domain.com"}` |
| POST | `/api/v1/wayback` | `{"url": "https://..."}` |
| POST | `/api/v1/portscan` | `{"target": "domain.com", "extended": false}` |
| POST | `/api/v1/cors` | `{"url": "https://..."}` |
| POST | `/api/v1/takeover` | `{"subdomains": ["a.com", "b.com"]}` |
| POST | `/api/v1/breach` | `{"email": "a@b.com"}` |
| POST | `/api/v1/ipinfo` | `{"target": "1.2.3.4"}` |
| POST | `/api/v1/metadata` | `{"url": "https://.../photo.jpg"}` |

## Environment Variables

| Variable | Deskripsi |
|----------|-----------|
| `API_KEY` | API key untuk autentikasi endpoint |
| `GOOGLE_API_KEY` | Google Custom Search API key |
| `GOOGLE_CX` | Google Custom Search Engine ID |
| `HIBP_API_KEY` | HaveIBeenPwned API key (opsional) |

## Disclaimer

Proyek ini lahir dari sebuah ketulusan untuk saling menjaga di ruang digital. Didedikasikan murni untuk edukasi, keamanan bersama, dan harapan agar tidak ada lagi sesama yang dirugikan oleh kejahatan siber. Semoga karya sederhana ini bisa menjadi tangan penolong dan bermanfaat bagi siapa saja yang membutuhkan
