# 🔍 PhoneGG — OSINT Toolkit

**PhoneGG** adalah toolkit OSINT (*Open Source Intelligence*) berbasis Flask untuk investigasi nomor HP, email, username, domain, dan web target — lengkap dengan web UI, REST API, dan dukungan PWA.

Dibangun oleh **NefZx**.

---

## ✨ Fitur

### Investigasi Identitas
| Fitur | Deskripsi |
|-------|-----------|
| 📱 Phone Lookup | Validasi nomor ID, cek status WhatsApp, deteksi operator, Google dork multi-platform |
| 📧 Email Lookup | HIBP breach check, Gravatar, domain WHOIS + DNS, email reputation, dork multi-platform |
| 👤 Username Search | Cek ketersediaan username di 60+ platform sosial media |
| 🎯 Dork Generator | Google/Bing/DDG dork untuk phone & email (30+ query template) |
| 🕵️ Breach Search | HIBP + BreachDirectory + IntelX + Dehashed links |

### Analisis Web & Domain
| Fitur | Deskripsi |
|-------|-----------|
| 🛡️ Vuln Scanner | Domain vulnerability scan (butuh `nuclei` terinstall) |
| 📂 Dir Enumeration | 150+ path umum dengan risk categorization & soft-404 detection |
| ⚠️ 404 Checker | HTTP status, redirect chain, SSL cert info, soft-404 detection |
| 🔒 Security Headers | CSP, HSTS, X-Frame-Options, dll + skor & grade |
| 🧩 Tech Detect | CMS, framework, web server, CDN, analytics, JS library fingerprinting |
| 🌐 Subdomain Enum | crt.sh + DNS brute-force + search engine dork (200+ prefix) |
| 🕰️ Wayback Lookup | Snapshot historis via web.archive.org |
| 🔌 Port Scanner | TCP connect scan (50+ port umum, mode extended 100+) |
| ⚡ CORS Checker | Deteksi misconfiguration (wildcard, reflection, null origin, credentials) |
| 🚨 Subdomain Takeover | CNAME + dangling DNS check (14 layanan) |
| 📍 IP Geolocation | ip-api.com + ipinfo.io — ASN, ISP, deteksi proxy |
| 🖼️ Metadata Extractor | EXIF/GPS dari gambar, metadata PDF |

### Tools Tambahan
| Fitur | Deskripsi |
|-------|-----------|
| 🧰 Pen Repeater | Tool HTTP request untuk pentest berizin — mirip tab Repeater di Burp Suite, dilengkapi history & multi-tab |
| 💻 Net Tools Console | Terminal whitelist-only (whois, dig, ping, traceroute, curl, dll) langsung dari browser |

---

## 🚀 Instalasi

**Otomatis:**
```bash
chmod +x install.sh
./install.sh
```

**Manual:**
```bash
pip install -r requirements.txt
cp .env.example .env   # isi API key kamu
```

## ▶️ Menjalankan

```bash
python3 app.py
```

- Web UI: `http://localhost:5000`
- API Docs (Swagger): `http://localhost:5000/apidocs/`

---

## 📡 API Endpoints

Semua endpoint API membutuhkan header `X-API-Key`.

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

---

## ⚙️ Environment Variables

| Variable | Deskripsi |
|----------|-----------|
| `API_KEY` | API key untuk autentikasi endpoint |
| `GOOGLE_API_KEY` | Google Custom Search API key |
| `GOOGLE_CX` | Google Custom Search Engine ID |
| `HIBP_API_KEY` | HaveIBeenPwned API key (opsional) |

> Jika `API_KEY` tidak diset, PhoneGG akan otomatis membuat key acak saat startup (dengan peringatan di console) — jangan andalkan ini untuk production.

---

## 🧱 Tech Stack

Python 3 · Flask · Vanilla JS · PWA (manifest + service worker)

---

## ⚠️ Disclaimer

Proyek ini lahir dari sebuah ketulusan untuk saling menjaga di ruang digital. Didedikasikan murni untuk edukasi, keamanan bersama, dan harapan agar tidak ada lagi sesama yang dirugikan oleh kejahatan siber.

Gunakan hanya pada target yang **kamu miliki izin resmi** untuk mengujinya. Penyalahgunaan alat ini di luar tanggung jawab pembuat.

Semoga karya sederhana ini bisa menjadi tangan penolong dan bermanfaat bagi siapa saja yang membutuhkan.
