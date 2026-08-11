# ============================================================
#  PhoneGG — Net Tools Console (WHITELIST command runner)
#  ------------------------------------------------------------
#  PENTING — kenapa ini BUKAN "web terminal / bash console":
#  Endpoint yang menjalankan string command bebas dari browser lewat
#  subprocess adalah remote-code-execution-as-a-feature: siapa pun
#  yang bisa mengirim request ke endpoint itu (bug auth, XSS, URL
#  bocor, dst) dapat shell penuh ke server. Modul ini SENGAJA tidak
#  menerima command bebas sama sekali.
#
#  Desain aman yang dipakai di sini:
#    1. Command yang boleh dijalankan HANYA dari whitelist tetap
#       (ALLOWED_COMMANDS) — user cuma memilih salah satu, tidak
#       pernah mengetik nama command.
#    2. Argumen tiap command dibangun dari template internal;
#       satu-satunya input user (target) divalidasi ketat lewat
#       validate_url_target() (SSRF guard yang sudah ada di
#       security_utils.py — blokir IP privat/loopback/metadata dan
#       karakter berbahaya) sebelum dipakai.
#    3. subprocess dipanggil dengan list argumen (TIDAK PERNAH
#       shell=True), jadi tidak ada shell metacharacter (`;`, `|`,
#       `&&`, backtick, dst) yang bisa dipakai untuk chaining command.
#    4. Setiap eksekusi punya timeout keras dan binary di-cek dulu
#       lewat shutil.which() sebelum dijalankan.
#    5. Semua path ini tetap di belakang @login_required session
#       PhoneGG (lihat app.py) — tidak publik.
# ============================================================
import json
import shutil
import socket
import subprocess
import time
from urllib.parse import quote, urlparse

from security_utils import validate_url_target

# Batas panjang output yang dikembalikan ke browser, biar UI tetap ringan.
_MAX_OUTPUT_CHARS = 20000


def _extract_host(target: str) -> str:
    """Ambil hostname/IP polos dari input yang mungkin berupa URL penuh."""
    t = target.strip()
    if t.startswith(("http://", "https://")):
        parsed = urlparse(t)
        return parsed.hostname or t
    return t


def _http_url(target: str) -> str:
    """Pastikan target punya scheme http(s) untuk tool yang butuh URL penuh."""
    t = target.strip()
    return t if t.startswith(("http://", "https://")) else f"https://{t}"


# Setiap entri: binary, cara membangun argumen dari target yang SUDAH
# divalidasi, timeout (detik), dan deskripsi singkat untuk UI.
ALLOWED_COMMANDS = {
    "whois": {
        "bin": "whois",
        "build_args": lambda t: [_extract_host(t)],
        "timeout": 15,
        "desc": "WHOIS domain/IP lookup",
    },
    "dig": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "ANY", "+noall", "+answer", "+multiline"],
        "timeout": 12,
        "desc": "DNS record lookup (dig)",
    },
    "nslookup": {
        "bin": "nslookup",
        "build_args": lambda t: [_extract_host(t)],
        "timeout": 12,
        "desc": "DNS resolve (nslookup)",
    },
    "ping": {
        "bin": "ping",
        "build_args": lambda t: ["-c", "4", "-W", "3", _extract_host(t)],
        "timeout": 20,
        "desc": "ICMP ping (4 paket)",
    },
    "traceroute": {
        "bin": "traceroute",
        "build_args": lambda t: ["-m", "15", "-w", "2", _extract_host(t)],
        "timeout": 30,
        "desc": "Traceroute (maks 15 hop)",
    },
    "curl_headers": {
        "bin": "curl",
        "build_args": lambda t: ["-sI", "-k", "--max-time", "10", "-A", "PhoneGG-NetTools/1.0", _http_url(t)],
        "timeout": 15,
        "desc": "Ambil response header HTTP (curl -I, skip verifikasi SSL utk target IP)",
    },
    "host": {
        "bin": "host",
        "build_args": lambda t: [_extract_host(t)],
        "timeout": 12,
        "desc": "DNS lookup ringkas (host)",
    },
    "dig_mx": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "MX", "+noall", "+answer"],
        "timeout": 12,
        "desc": "Cek mail server / MX record",
    },
    "dig_txt": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "TXT", "+noall", "+answer"],
        "timeout": 12,
        "desc": "Cek TXT record (SPF/DKIM/verifikasi domain)",
    },
    "curl_body": {
        "bin": "curl",
        "build_args": lambda t: ["-sL", "-k", "--max-time", "10", "-A", "PhoneGG-NetTools/1.0", _http_url(t)],
        "timeout": 15,
        "desc": "Ambil isi halaman + ikuti redirect (curl -sL)",
    },
    "dig_ns": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "NS", "+noall", "+answer"],
        "timeout": 12,
        "desc": "Cek nameserver (NS record)",
    },
    "dig_soa": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "SOA", "+noall", "+answer"],
        "timeout": 12,
        "desc": "Cek SOA record (info zona DNS)",
    },
    "dig_cname": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "CNAME", "+noall", "+answer"],
        "timeout": 12,
        "desc": "Cek CNAME record (alias domain)",
    },
    "dig_ptr": {
        "bin": "dig",
        "build_args": lambda t: ["-x", _extract_host(t), "+noall", "+answer"],
        "timeout": 12,
        "desc": "Reverse DNS lookup (PTR) — target berupa IP",
    },
    "curl_redirects": {
        "bin": "curl",
        "build_args": lambda t: ["-sIL", "-k", "--max-time", "10", "-A", "PhoneGG-NetTools/1.0", _http_url(t)],
        "timeout": 15,
        "desc": "Lacak rantai redirect HTTP (curl -sIL)",
    },
    "curl_timing": {
        "bin": "curl",
        "build_args": lambda t: [
            "-s", "-k", "-o", "/dev/null", "--max-time", "10", "-A", "PhoneGG-NetTools/1.0",
            "-w",
            "DNS: %{time_namelookup}s | Connect: %{time_connect}s | TLS: %{time_appconnect}s | "
            "TTFB: %{time_starttransfer}s | Total: %{time_total}s | HTTP: %{http_code}",
            _http_url(t),
        ],
        "timeout": 15,
        "desc": "Ukur waktu koneksi & respons HTTP (curl -w timing)",
    },
    "host_all": {
        "bin": "host",
        "build_args": lambda t: ["-a", _extract_host(t)],
        "timeout": 12,
        "desc": "Dump semua DNS record via host -a (setara AXFR-style query)",
    },
    "dig_axfr": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "AXFR", "+noall", "+answer"],
        "timeout": 12,
        "desc": "Coba DNS zone transfer (AXFR) — 99% ditolak server; kalau berhasil = misconfig serius",
    },
    "dig_trace": {
        "bin": "dig",
        "build_args": lambda t: ["+trace", "+nodnssec", _extract_host(t)],
        "timeout": 25,
        "desc": "Trace penuh path resolusi DNS dari root server sampai authoritative (dig +trace)",
    },
    "dig_caa": {
        "bin": "dig",
        "build_args": lambda t: [_extract_host(t), "CAA", "+noall", "+answer"],
        "timeout": 12,
        "desc": "Cek CAA record (CA mana saja yang boleh terbitkan sertifikat SSL utk domain ini)",
    },
    "curl_options": {
        "bin": "curl",
        "build_args": lambda t: ["-sI", "-k", "-X", "OPTIONS", "--max-time", "10", "-A", "PhoneGG-NetTools/1.0", _http_url(t)],
        "timeout": 15,
        "desc": "Cek HTTP method yang diizinkan server (curl -X OPTIONS, lihat header Allow)",
    },
    "tracepath": {
        "bin": "tracepath",
        "build_args": lambda t: [_extract_host(t)],
        "timeout": 25,
        "desc": "Trace jalur network ke target tanpa perlu root (alternatif traceroute)",
    },
}

# Command dua-tahap: proses pertama outputnya jadi input (stdin) proses kedua.
# Tetap TIDAK pakai shell=True dan TIDAK pakai pipe shell (|) — setiap tahap
# tetap subprocess.run terpisah dengan argumen list, cuma hasil tahap 1
# diteruskan lewat parameter `input=` ke tahap 2 (setara pipe tapi aman).
CHAINED_COMMANDS = {
    "ssl_info": {
        "desc": "Info sertifikat SSL/TLS (issuer, subject, masa berlaku)",
        "timeout": 15,
    },
    "curl_server_header": {
        "desc": "Deteksi tech stack dari header HTTP (Server, X-Powered-By, dll)",
        "timeout": 15,
    },
    "crt_watch": {
        "desc": "Cek Certificate Transparency log (crt.sh) buat nemuin subdomain/domain terkait yang pernah punya sertifikat SSL",
        "timeout": 20,
    },
    "robots_sitemap": {
        "desc": "Ambil robots.txt + sitemap.xml sekaligus (kadang bocorin path admin/staging)",
        "timeout": 15,
    },
    "shodan_internetdb": {
        "desc": "Query Shodan InternetDB (gratis, tanpa API key) — port terbuka, service, CVE, dan hostname terkait dari internet-wide scan",
        "timeout": 15,
    },
}

# Header yang informatif buat fingerprinting tech stack; header lain di-skip
# biar output nggak berisik (tanggal, cache-control, dst tidak relevan di sini).
_TECH_HEADER_KEYS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish", "via", "cf-ray",
    "x-cache", "x-runtime", "x-framework", "x-turbo-charged-by",
)


def list_commands():
    """Daftar command yang boleh dipilih user di UI (untuk populate <select>)."""
    normal = [{"key": k, "desc": v["desc"]} for k, v in ALLOWED_COMMANDS.items()]
    chained = [{"key": k, "desc": v["desc"]} for k, v in CHAINED_COMMANDS.items()]
    return normal + chained


def _run_ssl_info(target: str, timeout: int) -> dict:
    """
    Ambil info sertifikat SSL/TLS suatu host lewat dua proses berantai:
      1. openssl s_client -connect host:443 -servername host  -> ambil PEM cert
      2. openssl x509 -noout -issuer -subject -dates           -> parse PEM tsb
    Tahap 2 menerima output tahap 1 lewat parameter `input=` (setara pipe),
    bukan lewat shell pipe — jadi tetap shell=False penuh di kedua tahap.
    """
    host = _extract_host(target)
    port = "443"

    if shutil.which("openssl") is None:
        return {"ok": False, "error": "Binary 'openssl' tidak terpasang di server ini."}

    try:
        step1 = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"Command timeout (> {timeout}s)."}
    except Exception as e:
        return {"ok": False, "error": f"Gagal konek ke {host}:{port} — {e}"}

    pem = step1.stdout
    if "BEGIN CERTIFICATE" not in pem:
        return {"ok": False, "error": f"Tidak menemukan sertifikat SSL untuk {host} (mungkin port 443 tertutup atau bukan HTTPS)."}

    try:
        step2 = subprocess.run(
            ["openssl", "x509", "-noout", "-issuer", "-subject", "-dates", "-fingerprint"],
            input=pem,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
    except Exception as e:
        return {"ok": False, "error": f"Gagal parsing sertifikat: {e}"}

    output = (step2.stdout or "") + ((("\n" + step2.stderr) if step2.stderr else ""))
    return {
        "ok": True,
        "command": "ssl_info",
        "bin": "openssl",
        "target": target,
        "exit_code": step2.returncode,
        "output": output.strip() or "(tidak ada output)",
        "truncated": False,
    }


def _run_server_header(target: str, timeout: int) -> dict:
    """
    Ambil header HTTP (curl -sI, subprocess biasa shell=False), lalu filter
    di Python cuma header yang berguna buat fingerprint tech stack. Ini
    chained command (bukan masuk ALLOWED_COMMANDS) karena butuh langkah
    filter tambahan setelah subprocess selesai.
    """
    url = _http_url(target)

    try:
        proc = subprocess.run(
            ["curl", "-sI", "-k", "--max-time", "10", "-A", "PhoneGG-NetTools/1.0", url],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"Command timeout (> {timeout}s)."}
    except Exception as e:
        return {"ok": False, "error": f"Gagal konek ke {url} — {e}"}

    raw = proc.stdout or ""
    matched = []
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        if key.strip().lower() in _TECH_HEADER_KEYS:
            matched.append(f"{key.strip()}: {val.strip()}")

    output = "\n".join(matched) if matched else "(tidak ada header tech-stack yang terdeteksi)"
    return {
        "ok": True,
        "command": "curl_server_header",
        "bin": "curl",
        "target": target,
        "exit_code": proc.returncode,
        "output": output,
        "truncated": False,
    }


def _run_crt_watch(target: str, timeout: int) -> dict:
    """
    Query Certificate Transparency log lewat crt.sh (JSON API) buat nemuin
    subdomain/domain terkait yang pernah punya sertifikat SSL. Fetch pakai
    curl (subprocess biasa, shell=False) — parsing JSON dilakukan di Python,
    bukan lewat library HTTP baru, biar konsisten sama pola modul ini.
    """
    host = _extract_host(target)
    url = f"https://crt.sh/?q={quote(host)}&output=json"

    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", str(max(timeout - 2, 5)), "-A", "PhoneGG-NetTools/1.0", url],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"Command timeout (> {timeout}s)."}
    except Exception as e:
        return {"ok": False, "error": f"Gagal konek ke crt.sh — {e}"}

    raw = (proc.stdout or "").strip()
    if not raw:
        return {"ok": False, "error": "crt.sh tidak mengembalikan data (kemungkinan rate-limited atau domain tidak ditemukan)."}

    try:
        records = json.loads(raw)
    except json.JSONDecodeError:
        return {"ok": False, "error": "Gagal parsing respons crt.sh (format tidak sesuai — kemungkinan rate-limited)."}

    names = set()
    for rec in records:
        for n in rec.get("name_value", "").split("\n"):
            n = n.strip().lstrip("*.")
            if n:
                names.add(n)

    sorted_names = sorted(names)
    body = "\n".join(sorted_names) if sorted_names else "(tidak ada nama domain ditemukan di log CT)"
    output = f"Ditemukan {len(sorted_names)} nama unik dari {len(records)} record sertifikat.\n\n{body}"
    truncated = len(output) > _MAX_OUTPUT_CHARS
    if truncated:
        output = output[:_MAX_OUTPUT_CHARS] + "\n\n[...output dipotong...]"

    return {
        "ok": True,
        "command": "crt_watch",
        "bin": "curl",
        "target": target,
        "exit_code": proc.returncode,
        "output": output.strip(),
        "truncated": truncated,
    }


def _run_robots_sitemap(target: str, timeout: int) -> dict:
    """
    Ambil robots.txt dan sitemap.xml sekaligus lewat dua panggilan curl
    terpisah (bukan chained pipe — dua subprocess independen, hasilnya
    digabung di Python). Berguna buat nemuin path yang di-disallow (kadang
    admin/staging area) dan daftar URL dari sitemap.
    """
    base = _http_url(target).rstrip("/")
    per_fetch_timeout = str(max(timeout // 2 - 1, 5))

    def _fetch(path: str) -> tuple[bool, str]:
        url = f"{base}{path}"
        try:
            proc = subprocess.run(
                ["curl", "-sL", "-k", "--max-time", per_fetch_timeout, "-A", "PhoneGG-NetTools/1.0", url],
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"[{path}] timeout (> {per_fetch_timeout}s)."
        except Exception as e:
            return False, f"[{path}] gagal konek — {e}"

        body = (proc.stdout or "").strip()
        if not body:
            return False, f"[{path}] tidak ada isi (kemungkinan 404 atau file kosong)."
        return True, body

    robots_ok, robots_out = _fetch("/robots.txt")
    sitemap_ok, sitemap_out = _fetch("/sitemap.xml")

    parts = [
        "=== robots.txt ===",
        robots_out if robots_ok else f"(tidak ditemukan) {robots_out}",
        "",
        "=== sitemap.xml ===",
        sitemap_out if sitemap_ok else f"(tidak ditemukan) {sitemap_out}",
    ]
    output = "\n".join(parts)
    truncated = len(output) > _MAX_OUTPUT_CHARS
    if truncated:
        output = output[:_MAX_OUTPUT_CHARS] + "\n\n[...output dipotong...]"

    if not robots_ok and not sitemap_ok:
        return {"ok": False, "error": f"Dua-duanya gagal diambil.\n{robots_out}\n{sitemap_out}"}

    return {
        "ok": True,
        "command": "robots_sitemap",
        "bin": "curl",
        "target": target,
        "exit_code": 0,
        "output": output.strip(),
        "truncated": truncated,
    }


def _run_shodan_internetdb(target: str, timeout: int) -> dict:
    """
    Query Shodan InternetDB (internetdb.shodan.io) — endpoint gratis tanpa
    API key yang ngembaliin hasil internet-wide scan Shodan buat satu IP
    (port terbuka, CPE, CVE, hostname, tag). API ini cuma nerima IP, jadi
    kalau target berupa domain, di-resolve dulu pakai socket.gethostbyname
    (bukan subprocess — resolusi DNS murni Python, tetap kena
    validate_url_target di run_tool() sebelum sampai sini).
    """
    host = _extract_host(target)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"ok": False, "error": f"Gagal resolve '{host}' ke IP — {e}"}

    url = f"https://internetdb.shodan.io/{ip}"

    try:
        proc = subprocess.run(
            ["curl", "-s", "--max-time", str(max(timeout - 2, 5)), "-A", "PhoneGG-NetTools/1.0", url],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"Command timeout (> {timeout}s)."}
    except Exception as e:
        return {"ok": False, "error": f"Gagal konek ke InternetDB — {e}"}

    raw = (proc.stdout or "").strip()
    if not raw:
        return {"ok": False, "error": "InternetDB tidak mengembalikan data."}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"ok": False, "error": "Gagal parsing respons InternetDB."}

    if "detail" in data and "ip" not in data:
        # Shodan balikin {"detail": "No information available"} kalau IP-nya
        # belum pernah kescan / nggak ada data.
        return {"ok": False, "error": f"InternetDB: {data['detail']} (IP {ip})."}

    lines = [f"IP: {data.get('ip', ip)}"]
    ports = data.get("ports") or []
    lines.append(f"Port terbuka: {', '.join(str(p) for p in ports) if ports else '(tidak ada)'}")

    hostnames = data.get("hostnames") or []
    if hostnames:
        lines.append(f"Hostname terkait: {', '.join(hostnames)}")

    cpes = data.get("cpes") or []
    if cpes:
        lines.append(f"CPE (fingerprint software): {', '.join(cpes)}")

    tags = data.get("tags") or []
    if tags:
        lines.append(f"Tag: {', '.join(tags)}")

    vulns = data.get("vulns") or []
    if vulns:
        lines.append(f"CVE terdeteksi ({len(vulns)}): {', '.join(vulns)}")
    else:
        lines.append("CVE terdeteksi: (tidak ada)")

    output = "\n".join(lines)
    truncated = len(output) > _MAX_OUTPUT_CHARS
    if truncated:
        output = output[:_MAX_OUTPUT_CHARS] + "\n\n[...output dipotong...]"

    return {
        "ok": True,
        "command": "shodan_internetdb",
        "bin": "curl",
        "target": target,
        "exit_code": proc.returncode,
        "output": output.strip(),
        "truncated": truncated,
    }


def run_tool(command_key: str, target: str) -> dict:
    """
    Jalankan satu command whitelist terhadap satu target yang sudah
    divalidasi. Selalu mengembalikan dict, tidak pernah melempar exception
    ke caller.
    """
    started = time.time()

    if command_key not in ALLOWED_COMMANDS and command_key not in CHAINED_COMMANDS:
        return {"ok": False, "error": f"Command '{command_key}' tidak ada di whitelist."}

    if not target or not target.strip():
        return {"ok": False, "error": "Target tidak boleh kosong."}

    # SSRF / target guard yang sama dipakai modul lain di PhoneGG
    # (misal port scanner & vuln scanner): blokir IP privat, loopback,
    # metadata endpoint, dan karakter mencurigakan.
    is_valid, err_msg = validate_url_target(target)
    if not is_valid:
        return {"ok": False, "error": err_msg}

    # Command dua-tahap ditangani terpisah (bukan lewat ALLOWED_COMMANDS)
    if command_key in CHAINED_COMMANDS:
        cfg = CHAINED_COMMANDS[command_key]
        if command_key == "ssl_info":
            result = _run_ssl_info(target, cfg["timeout"])
        elif command_key == "curl_server_header":
            result = _run_server_header(target, cfg["timeout"])
        elif command_key == "crt_watch":
            result = _run_crt_watch(target, cfg["timeout"])
        elif command_key == "robots_sitemap":
            result = _run_robots_sitemap(target, cfg["timeout"])
        elif command_key == "shodan_internetdb":
            result = _run_shodan_internetdb(target, cfg["timeout"])
        else:
            result = {"ok": False, "error": "Command dua-tahap belum diimplementasikan."}
        if result.get("ok"):
            result["duration_seconds"] = round(time.time() - started, 2)
        return result

    cfg = ALLOWED_COMMANDS[command_key]

    if shutil.which(cfg["bin"]) is None:
        return {
            "ok": False,
            "error": f"Binary '{cfg['bin']}' tidak terpasang di server ini. "
                     f"Install dulu (mis. `apt install {cfg['bin']}`) untuk mengaktifkan command ini.",
        }

    try:
        args = [cfg["bin"]] + cfg["build_args"](target)
    except Exception as e:
        return {"ok": False, "error": f"Gagal membangun argumen command: {e}"}

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=cfg["timeout"],
            shell=False,  # WAJIB False — jangan pernah diubah
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"Command timeout (> {cfg['timeout']}s)."}
    except Exception as e:
        return {"ok": False, "error": f"Gagal menjalankan command: {e}"}

    output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    truncated = len(output) > _MAX_OUTPUT_CHARS
    if truncated:
        output = output[:_MAX_OUTPUT_CHARS] + "\n\n[...output dipotong...]"

    return {
        "ok": True,
        "command": command_key,
        "bin": cfg["bin"],
        "target": target,
        "exit_code": proc.returncode,
        "output": output.strip() or "(tidak ada output)",
        "truncated": truncated,
        "duration_seconds": round(time.time() - started, 2),
    }