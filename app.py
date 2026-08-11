# ============================================================
#  PhoneGG — OSINT Toolkit  (Flask Web + REST API + PWA)
#  Professional edition — stable & responsive
# ============================================================
import os
import json
import secrets
import logging
from datetime import datetime
from functools import wraps
from urllib.parse import quote as url_quote
from concurrent.futures import ThreadPoolExecutor

try:
    from dotenv import load_dotenv
    load_dotenv()  # baca file .env otomatis kalau ada
except ImportError:
    pass  # python-dotenv belum terinstall, tetap jalan pakai env var sistem

from flask import (Flask, render_template, request, session,
                    send_file, jsonify, send_from_directory,
                    redirect, url_for)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger
from werkzeug.security import generate_password_hash, check_password_hash

# ── Internal modules ──
from modules.gravatar import get_gravatar
from modules.domain_info import get_domain_info
from modules.check_404 import check_url_status
from modules.dir_enum import scan_directories
from modules.security_headers import analyze_security_headers
from modules.tech_detect import detect_technologies
from modules.subdomain_enum import enumerate_subdomains
from modules.wayback_lookup import get_snapshots, get_all_urls_for_domain
from modules.scam_checker import check_site_reputation
from modules.port_scan import scan_ports
from modules.cors_check import check_cors
from modules.subdomain_takeover import check_takeover
from modules.breach_search import search_all_breaches, search_all_breaches_phone, check_hibp as _hibp_check
from modules.ip_info import full_ip_lookup
from modules.metadata_extractor import extract_metadata
from modules.social_probe import check_username, check_username_detailed, PLATFORMS
from modules.origin_ip_finder import find_origin_ip
from modules.header_detector import analyze_headers
from modules.link_scraper import extract_links_and_scripts, extract_by_category
from modules.graph_builder import build_phone_graph
from modules.net_tools import list_commands as net_tools_list_commands, run_tool as net_tools_run_tool

# ── PhoneGG Pen — Repeater module (authorized pentest tooling) ──
from pen_repeater import send_pen_request, parse_raw_request, normalize_headers_for_display

# ── AI Modules ──
from ai_model import get_phone_risk_prediction
from ai_analyst import get_ai_analysis, process_chat_message
from modules.custom_ai_engine import analyze_custom_data

# ── Security Utilities ──
from security_utils import validate_url_target, sanitize_input, sanitize_username, apply_security_headers

# ============================================================
#  Validation & Helper Functions
# ============================================================

def validate_phone_id(phone: str):
    """
    Validate and normalize Indonesian phone numbers to international format (62xxxxxxxxxx).
    
    Args:
        phone: Raw phone number string (can include spaces, dashes, or +62 prefix)
    
    Returns:
        Normalized phone number string starting with 62, or None if invalid
    
    Supported formats:
        - +6281234567890 -> 6281234567890
        - 6281234567890 -> 6281234567890
        - 081234567890 -> 6281234567890
        - 81234567890 -> 6281234567890
    """
    p = phone.strip().replace("-", "").replace(" ", "")
    if p.startswith("+62"):
        return p[1:]
    if p.startswith("62"):
        return p
    if p.startswith("08"):
        return "62" + p[1:]
    if p.startswith("8") and len(p) >= 9:
        return "62" + p
    return None

def validate_email(email: str):
    """
    Basic email validation and normalization.
    
    Args:
        email: Raw email address string
    
    Returns:
        Normalized lowercase email address, or None if invalid format
    
    Note: This is basic validation. For production, consider using proper email validation libraries.
    """
    email = email.strip().lower()
    if "@" in email and "." in email.split("@")[1]:
        return email
    return None

def check_whatsapp_status(number: str):
    """
    Check WhatsApp registration status (placeholder function).
    
    Args:
        number: Normalized phone number string
    
    Returns:
        Dictionary with status information
    
    Note: There is no free/reliable way to check WhatsApp registration status
    without an unofficial/paid third-party API. This function returns a 
    transparent message instead of fabricating results.
    """
    return {
        "status": "tidak tersedia",
        "note": "Pengecekan status WhatsApp real-time membutuhkan API pihak ketiga "
                "yang belum dikonfigurasi. Gunakan link wa.me di bawah untuk cek manual.",
    }

def check_hibp(email: str):
    return _hibp_check(email)

_GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
_GOOGLE_CX = os.environ.get("GOOGLE_CX")

def google_search(query: str, max_results: int = 5):
    """Google Custom Search JSON API. Returns [] (silently, by design) when
    GOOGLE_API_KEY / GOOGLE_CX are not configured — no fabricated results."""
    if not _GOOGLE_API_KEY or not _GOOGLE_CX:
        return []
    try:
        import requests
        resp = requests.get(
            "https://www.googleapis.com/customsearch/v1",
            params={"key": _GOOGLE_API_KEY, "cx": _GOOGLE_CX, "q": query, "num": min(max_results, 10)},
            timeout=8,
        )
        if resp.status_code != 200:
            return []
        items = resp.json().get("items", [])
        return [{"title": i.get("title", ""), "link": i.get("link", ""), "snippet": i.get("snippet", "")} for i in items]
    except Exception:
        return []

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
    "yopmail.com", "throwawaymail.com", "trashmail.com", "getnada.com",
    "fakeinbox.com", "sharklasers.com", "dispostable.com", "maildrop.cc",
    "temp-mail.org", "mohmal.com", "moakt.com", "emailondeck.com",
}

def check_email_reputation(email: str):
    """Heuristic, no-external-API-key reputation check: disposable-domain
    list + real MX record lookup. Transparent about what it can and can't tell."""
    domain = email.split("@")[-1].lower()
    disposable = domain in _DISPOSABLE_DOMAINS
    has_mx = None
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        has_mx = len(answers) > 0
    except Exception:
        has_mx = False

    if disposable:
        reputation = "Domain email sekali pakai (disposable) — mencurigakan"
    elif not has_mx:
        reputation = "Domain tidak punya MX record — kemungkinan tidak bisa menerima email"
    else:
        reputation = "Tidak ada indikator mencurigakan (heuristik dasar)"

    return {
        "status": "success", "reputation": reputation,
        "disposable": disposable, "has_mx": has_mx, "suspicious": disposable or not has_mx,
        "spam": False,
        "note": "Heuristik lokal (disposable-domain list + MX record), bukan database reputasi eksternal.",
    }

# Indonesian mobile prefix -> operator table (real lookup, no external API needed)
_ID_OPERATOR_PREFIXES = {
    "0811": "Telkomsel", "0812": "Telkomsel", "0813": "Telkomsel",
    "0821": "Telkomsel", "0822": "Telkomsel", "0823": "Telkomsel",
    "0851": "Telkomsel", "0852": "Telkomsel", "0853": "Telkomsel",
    "0814": "Indosat Ooredoo", "0815": "Indosat Ooredoo", "0816": "Indosat Ooredoo",
    "0855": "Indosat Ooredoo", "0856": "Indosat Ooredoo", "0857": "Indosat Ooredoo", "0858": "Indosat Ooredoo",
    "0817": "XL Axiata", "0818": "XL Axiata", "0819": "XL Axiata",
    "0859": "XL Axiata", "0877": "XL Axiata", "0878": "XL Axiata",
    "0831": "AXIS", "0832": "AXIS", "0833": "AXIS", "0838": "AXIS",
    "0895": "Tri (3)", "0896": "Tri (3)", "0897": "Tri (3)", "0898": "Tri (3)", "0899": "Tri (3)",
    "0881": "Smartfren", "0882": "Smartfren", "0883": "Smartfren", "0884": "Smartfren",
    "0885": "Smartfren", "0886": "Smartfren", "0887": "Smartfren", "0888": "Smartfren", "0889": "Smartfren",
}

def detect_operator(number: str):
    """
    Detect Indonesian mobile operator based on phone number prefix.
    
    Args:
        number: Normalized phone number string (62xxxxxxxxxx format)
    
    Returns:
        Dictionary containing operator name, country, and prefix information
    
    Uses local prefix mapping table - no external API needed.
    """
    # Rebuild the 08xx form from normalized 62xxxxxxxxxx
    local_prefix = "0" + number[2:5] if number.startswith("62") else number[:4]
    operator = _ID_OPERATOR_PREFIXES.get(local_prefix, "Tidak diketahui")
    return {"operator": operator, "country": "Indonesia", "prefix": local_prefix}

def scan_domain(target: str, severity: str = "medium"):
    """
    Run vulnerability scan using nuclei security scanner.
    
    Args:
        target: Domain or URL to scan
        severity: Minimum severity level (low, medium, high, critical)
    
    Returns:
        Dictionary containing scan results, findings, and summary
    
    Note: Requires nuclei binary to be installed on the system.
    Returns honest error message if nuclei is not available.
    Includes input sanitization to prevent command injection.
    """
    import shutil, subprocess, time, json as _json
    
    # Check if nuclei binary is available
    if shutil.which("nuclei") is None:
        return {
            "target": target, "engine": "nuclei", "findings": [],
            "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "error": "Binary 'nuclei' tidak ditemukan di server ini. Install dari "
                     "https://github.com/projectdiscovery/nuclei untuk mengaktifkan fitur ini.",
        }
    
    # Input sanitization to prevent command injection
    safe_target = target.strip()
    if not safe_target or any(c in safe_target for c in " \t\n;&|`$(){}<>"):
        return {"target": target, "error": "Target tidak valid."}
    
    # Ensure URL has proper protocol
    url_target = safe_target if safe_target.startswith(("http://", "https://")) else f"https://{safe_target}"
    started = time.time()
    
    try:
        proc = subprocess.run(
            ["nuclei", "-u", url_target, "-severity", severity, "-jsonl", "-silent", "-timeout", "8"],
            capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return {"target": target, "engine": "nuclei", "error": "Scan timeout (>180s)."}
    except Exception as e:
        return {"target": target, "engine": "nuclei", "error": f"Gagal menjalankan nuclei: {e}"}

    # Parse nuclei JSONL output
    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = _json.loads(line)
        except Exception:
            continue
        info = item.get("info", {})
        findings.append({
            "name": info.get("name", "Unknown"),
            "severity": info.get("severity", "info"),
            "template": item.get("template-id", ""),
            "matched_at": item.get("matched-at", url_target),
        })
    
    # Generate summary statistics
    summary = {"total": len(findings)}
    for lvl in ("critical", "high", "medium", "low", "info"):
        summary[lvl] = sum(1 for f in findings if f["severity"] == lvl)
    
    return {
        "target": target, "engine": "nuclei", "findings": findings,
        "summary": summary, "duration_seconds": round(time.time() - started, 1),
    }

def _load_config() -> dict:
    """
    Load configuration from config.json file.
    
    Returns:
        Dictionary containing configuration data, or empty dict if file not found/error
    
    Note: Silently fails on error to allow app to run with defaults.
    """
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

_SEARCH_ENGINES = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "duckduckgo": "https://duckduckgo.com/?q={query}",
}

def _build_search_url(engine: str, query: str) -> str:
    """Build a search-engine URL with proper encoding."""
    encoded = url_quote(query, safe="")
    template = _SEARCH_ENGINES.get(engine, _SEARCH_ENGINES["google"])
    return template.format(query=encoded)

def _generate_dorks(replacements: dict, query_type: str) -> dict:
    """Generate dork search URLs from config.json templates.

    Skips malformed entries and ensures all placeholders are replaced.
    Duplicate labels get a numeric suffix to avoid silent overwrites.
    """
    config = _load_config()
    queries = config.get(query_type)
    if not isinstance(queries, list):
        return {}

    links = {}
    label_counts = {}

    for q in queries:
        if not isinstance(q, dict):
            continue
        label = str(q.get("label", "")).strip()
        query = str(q.get("query", "")).strip()
        engine = str(q.get("engine", "google")).strip().lower()
        if not label or not query:
            continue

        for k, v in replacements.items():
            query = query.replace(f"{{{k}}}", str(v))

        if "{" in query or "}" in query:
            continue

        label_counts[label] = label_counts.get(label, 0) + 1
        key = label if label_counts[label] == 1 else f"{label} ({label_counts[label]})"
        links[key] = _build_search_url(engine, query)

    return links

def generate_dork_urls(number: str):
    local = "0" + number[2:] if number.startswith("62") else number
    return _generate_dorks({"number": number, "local": local}, "phone_queries")

def generate_email_dork_urls(email: str):
    username = email.split("@")[0] if "@" in email else email
    return _generate_dorks({"email": email, "username": username}, "email_queries")

# ============================================================
#  Flask Application Setup
# ============================================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Production configuration
app.config['DEBUG'] = os.environ.get("FLASK_DEBUG", "0") == "1"
app.config['TESTING'] = False
app.config['SESSION_COOKIE_SECURE'] = True if os.environ.get("FLASK_ENV") == "production" else False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ── Login System ──
# Akun disimpan sebagai hash password lewat env var AUTH_USERS, format:
#   AUTH_USERS="admin:hash_password_1,budi:hash_password_2"
# Kalau env var kosong, fallback ke satu akun default (WAJIB diganti sebelum
# di-hosting publik) dengan password dari env var AUTH_DEFAULT_PASSWORD,
# atau "phonegg123" kalau env var itu juga kosong.
#
# Cara generate hash password baru (jalankan sekali di python shell):
#   from werkzeug.security import generate_password_hash
#   generate_password_hash("password_kamu")
def _load_users():
    raw = os.environ.get("AUTH_USERS", "").strip()
    if raw:
        users = {}
        for pair in raw.split(","):
            if ":" in pair:
                uname, phash = pair.split(":", 1)
                users[uname.strip()] = phash.strip()
        if users:
            return users
    default_pw = os.environ.get("AUTH_DEFAULT_PASSWORD", "phonegg123")
    if default_pw == "phonegg123":
        print(
            "\n[PERINGATAN KEAMANAN] AUTH_USERS/AUTH_DEFAULT_PASSWORD belum di-set di .env — "
            "server ini masih pakai akun default admin/phonegg123 yang gampang ditebak. "
            "Set AUTH_DEFAULT_PASSWORD (atau AUTH_USERS) di .env sebelum dipakai di luar localhost!\n",
            flush=True,
        )
    return {"admin": generate_password_hash(default_pw)}

USERS = _load_users()

# Path yang tetap bisa diakses tanpa login (halaman login itu sendiri,
# aset statis, PWA manifest/service worker, health check untuk hosting).
PUBLIC_PATHS = {"/login", "/manifest.json", "/sw.js", "/healthz"}

def login_required(f):
    """Decorator opsional untuk mengunci satu route spesifik."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

@app.before_request
def require_login():
    """
    Gerbang login global: semua halaman & endpoint (termasuk /api/* yang
    dipakai frontend PhoneGG sendiri) butuh sesi login, KECUALI path yang
    ada di PUBLIC_PATHS dan file statis di /static/.
    Endpoint /api/v1/* yang sudah pakai @require_api_key tetap jalan untuk
    pemanggilan API eksternal dengan API key, terlepas dari status login.
    """
    path = request.path
    if path in PUBLIC_PATHS or path.startswith("/static/"):
        return None
    if session.get("logged_in"):
        return None
    if request.headers.get("X-API-Key"):
        # Biarkan lewat; endpoint yang butuh key akan validasi sendiri
        # lewat @require_api_key, dan yang tidak pakai key tetap kena 401 di bawah.
        return None
    if path.startswith("/api/"):
        return jsonify({
            "status": "error", "code": 401,
            "message": "Unauthorized. Silakan login terlebih dahulu.",
            "timestamp": datetime.now().isoformat(),
        }), 401
    return redirect(url_for("login", next=path))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        stored_hash = USERS.get(username)
        if stored_hash and check_password_hash(stored_hash, password):
            session["logged_in"] = True
            session["username"] = username
            if request.form.get("remember"):
                session.permanent = True
            next_url = request.form.get("next") or request.args.get("next") or url_for("index")
            return redirect(next_url)
        return render_template("login.html", error="Username atau password salah.")
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# Initialize export directory for report generation
EXPORT_DIR = "exports"
os.makedirs(EXPORT_DIR, exist_ok=True)
REPORTS = {}
CHAT_SESSIONS = {}  # per-session chat history: {sid: [{"role": "user"/"assistant", "content": str}, ...]}
PEN_HISTORY = {}  # per-session Pen Repeater history: {sid: [entry, ...]} (in-memory, max 50/entri sesi)
PEN_HISTORY_MAX = 50

# Configure logging for error tracking and debugging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('phonegg.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ── Rate Limiter Configuration ──
limiter = Limiter(
    app=app, key_func=get_remote_address,
    default_limits=["200 per hour", "20 per minute"],
    storage_uri="memory://",
)

# ── Thread Pool Executor for Parallel Scanning ──
executor = ThreadPoolExecutor(max_workers=25)

# ── Error Handling Decorator ──

def handle_errors(f):
    """
    Decorator to handle exceptions in route handlers.
    
    Catches exceptions and logs them while returning appropriate error responses.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}", exc_info=True)
            if request.path.startswith("/api/"):
                return err(f"Internal server error: {str(e)}", 500)
            return render_template("error.html", code=500, message=f"Terjadi kesalahan: {str(e)}", **history_ctx()), 500
    return decorated

# ── Session Management Helpers ──

def get_sid():
    """
    Get or create session ID for current user.
    
    Returns:
        Session ID string (hex format)
    
    Used to track user-specific data like reports and history.
    """
    if "sid" not in session:
        session["sid"] = secrets.token_hex(8)
    return session["sid"]

def save_report(report_type, data):
    """
    Save report data for current session.
    
    Args:
        report_type: Type of report (phone, email, username, etc.)
        data: Report data dictionary
    
    Reports are stored in memory and can be exported later.
    """
    REPORTS[get_sid()] = {"type": report_type, "data": data}

def add_history(query):
    """
    Add query to user's search history.
    
    Args:
        query: Search query string
    
    Maintains last 20 queries in session history.
    """
    history = session.get("history", [])
    history.insert(0, {"query": query, "time": datetime.now().strftime("%H:%M:%S %d-%m-%Y")})
    session["history"] = history[:20]

def save_pen_history(entry):
    """
    Simpan satu entri riwayat Pen Repeater untuk sesi saat ini (in-memory,
    reset saat server restart — sama seperti REPORTS/CHAT_SESSIONS di project ini).

    Args:
        entry: dict berisi id/time/method/url/status_code/elapsed_ms/request/response
    """
    sid = get_sid()
    items = PEN_HISTORY.get(sid, [])
    items.insert(0, entry)
    PEN_HISTORY[sid] = items[:PEN_HISTORY_MAX]

@app.before_request
def ensure_history():
    """
    Ensure history list exists in session before each request.
    """
    session.setdefault("history", [])

def history_ctx():
    """
    Get history context for template rendering.
    
    Returns:
        Dictionary with history data
    """
    return {"history": session.get("history", [])}

# ── Security Headers Middleware ──
@app.after_request
def add_security_headers(response):
    """Apply security headers to all responses."""
    return apply_security_headers(response)

# ── PWA manifest & service worker ──
@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "PhoneGG OSINT Toolkit",
        "short_name": "PhoneGG",
        "description": "All-in-one OSINT toolkit",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0a0e1a",
        "theme_color": "#0a0e1a",
        "orientation": "portrait-primary",
        "icons": [
            {"src": "/static/icons/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/static/icons/icon-512.png", "sizes": "512x512", "type": "image/png"},
        ],
        "categories": ["security", "utilities", "productivity"],
    })

@app.route("/sw.js")
def service_worker():
    return send_from_directory("static", "sw.js", mimetype="application/javascript")

# ============================================================
#  Health
# ============================================================
@app.route("/healthz")
def healthz():
    return "OK", 200

@app.route("/test")
def test():
    return "Test OK", 200

# ============================================================
#  Web Routes
# ============================================================
@app.route("/")
@handle_errors
def index():
    """Render main dashboard page."""
    return render_template("index.html", **history_ctx())

@app.route("/phone", methods=["GET", "POST"])
@handle_errors
def phone_page():
    """
    Handle phone lookup requests.
    
    GET: Render phone lookup page
    POST: Process phone number and return analysis results
    """
    result = err = phone = None
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        number = validate_phone_id(phone)
        if not number:
            err = "Format nomor tidak valid. Gunakan 08xx / 628xx."
        else:
            try:
                wa_status = check_whatsapp_status(number)
                links = generate_dork_urls(number)
                operator_info = detect_operator(number)
                google_results = google_search(f'"{number}" OR "0{number[2:]}"', max_results=5)
                
                # Get ML risk prediction
                ml_risk = get_phone_risk_prediction(number)
                
                result = {
                    "number": number, "operator": operator_info["operator"],
                    "country": operator_info["country"], "prefix": operator_info["prefix"],
                    "wa_status": wa_status, "links": links, "google_results": google_results,
                    "ml_risk_prediction": ml_risk
                }
                add_history(number)
                save_report("phone", result)
            except Exception as e:
                logger.error(f"Phone lookup error: {str(e)}")
                err = f"Terjadi kesalahan saat memproses nomor: {str(e)}"
    return render_template("phone.html", phone_result=result, phone_error=err, phone=phone, **history_ctx())

@app.route("/phone-graph")
@handle_errors
def phone_graph_page():
    """
    Phone Network Graph Visualization Page
    
    GET: Render interactive graph visualization interface
    """
    return render_template("phone_graph.html", **history_ctx())

@app.route("/email", methods=["GET", "POST"])
def email_page():
    result = err = email = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        valid = validate_email(email)
        if not valid:
            err = "Format email tidak valid."
        else:
            result = {
                "email": valid,
                "hibp": check_hibp(valid),
                "links": generate_email_dork_urls(valid),
                "google_results": google_search(f'"{valid}"', max_results=5),
                "reputation": check_email_reputation(valid),
                "gravatar": get_gravatar(valid),
                "domain_info": get_domain_info(valid),
            }
            add_history(valid)
            save_report("email", result)
    return render_template("email.html", email_result=result, email_error=err, email=email, **history_ctx())

@app.route("/ai-analysis", methods=["GET"])
@handle_errors
def ai_analysis_page():
    """
    AIZX Native Engine Chatbot Interface.
    
    GET: Render clean chatbot interface for universal AI assistance
    """
    from ai_analyst import ai_chatbot
    # Render clean chatbot interface
    return render_template(
        "ai_analysis.html",
        llm_enabled=ai_chatbot.llm_enabled,
        llm_providers=[p[0] for p in ai_chatbot.llm_providers],
        **history_ctx(),
    )

@app.route("/custom-ai", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def custom_ai_page():
    """
    Custom AI Engine - Analisis data kustom dengan heuristik dan pattern matching
    """
    result = err = data_type = None
    if request.method == "POST":
        data_type = sanitize_input(request.form.get("cai_data_type", "generic").strip())
        
        # Collect form data as input payload
        input_payload = {}
        for key, value in request.form.items():
            if key.startswith("field_") and value:
                field_name = key.replace("field_", "")
                input_payload[field_name] = sanitize_input(value.strip())
        
        if not input_payload:
            err = "Masukkan minimal satu field data untuk dianalisis."
        else:
            try:
                result = analyze_custom_data(data_type, input_payload)
                add_history(f"CustomAI: {data_type}")
                save_report("custom_ai", result)
            except Exception as e:
                logger.error(f"Custom AI analysis error: {str(e)}")
                err = f"Terjadi kesalahan saat menganalisis dengan Custom AI: {str(e)}"
    
    return render_template("custom_ai.html", cai_result=result, cai_error=err, cai_data_type=data_type, **history_ctx())

@app.route("/username", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def username_page():
    result = err = username = None
    if request.method == "POST":
        username = sanitize_username(request.form.get("username", "").strip())
        if not username:
            err = "Username tidak boleh kosong."
        else:
            detailed = check_username_detailed(username)
            results = {r["platform"]: r["status"] for r in detailed["results"]}
            found = [r["platform"] for r in detailed["results"] if r["status"] == "found"]
            links = {p: cfg["url"].format(username=username) for p, cfg in PLATFORMS.items()}
            result = {
                "username": username, "found": found, "details": results, "links": links,
                "summary": detailed["summary"], "scan": detailed["results"],
            }
            add_history(f"@{username}")
            save_report("username", result)
    return render_template("username.html", username_result=result, username_error=err, username=username, **history_ctx())

@app.route("/dork", methods=["GET", "POST"])
def dork_page():
    result = err = target = None
    dtype = "phone"
    if request.method == "POST":
        target = request.form.get("dork_target", "").strip()
        dtype = request.form.get("dork_type", "phone")
        if not target:
            err = "Masukkan nomor HP atau email."
        elif dtype == "email":
            valid = validate_email(target)
            if not valid:
                err = "Format email tidak valid."
            else:
                links = generate_email_dork_urls(valid)
                result = {"target": valid, "type": "email", "links": links}
                add_history(f"Dork: {valid}")
                save_report("dork", result)
        else:
            number = validate_phone_id(target)
            if not number:
                err = "Format nomor tidak valid. Gunakan 08xx / 628xx."
            else:
                links = generate_dork_urls(number)
                result = {"target": number, "type": "phone", "links": links}
                add_history(f"Dork: {number}")
                save_report("dork", result)
    return render_template("dork.html", dork_result=result, dork_error=err, dork_target=target, dork_type=dtype, **history_ctx())

@app.route("/vuln", methods=["GET", "POST"])
@handle_errors
def vuln_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("vuln_target", "").strip())
        if not target:
            err = "Masukkan domain atau URL."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                severity = request.form.get("severity", "medium")
                result = scan_domain(target, severity=severity)
                add_history(f"Scan: {target}")
                save_report("vuln", result)
    return render_template("vuln.html", vuln_result=result, vuln_error=err, vuln_target=target, **history_ctx())

@app.route("/dir", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def dir_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("dir_target", "").strip())
        if not target:
            err = "Masukkan URL target."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                raw = scan_directories(target)
                valid = [r for r in raw if not r.get("fake_404", False) and r["status"] in (200, 301, 302, 403, 401)]
                fake = [r for r in raw if r.get("fake_404", False)]
                result = {"target": target, "results": raw, "found": valid, "fake": fake, "total": len(raw)}
                add_history(f"Dir: {target}")
                save_report("dir", result)
    return render_template("dir.html", dir_result=result, dir_error=err, dir_target=target, **history_ctx())

@app.route("/check404", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def check404_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("check404_url", "").strip())
        if not target:
            err = "Masukkan URL yang mau dicek."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                result = check_url_status(target)
                add_history(f"404check: {target}")
                save_report("check404", result)
    return render_template("check404.html", check404_result=result, check404_error=err, check404_target=target, **history_ctx())

@app.route("/security-headers", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def security_headers_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("sh_target", "").strip())
        if not target:
            err = "Masukkan URL."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                result = analyze_security_headers(target)
                add_history(f"SecHeaders: {target}")
                save_report("security_headers", result)
    return render_template("security_headers.html", sh_result=result, sh_error=err, sh_target=target, **history_ctx())

@app.route("/tech-detect", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def tech_detect_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("td_target", "").strip())
        if not target:
            err = "Masukkan URL."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                result = detect_technologies(target)
            add_history(f"TechDetect: {target}")
            save_report("tech_detect", result)
    return render_template("tech_detect.html", td_result=result, td_error=err, td_target=target, **history_ctx())

@app.route("/header-detector", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def header_detector_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("hd_target", "").strip())
        if not target:
            err = "Masukkan URL."
        else:
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                result = analyze_headers(target)
            add_history(f"HeaderDetector: {target}")
            save_report("header_detector", result)
    return render_template("header_detector.html", hd_result=result, hd_error=err, hd_target=target, **history_ctx())

@app.route("/link-scraper", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def link_scraper_page():
    result = err = target = None
    category = "all"
    if request.method == "POST":
        target = sanitize_input(request.form.get("ls_target", "").strip())
        category = sanitize_input(request.form.get("ls_category", "all").strip())
        if not target:
            err = "Masukkan URL."
        else:
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                if category == "all":
                    result = extract_links_and_scripts(target)
                else:
                    result = extract_by_category(target, category)
            add_history(f"LinkScraper: {target}")
            save_report("link_scraper", result)
    return render_template("link_scraper.html", ls_result=result, ls_error=err, ls_target=target, ls_category=category if 'category' in locals() else "all", **history_ctx())

@app.route("/subdomain", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def subdomain_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("sub_target", "").strip())
        if not target:
            err = "Masukkan domain."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                use_crt = request.form.get("use_crtsh", "on") == "on"
                use_brute = request.form.get("use_bruteforce", "on") == "on"
                use_search = request.form.get("use_search", "on") == "on"
                result = enumerate_subdomains(target, use_crtsh=use_crt,
                                                use_bruteforce=use_brute, use_search=use_search)
                add_history(f"Subdomain: {target}")
                save_report("subdomain", result)
    return render_template("subdomain.html", sub_result=result, sub_error=err, sub_target=target, **history_ctx())

@app.route("/wayback", methods=["GET", "POST"])
def wayback_page():
    result = err = target = None
    if request.method == "POST":
        target = request.form.get("wb_target", "").strip()
        if not target:
            err = "Masukkan URL atau domain."
        else:
            mode = request.form.get("wb_mode", "snapshots")
            if mode == "all_urls":
                result = get_all_urls_for_domain(target)
            else:
                result = get_snapshots(target)
            add_history(f"Wayback: {target}")
            save_report("wayback", result)
    return render_template("wayback.html", wb_result=result, wb_error=err, wb_target=target, **history_ctx())

@app.route("/scam-check", methods=["GET", "POST"])
@handle_errors
@limiter.limit("15 per minute")
def scam_check_page():
    result = err = target = None
    if request.method == "POST":
        target = request.form.get("sc_target", "").strip()
        if not target:
            err = "Masukkan URL atau domain yang mau dicek."
        else:
            result = check_site_reputation(target)
            add_history(f"ScamCheck: {target}")
            save_report("scam_check", result)
    return render_template("scam_check.html", sc_result=result, sc_error=err, sc_target=target, **history_ctx())

@app.route("/api/v1/scam-check", methods=["POST"])
@handle_errors
@limiter.limit("15 per minute")
def api_scam_check():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Field 'target' wajib diisi."}), 400
    return jsonify(check_site_reputation(target))

@app.route("/portscan", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def portscan_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("ps_target", "").strip())
        if not target:
            err = "Masukkan domain atau IP."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                extended = request.form.get("ps_extended") == "on"
                result = scan_ports(target, extended=extended)
                add_history(f"PortScan: {target}")
                save_report("portscan", result)
    return render_template("portscan.html", ps_result=result, ps_error=err, ps_target=target, **history_ctx())

@app.route("/net-tools", methods=["GET"])
@handle_errors
def net_tools_page():
    """
    Net Tools Console — UI bergaya terminal untuk menjalankan tool
    diagnostik jaringan (whois/dig/nslookup/ping/traceroute/curl -I)
    terhadap SATU target per request. Command dipilih dari whitelist
    tetap (lihat modules/net_tools.py); user tidak pernah mengetik
    command bebas. Dieksekusi lewat AJAX ke /api/v1/net-tools.
    """
    return render_template("net_tools.html", nt_commands=net_tools_list_commands(), **history_ctx())

@app.route("/api/v1/net-tools", methods=["POST"])
@handle_errors
@limiter.limit("15 per minute")
def api_net_tools():
    """Eksekusi satu command whitelist dari Net Tools Console (login session, bukan API key publik)."""
    data = request.get_json(silent=True) or {}
    command_key = str(data.get("command", "")).strip()
    target = str(data.get("target", "")).strip()

    if not command_key:
        return err("Parameter 'command' wajib diisi.")
    if not target:
        return err("Parameter 'target' wajib diisi.")

    result = net_tools_run_tool(command_key, target)
    if not result.get("ok"):
        return err(result.get("error", "Command gagal dijalankan."), 400)

    add_history(f"NetTools: {command_key} {target}")
    return ok(result)

@app.route("/cors", methods=["GET", "POST"])
def cors_page():
    result = err = target = None
    if request.method == "POST":
        target = request.form.get("cors_target", "").strip()
        if not target:
            err = "Masukkan URL."
        else:
            result = check_cors(target)
            add_history(f"CORS: {target}")
            save_report("cors", result)
    return render_template("cors.html", cors_result=result, cors_error=err, cors_target=target, **history_ctx())

@app.route("/takeover", methods=["GET", "POST"])
def takeover_page():
    result = err = subs_input = None
    if request.method == "POST":
        subs_input = request.form.get("takeover_subs", "").strip()
        if not subs_input:
            err = "Masukkan daftar subdomain (satu per baris)."
        else:
            subs = [s.strip() for s in subs_input.split("\n") if s.strip()]
            result = check_takeover(subs)
            add_history(f"Takeover: {len(subs)} subdomains")
            save_report("takeover", result)
    return render_template("takeover.html", takeover_result=result, takeover_error=err, takeover_input=subs_input, **history_ctx())

@app.route("/breach", methods=["GET", "POST"])
def breach_page():
    result = err = email = phone = None
    breach_type = request.form.get("breach_type", "email")
    if request.method == "POST":
        if breach_type == "phone":
            phone = request.form.get("breach_phone", "").strip()
            valid = validate_phone_id(phone)
            if not valid:
                err = "Format nomor HP tidak valid."
            else:
                result = search_all_breaches_phone(valid)
                add_history(f"Breach (phone): {valid}")
                save_report("breach", result)
        else:
            email = request.form.get("breach_email", "").strip()
            valid = validate_email(email)
            if not valid:
                err = "Format email tidak valid."
            else:
                result = search_all_breaches(valid)
                add_history(f"Breach: {valid}")
                save_report("breach", result)
    return render_template("breach.html", breach_result=result, breach_error=err,
                            breach_email=email, breach_phone=phone, breach_type=breach_type,
                            **history_ctx())

@app.route("/ipinfo", methods=["GET", "POST"])
def ipinfo_page():
    result = err = target = None
    if request.method == "POST":
        target = request.form.get("ip_target", "").strip()
        if not target:
            err = "Masukkan IP atau domain."
        else:
            result = full_ip_lookup(target)
            add_history(f"IPInfo: {target}")
            save_report("ipinfo", result)
    return render_template("ipinfo.html", ip_result=result, ip_error=err, ip_target=target, **history_ctx())

@app.route("/metadata", methods=["GET", "POST"])
def metadata_page():
    result = err = url = None
    if request.method == "POST":
        url = request.form.get("meta_url", "").strip()
        if not url:
            err = "Masukkan URL file."
        else:
            result = extract_metadata(url)
            add_history(f"Metadata: {url}")
            save_report("metadata", result)
    return render_template("metadata.html", meta_result=result, meta_error=err, meta_url=url, **history_ctx())

@app.route("/origin-ip", methods=["GET", "POST"])
@handle_errors
@limiter.limit("10 per minute")
def origin_ip_page():
    result = err = target = None
    if request.method == "POST":
        target = sanitize_input(request.form.get("target", "").strip())
        if not target:
            err = "Masukkan domain atau URL target."
        else:
            # SSRF protection
            is_valid, error_msg = validate_url_target(target)
            if not is_valid:
                err = error_msg
            else:
                result = find_origin_ip(target)
                add_history(f"OriginIP: {target}")
                save_report("origin_ip", result)
    return render_template("origin_ip.html", result=result, error=err, target=target, **history_ctx())

# ============================================================
#  Export
# ============================================================
@app.route("/export")
def export_report():
    sid = session.get("sid")
    entry = REPORTS.get(sid) if sid else None
    if not entry:
        return "Tidak ada laporan untuk diekspor", 400
    report_type = entry["type"]
    report = entry["data"]

    if report_type == "phone":
        filename = f"phonegg_phone_{report['number']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Report - {datetime.now()}\nNomor: {report['number']}\nOperator: {report['operator']}\nWhatsApp: {report['wa_status']}\n\nLink Pencarian:\n"
        for label, url in report["links"].items():
            content += f"  {label}: {url}\n"
        if report.get("google_results"):
            content += "\nGoogle API:\n"
            for item in report["google_results"]:
                content += f"  {item.get('title','')} - {item.get('link','')}\n"
    elif report_type == "email":
        filename = f"phonegg_email_{report['email']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Report - {datetime.now()}\nEmail: {report['email']}\n"
        content += f"Gravatar: {report.get('gravatar', 'Tidak ada')}\n"
        hibp = report["hibp"]
        if hibp.get("breached") is True:
            content += f"HIBP: TERLIBAT ({hibp.get('count',0)} breach) - {', '.join(hibp.get('breaches',[]))}\n"
        elif hibp.get("breached") is False:
            content += "HIBP: AMAN\n"
        else:
            content += f"HIBP: {hibp.get('error', 'Tidak bisa dicek')}\n"
        content += "\nLink Pencarian:\n"
        for label, url in report["links"].items():
            content += f"  {label}: {url}\n"
    elif report_type == "username":
        filename = f"phonegg_username_{report['username']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Report - {datetime.now()}\nUsername: {report['username']}\n"
        found = [p for p, s in report["details"].items() if s == "found"]
        content += f"Platform ditemukan ({len(found)}):\n"
        for p in found:
            content += f"  - {p}: {report['links'][p]}\n"
    elif report_type == "subdomain":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("domain", "target"))[:50]
        filename = f"phonegg_subdomain_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Subdomain Report - {datetime.now()}\nDomain: {report['domain']}\nTotal: {report.get('total',0)}\n\n"
        for s in report.get("subdomains", []):
            content += f"  {s}\n"
    elif report_type == "portscan":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("host", "target"))[:50]
        filename = f"phonegg_portscan_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Port Scan Report - {datetime.now()}\nHost: {report.get('host')} ({report.get('ip')})\n"
        content += f"Total scanned: {report.get('total_scanned')} | Open: {report.get('total_open')}\n\n"
        for p in report.get("open_ports", []):
            content += f"  {p['port']}/{p['service']} - OPEN\n"
    elif report_type == "cors":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("url", "target"))[:50]
        filename = f"phonegg_cors_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG CORS Report - {datetime.now()}\nURL: {report.get('url')}\nVulnerable: {report.get('vulnerable')}\nSeverity: {report.get('severity')}\n\n"
        for f in report.get("findings", []):
            content += f"  Origin: {f.get('origin_tested')} | ACAO: {f.get('acao')} | ACAC: {f.get('acac')}\n"
            for issue in f.get("issues", []):
                content += f"    - {issue}\n"
    elif report_type == "breach":
        target = report.get("email") or report.get("phone") or "unknown"
        label = "Email" if report.get("email") else "Phone"
        filename = f"phonegg_breach_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Breach Report - {datetime.now()}\n{label}: {target}\n"
        content += f"Total breaches: {report.get('total_breaches', 0)}\n\nBreaches:\n"
        for b in report.get("all_breaches", []):
            content += f"  - {b}\n"
        for source, data in report.get("sources", {}).items():
            if data.get("url"):
                content += f"\n[{source}] {data.get('note','')}\n  {data['url']}\n"
    elif report_type == "wayback":
        safe = "".join(c if c.isalnum() else "_" for c in str(report.get("url") or report.get("domain", "target")))[:50]
        filename = f"phonegg_wayback_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Wayback Report - {datetime.now()}\nTotal: {report.get('total', 0)}\n\n"
        for s in report.get("snapshots", report.get("urls", [])):
            if isinstance(s, dict):
                content += f"  {s.get('wayback_url') or s.get('url', '')} ({s.get('formatted_date') or s.get('first_seen', '')})\n"
            else:
                content += f"  {s}\n"
    elif report_type == "ipinfo":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("target", "target"))[:50]
        filename = f"phonegg_ipinfo_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG IP Info Report - {datetime.now()}\nTarget: {report.get('target')}\n"
        if report.get("resolved_ips"):
            content += f"Resolved IPs: {', '.join(report['resolved_ips'])}\n"
        for ip, sources in report.get("sources", {}).items():
            content += f"\n--- {ip} ---\n"
            for src_name, src_data in sources.items():
                content += f"  [{src_name}] {src_data}\n"
    elif report_type == "dork":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("target", "target"))[:50]
        filename = f"phonegg_dork_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Dork Report - {datetime.now()}\nTarget: {report.get('target')} ({report.get('type')})\n\nLink Dork:\n"
        for label, url in report.get("links", {}).items():
            content += f"  {label}: {url}\n"
    elif report_type == "vuln":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("target", "target"))[:50]
        filename = f"phonegg_vuln_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Vuln Scan Report - {datetime.now()}\nTarget: {report.get('target')}\n"
        if report.get("error"):
            content += f"Error: {report['error']}\n"
        else:
            s = report.get("summary", {})
            content += (f"Engine: {report.get('engine')} · Durasi: {report.get('duration_seconds')}s\n"
                        f"Total temuan: {s.get('total',0)} (critical:{s.get('critical',0)} high:{s.get('high',0)} "
                        f"medium:{s.get('medium',0)} low:{s.get('low',0)} info:{s.get('info',0)})\n\n")
            for f_ in report.get("findings", []):
                content += f"  [{f_['severity']}] {f_['name']} — template:{f_['template']} @ {f_['matched_at']}\n"
    elif report_type == "dir":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("target", "target"))[:50]
        filename = f"phonegg_dir_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Dir Enum Report - {datetime.now()}\nTarget: {report.get('target')}\n"
        content += f"Ditemukan {len(report.get('found', []))} path valid dari {report.get('total', 0)} yang dicek\n\n"
        for item in report.get("found", []):
            content += f"  [{item.get('status')}] /{item.get('path')} (risk:{item.get('risk')})\n"
    elif report_type == "check404":
        filename = f"phonegg_check404_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG URL Status Report - {datetime.now()}\n"
        if report.get("error"):
            content += f"Error: {report['error']}\n"
        else:
            content += (f"URL: {report.get('url')}\nStatus Code: {report.get('status_code')}\n"
                        f"Response Time: {report.get('response_time_ms')} ms\n")
            if report.get("redirect_chain"):
                content += "Redirect Chain: " + " -> ".join(report["redirect_chain"]) + "\n"
            if report.get("ssl"):
                content += f"SSL: {report['ssl']}\n"
            if report.get("recommendation"):
                content += f"Rekomendasi: {report['recommendation']}\n"
    elif report_type == "security_headers":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("url", "target"))[:50]
        filename = f"phonegg_secheaders_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Security Headers Report - {datetime.now()}\n"
        if report.get("error"):
            content += f"Error: {report['error']}\n"
        else:
            content += f"URL: {report.get('url')}\nGrade: {report.get('grade')} · Skor: {report.get('score')}/{report.get('max_score')}\n\n"
            for name, info in report.get("security_headers", {}).items():
                content += f"  {name}: {'Ada' if info.get('found') else 'Tidak ada'} ({info.get('value') or '-'})\n"
            if report.get("recommendations"):
                content += "\nRekomendasi:\n"
                for rec in report["recommendations"]:
                    content += f"  - {rec}\n"
    elif report_type == "tech_detect":
        safe = "".join(c if c.isalnum() else "_" for c in report.get("url", "target"))[:50]
        filename = f"phonegg_techdetect_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Tech Detect Report - {datetime.now()}\n"
        if report.get("error"):
            content += f"Error: {report['error']}\n"
        else:
            content += f"URL: {report.get('url')}\nTotal Terdeteksi: {report.get('total_detected')}\n\n"
            for category, techs in report.get("technologies", {}).items():
                content += f"  {category}: {techs}\n"
    elif report_type == "takeover":
        filename = f"phonegg_takeover_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Subdomain Takeover Report - {datetime.now()}\n"
        content += f"{report.get('total_vulnerable',0)} vulnerable / {report.get('total_checked',0)} checked\n\n"
        for v in report.get("vulnerable", []):
            content += f"  {v.get('subdomain')} — CNAME:{v.get('cname')} -> {v.get('service')} (evidence: {v.get('evidence')})\n"
    elif report_type == "metadata":
        filename = f"phonegg_metadata_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Metadata Report - {datetime.now()}\n"
        if report.get("error"):
            content += f"Error: {report['error']}\n"
        else:
            content += f"Format: {report.get('format')}\nDimensions: {report.get('size')}\n"
            if report.get("gps"):
                content += f"GPS: {report['gps'].get('latitude')}, {report['gps'].get('longitude')}\n"
            content += f"\nFull metadata:\n{report}\n"
    else:
        filename = f"phonegg_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        content = f"PhoneGG Report - {datetime.now()}\nType: {report_type}\n\n{report}"

    path = os.path.join(EXPORT_DIR, filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(str(content))
    except Exception as e:
        return f"Gagal export: {e}", 500
    return send_file(path, as_attachment=True)

# ============================================================
#  REST API
# ============================================================
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    API_KEY = secrets.token_urlsafe(24)
    print(f"[PhoneGG] PERINGATAN: env var API_KEY tidak diset. Menggunakan API key "
          f"acak sementara (berubah tiap restart): {API_KEY}\n"
          f"[PhoneGG] Set API_KEY di environment/.env untuk production.")

CORS(app)

Swagger(app, config={
    "headers": [],
    "specs": [{
        "endpoint": "apispec",
        "route": "/apispec.json",
        "rule_filter": lambda rule: True,
        "model_filter": lambda tag: True,
    }],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
})

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if not key or key != API_KEY:
            return jsonify({
                "status": "error", "code": 401,
                "message": "Unauthorized. Invalid or missing API Key",
                "timestamp": datetime.now().isoformat(),
            }), 401
        return f(*args, **kwargs)
    return decorated

def ok(data, path=None):
    try:
        return jsonify({
            "status": "success", "data": data,
            "timestamp": datetime.now().isoformat(),
            "path": path or request.path,
        })
    except Exception as e:
        # Jaga-jaga jika 'data' berisi objek yang tidak bisa di-serialize ke JSON
        logger.error(f"[ok] Gagal serialize response: {e}")
        return jsonify({
            "status": "error", "code": 500,
            "message": "Gagal membentuk response JSON",
            "timestamp": datetime.now().isoformat(),
            "path": path or request.path,
        }), 500

def err(msg, code=400, path=None):
    try:
        return jsonify({
            "status": "error", "code": code, "message": str(msg),
            "timestamp": datetime.now().isoformat(),
            "path": path or request.path,
        }), code
    except Exception:
        return jsonify({
            "status": "error", "code": 500, "message": "Unknown error",
            "timestamp": datetime.now().isoformat(),
        }), 500

# ── Original API ──
@app.route("/api/v1/phone", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_phone():
    try:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return err("Body request harus berupa JSON object yang valid")

        raw_number = data.get("number")
        if not raw_number or not isinstance(raw_number, str):
            return err("Parameter 'number' wajib diisi dan berupa teks")

        number = validate_phone_id(raw_number.strip())
        if not number:
            return err("Format nomor tidak valid. Gunakan 08xx / 628xx.")

        op = detect_operator(number) or {}

        # google_search / check_whatsapp_status / generate_dork_urls memanggil
        # layanan luar yang bisa gagal (timeout, rate limit, dsb) — jangan
        # sampai satu kegagalan menjatuhkan seluruh response.
        try:
            wa_status = check_whatsapp_status(number)
        except Exception as e:
            logger.warning(f"[api_phone] check_whatsapp_status gagal: {e}")
            wa_status = {}

        try:
            links = generate_dork_urls(number)
        except Exception as e:
            logger.warning(f"[api_phone] generate_dork_urls gagal: {e}")
            links = {}

        try:
            google_results = google_search(f'"{number}" OR "0{number[2:]}"', max_results=5)
        except Exception as e:
            logger.warning(f"[api_phone] google_search gagal: {e}")
            google_results = []

        return ok({
            "number": number,
            "operator": op.get("operator", "Unknown"),
            "country": op.get("country", "Unknown"),
            "prefix": op.get("prefix", "Unknown"),
            "wa_status": wa_status,
            "links": links,
            "google_results": google_results,
        })
    except Exception as e:
        logger.error(f"[api_phone] Unhandled error: {e}")
        return err("Terjadi kesalahan saat memproses permintaan", 500)

@app.route("/api/v1/phone-graph", methods=["POST"])
@limiter.limit("15 per minute")
def api_phone_graph():
    """
    Phone Graph Visualization API

    Returns phone lookup data in graph format (nodes + edges) for Vis.js Network
    visualization. Endpoint ini dirancang untuk TIDAK PERNAH crash — setiap
    tahap (parsing JSON, validasi nomor, pemanggilan modul eksternal, dan
    pembangunan graph) dibungkus try-except sendiri dengan fallback yang aman,
    supaya kegagalan pada satu bagian tidak menjatuhkan seluruh request.
    """
    # 1) Parsing body JSON — tahan terhadap body kosong / bukan JSON / bukan object
    try:
        data = request.get_json(silent=True)
    except Exception as e:
        logger.warning(f"[api_phone_graph] Gagal parsing JSON: {e}")
        data = None

    if not isinstance(data, dict):
        return err("Body request harus berupa JSON object yang valid, mis. {\"phone\": \"08xxxxxxxxxx\"}")

    raw_phone = data.get("phone")
    if not raw_phone or not isinstance(raw_phone, str):
        return err("Parameter 'phone' wajib diisi dan berupa teks")

    # 2) Validasi nomor
    try:
        number = validate_phone_id(raw_phone.strip())
    except Exception as e:
        logger.warning(f"[api_phone_graph] Gagal validasi nomor: {e}")
        number = None

    if not number:
        return err("Format nomor tidak valid. Gunakan 08xx / 628xx.")

    # 3) Kumpulkan data lookup — masing-masing sumber dibungkus try-except
    #    terpisah dengan nilai default aman, supaya satu modul yang error/timeout
    #    tidak membuat seluruh graph gagal dibangun.
    try:
        wa_status = check_whatsapp_status(number)
    except Exception as e:
        logger.warning(f"[api_phone_graph] check_whatsapp_status gagal: {e}")
        wa_status = {}

    try:
        links = generate_dork_urls(number)
    except Exception as e:
        logger.warning(f"[api_phone_graph] generate_dork_urls gagal: {e}")
        links = {}

    try:
        operator_info = detect_operator(number) or {}
    except Exception as e:
        logger.warning(f"[api_phone_graph] detect_operator gagal: {e}")
        operator_info = {}

    try:
        google_results = google_search(f'"{number}" OR "0{number[2:]}"', max_results=5)
    except Exception as e:
        logger.warning(f"[api_phone_graph] google_search gagal: {e}")
        google_results = []

    try:
        ml_risk = get_phone_risk_prediction(number)
    except Exception as e:
        logger.warning(f"[api_phone_graph] get_phone_risk_prediction gagal: {e}")
        ml_risk = {}

    # Build complete phone data object — semua field punya fallback aman
    phone_data = {
        "number": number,
        "operator": operator_info.get("operator", "Unknown") if isinstance(operator_info, dict) else "Unknown",
        "country": operator_info.get("country", "Unknown") if isinstance(operator_info, dict) else "Unknown",
        "prefix": operator_info.get("prefix", "Unknown") if isinstance(operator_info, dict) else "Unknown",
        "wa_status": wa_status if isinstance(wa_status, dict) else {},
        "links": links if isinstance(links, dict) else {},
        "google_results": google_results if isinstance(google_results, list) else [],
        "ml_risk_prediction": ml_risk if isinstance(ml_risk, dict) else {}
    }

    # 4) Konversi ke format graph — build_phone_graph sendiri sudah tidak
    #    pernah melempar exception, tapi tetap dijaga di sini sebagai lapisan
    #    pertahanan terakhir (defense in depth).
    try:
        graph = build_phone_graph(phone_data)
        if not isinstance(graph, dict):
            raise ValueError("build_phone_graph mengembalikan tipe data tidak valid")
    except Exception as e:
        logger.error(f"[api_phone_graph] build_phone_graph gagal: {e}")
        graph = {
            "nodes": [], "edges": [],
            "metadata": {
                "phone": number, "operator": phone_data["operator"],
                "country": phone_data["country"], "risk_score": 0,
                "risk_level": "Unknown", "node_count": 0, "edge_count": 0,
                "error": "Gagal membangun graph visualisasi",
            }
        }

    graph["lookup_data"] = phone_data
    return ok(graph)

# ============================================================
#  PhoneGG Pen — Repeater (authorized pentest tooling)
#  Kirim & modifikasi HTTP request custom, mirip tab Repeater di
#  Burp Suite. WAJIB hanya dipakai pada target yang sudah diberi
#  izin tertulis (authorized penetration testing).
# ============================================================
@app.route("/pen/repeater")
def pen_repeater_page():
    """Halaman UI Pen Repeater — request builder + response viewer."""
    return render_template("pen_repeater.html", **history_ctx())

@app.route("/api/v1/pen/repeater", methods=["POST"])
@limiter.limit("20 per minute")
def api_pen_repeater():
    """
    Kirim satu HTTP request custom (method/url/headers/body) ke target
    yang sudah diizinkan, lalu kembalikan response mentahnya.

    Body JSON yang diterima:
        {
          "url": "https://target.example.com/path",
          "method": "GET",
          "headers": [{"key": "X-Test", "value": "1"}]  (atau object biasa),
          "body": "raw body string (opsional)",
          "timeout": 10,
          "follow_redirects": false,
          "cookies": {"session_id": "abc123"}  (opsional — dari cookie jar frontend)
        }
    """
    try:
        data = request.get_json(silent=True)
    except Exception as e:
        logger.warning(f"[api_pen_repeater] Gagal parsing JSON: {e}")
        data = None

    if not isinstance(data, dict):
        return err("Body request harus berupa JSON object yang valid")

    url = data.get("url")
    if not url or not isinstance(url, str):
        return err("Parameter 'url' wajib diisi dan berupa teks")

    cookies_in = data.get("cookies")
    if cookies_in is not None and not isinstance(cookies_in, dict):
        return err("Parameter 'cookies' harus berupa object {nama: nilai}")

    result = send_pen_request(
        url=url,
        method=data.get("method", "GET"),
        headers=data.get("headers"),
        body=data.get("body"),
        timeout=data.get("timeout"),
        follow_redirects=bool(data.get("follow_redirects", False)),
        cookies=cookies_in,
    )

    entry_id = secrets.token_hex(6)
    entry_time = datetime.now().strftime("%H:%M:%S %d-%m-%Y")

    if not result.get("ok"):
        # Simpan juga percobaan yang gagal (mirip Burp: request error tetap tercatat di history)
        save_pen_history({
            "id": entry_id,
            "time": entry_time,
            "method": (data.get("method") or "GET").upper(),
            "url": url,
            "status_code": None,
            "elapsed_ms": None,
            "error": result.get("error", "Request gagal diproses"),
            "request": {
                "method": (data.get("method") or "GET").upper(),
                "url": url,
                "headers": normalize_headers_for_display(data.get("headers")),
                "body": data.get("body"),
            },
            "response": None,
        })
        return err(result.get("error", "Request gagal diproses"), 400)

    save_pen_history({
        "id": entry_id,
        "time": entry_time,
        "method": result["request"]["method"],
        "url": result["request"]["url"],
        "status_code": result["response"]["status_code"],
        "elapsed_ms": result["response"]["elapsed_ms"],
        "error": None,
        "request": result["request"],
        "response": result["response"],
    })

    return ok({"id": entry_id, "request": result["request"], "response": result["response"]})

@app.route("/api/v1/pen/repeater/parse", methods=["POST"])
@limiter.limit("20 per minute")
def api_pen_repeater_parse():
    """
    Parsing raw HTTP request text (gaya paste dari DevTools/proxy lain)
    menjadi field method/url/headers/body untuk mengisi form Repeater
    secara otomatis.

    Body JSON: {"raw": "GET /path HTTP/1.1\\nHost: example.com\\n..."}
    """
    try:
        data = request.get_json(silent=True)
    except Exception as e:
        logger.warning(f"[api_pen_repeater_parse] Gagal parsing JSON: {e}")
        data = None

    if not isinstance(data, dict):
        return err("Body request harus berupa JSON object yang valid")

    raw_text = data.get("raw")
    if not raw_text or not isinstance(raw_text, str):
        return err("Parameter 'raw' wajib diisi dan berupa teks")

    result = parse_raw_request(raw_text)
    if not result.get("ok"):
        return err(result.get("error", "Gagal parsing raw request"), 400)

    return ok(result)

@app.route("/api/v1/pen/repeater/history", methods=["GET"])
def api_pen_repeater_history_list():
    """Daftar ringkas riwayat request Repeater untuk sesi saat ini (terbaru duluan)."""
    try:
        items = PEN_HISTORY.get(get_sid(), [])
        summary = [{
            "id": it.get("id"),
            "time": it.get("time"),
            "method": it.get("method"),
            "url": it.get("url"),
            "status_code": it.get("status_code"),
            "elapsed_ms": it.get("elapsed_ms"),
            "error": it.get("error"),
        } for it in items]
        return ok({"history": summary})
    except Exception as e:
        logger.error(f"[api_pen_repeater_history_list] {e}")
        return err("Gagal mengambil riwayat", 500)

@app.route("/api/v1/pen/repeater/history/<hid>", methods=["GET"])
def api_pen_repeater_history_get(hid):
    """Ambil satu entri riwayat lengkap (request + response penuh) untuk dimuat ulang ke Repeater."""
    try:
        items = PEN_HISTORY.get(get_sid(), [])
        match = next((it for it in items if it.get("id") == hid), None)
        if not match:
            return err("Riwayat tidak ditemukan (mungkin sudah dihapus atau sesi berbeda)", 404)
        return ok(match)
    except Exception as e:
        logger.error(f"[api_pen_repeater_history_get] {e}")
        return err("Gagal mengambil detail riwayat", 500)

@app.route("/api/v1/pen/repeater/history/<hid>", methods=["DELETE"])
def api_pen_repeater_history_delete(hid):
    """Hapus satu entri riwayat berdasarkan id."""
    try:
        sid = get_sid()
        items = PEN_HISTORY.get(sid, [])
        new_items = [it for it in items if it.get("id") != hid]
        deleted = len(new_items) != len(items)
        PEN_HISTORY[sid] = new_items
        return ok({"deleted": deleted})
    except Exception as e:
        logger.error(f"[api_pen_repeater_history_delete] {e}")
        return err("Gagal menghapus riwayat", 500)

@app.route("/api/v1/pen/repeater/history", methods=["DELETE"])
def api_pen_repeater_history_clear():
    """Kosongkan seluruh riwayat Repeater untuk sesi saat ini."""
    try:
        PEN_HISTORY[get_sid()] = []
        return ok({"cleared": True})
    except Exception as e:
        logger.error(f"[api_pen_repeater_history_clear] {e}")
        return err("Gagal mengosongkan riwayat", 500)

@app.route("/api/v1/email", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_email():
    data = request.get_json(silent=True) or {}
    if "email" not in data:
        return err("Parameter 'email' wajib diisi")
    email = validate_email(data["email"].strip())
    if not email:
        return err("Format email tidak valid.")
    return ok({
        "email": email, "hibp": check_hibp(email),
        "links": generate_email_dork_urls(email),
        "google_results": google_search(f'"{email}"', max_results=5),
        "reputation": check_email_reputation(email),
        "gravatar": get_gravatar(email),
        "domain_info": get_domain_info(email),
    })

@app.route("/api/v1/username", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_username():
    data = request.get_json(silent=True) or {}
    if "username" not in data:
        return err("Parameter 'username' wajib diisi")
    username = data["username"].strip()
    if not username:
        return err("Username tidak boleh kosong.")
    detailed = check_username_detailed(username)
    results = {r["platform"]: r["status"] for r in detailed["results"]}
    found = [r["platform"] for r in detailed["results"] if r["status"] == "found"]
    links = {p: cfg["url"].format(username=username) for p, cfg in PLATFORMS.items()}
    return ok({
        "username": username,
        "summary": detailed["summary"],
        "found": found,
        "details": results,
        "links": links,
        "results": detailed["results"],
    })

@app.route("/api/v1/vuln", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_vuln():
    data = request.get_json(silent=True) or {}
    if "target" not in data:
        return err("Parameter 'target' wajib diisi")
    target = data["target"].strip()
    severity = data.get("severity", "medium")
    if severity not in ["low", "medium", "high", "critical"]:
        return err("Severity harus: low, medium, high, critical")
    return ok(scan_domain(target, severity=severity))

@app.route("/api/v1/dir", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_dir():
    data = request.get_json(silent=True) or {}
    if "target" not in data:
        return err("Parameter 'target' wajib diisi")
    target = data["target"].strip()
    if not target:
        return err("Target tidak boleh kosong.")
    raw = scan_directories(target)
    valid = [r for r in raw if not r.get("fake_404", False) and r["status"] in (200, 301, 302, 403, 401)]
    fake = [r for r in raw if r.get("fake_404", False)]
    return ok({"target": target, "found": valid, "fake": fake, "total": len(raw)})

@app.route("/api/v1/dork", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_dork():
    data = request.get_json(silent=True) or {}
    if "target" not in data:
        return err("Parameter 'target' wajib diisi")
    target = data["target"].strip()
    dtype = data.get("type", "phone")
    if dtype == "email":
        valid = validate_email(target)
        if not valid:
            return err("Format email tidak valid.")
        return ok({"target": valid, "type": "email", "links": generate_email_dork_urls(valid)})
    number = validate_phone_id(target)
    if not number:
        return err("Format nomor tidak valid. Gunakan 08xx / 628xx.")
    return ok({"target": number, "type": "phone", "links": generate_dork_urls(number)})

@app.route("/api/v1/check404", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_check404():
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    return ok(check_url_status(url))

@app.route("/api/v1/security-headers", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_security_headers():
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    result = analyze_security_headers(url)
    if result.get("error"):
        return err(result["error"])
    return ok(result)

@app.route("/api/v1/tech-detect", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_tech_detect():
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    result = detect_technologies(url)
    if result.get("error"):
        return err(result["error"])
    return ok(result)

@app.route("/api/v1/header-detector", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_header_detector():
    """
    Analisis header HTTP dan deteksi teknologi web
    ---
    tags:
      - Web Analysis
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            url:
              type: string
              description: Target URL
    responses:
      200:
        description: Header analysis result
    """
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    result = analyze_headers(url)
    if result.get("error"):
        return err(result["error"])
    return ok(result)

@app.route("/api/v1/link-scraper", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_link_scraper():
    """
    Extract link dan script dari HTML dengan highlight sensitif
    ---
    tags:
      - Web Analysis
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            url:
              type: string
              description: Target URL
            category:
              type: string
              description: Filter category (all, sensitive, scripts, links)
              default: all
    responses:
      200:
        description: Link and script extraction result
    """
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    category = data.get("category", "all")
    if category == "all":
        result = extract_links_and_scripts(url)
    else:
        result = extract_by_category(url, category)
    if result.get("error"):
        return err(result["error"])
    return ok(result)

# ── New API ──
@app.route("/api/v1/subdomain", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_subdomain():
    data = request.get_json(silent=True) or {}
    if "target" not in data:
        return err("Parameter 'target' wajib diisi")
    target = data["target"].strip()
    if not target:
        return err("Target tidak boleh kosong.")
    return ok(enumerate_subdomains(target,
        use_crtsh=data.get("use_crtsh", True),
        use_bruteforce=data.get("use_bruteforce", True),
        use_search=data.get("use_search", True)))

@app.route("/api/v1/wayback", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_wayback():
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    if data.get("mode") == "all_urls":
        return ok(get_all_urls_for_domain(url))
    return ok(get_snapshots(url))

@app.route("/api/v1/portscan", methods=["POST"])
@limiter.limit("3 per minute")
@require_api_key
def api_portscan():
    data = request.get_json(silent=True) or {}
    if "target" not in data:
        return err("Parameter 'target' wajib diisi")
    target = data["target"].strip()
    if not target:
        return err("Target tidak boleh kosong.")
    return ok(scan_ports(target, ports=data.get("ports"), extended=data.get("extended", False)))

@app.route("/api/v1/cors", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_cors():
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    return ok(check_cors(url))

@app.route("/api/v1/takeover", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_takeover():
    data = request.get_json(silent=True) or {}
    if "subdomains" not in data:
        return err("Parameter 'subdomains' (list) wajib diisi")
    subs = data["subdomains"]
    if not isinstance(subs, list) or not subs:
        return err("subdomains harus berupa list dan tidak kosong")
    return ok(check_takeover(subs))

@app.route("/api/v1/breach", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_breach():
    data = request.get_json(silent=True) or {}
    if "email" not in data:
        return err("Parameter 'email' wajib diisi")
    email = validate_email(data["email"].strip())
    if not email:
        return err("Format email tidak valid.")
    return ok(search_all_breaches(email))

@app.route("/api/v1/breach-phone", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_breach_phone():
    data = request.get_json(silent=True) or {}
    if "phone" not in data:
        return err("Parameter 'phone' wajib diisi")
    phone = validate_phone_id(data["phone"].strip())
    if not phone:
        return err("Format nomor HP tidak valid.")
    return ok(search_all_breaches_phone(phone))

@app.route("/api/v1/ipinfo", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_ipinfo():
    data = request.get_json(silent=True) or {}
    if "target" not in data:
        return err("Parameter 'target' wajib diisi")
    target = data["target"].strip()
    return ok(full_ip_lookup(target))

@app.route("/api/v1/origin-ip", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_origin_ip():
    data = request.get_json(silent=True) or {}
    if "target" not in data:
        return err("Parameter 'target' wajib diisi")
    target = data["target"].strip()
    # SSRF protection
    is_valid, error_msg = validate_url_target(target)
    if not is_valid:
        return err(error_msg)
    return ok(find_origin_ip(target))
    target = data["target"].strip()
    if not target:
        return err("Target tidak boleh kosong.")
    return ok(full_ip_lookup(target))

@app.route("/api/v1/metadata", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_metadata():
    data = request.get_json(silent=True) or {}
    if "url" not in data:
        return err("Parameter 'url' wajib diisi")
    url = data["url"].strip()
    if not url:
        return err("URL tidak boleh kosong.")
    return ok(extract_metadata(url))

# ── AI Analysis API Routes ──

@app.route("/api/analyze-risk", methods=["POST"])
@limiter.limit("10 per minute")
def api_analyze_risk():
    """
    Analyze phone number risk using ML model.
    Public endpoint (no API key required) for basic risk assessment.
    """
    data = request.get_json(silent=True) or {}
    if "phone_number" not in data:
        return err("Parameter 'phone_number' wajib diisi")
    
    phone_number = data["phone_number"].strip()
    if not phone_number:
        return err("Nomor telepon tidak boleh kosong.")
    
    try:
        # Normalize phone number
        normalized = validate_phone_id(phone_number)
        if not normalized:
            return err("Format nomor tidak valid. Gunakan 08xx / 628xx.")
        
        # Get ML risk prediction
        risk_prediction = get_phone_risk_prediction(normalized)
        
        return ok({
            "phone_number": normalized,
            "original_input": phone_number,
            "risk_analysis": risk_prediction,
            "analyzed_at": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Risk analysis error: {str(e)}")
        return err(f"Gagal menganalisis risiko: {str(e)}")

@app.route("/api/v1/ai-analysis", methods=["POST"])
@limiter.limit("5 per minute")
@require_api_key
def api_ai_analysis():
    """
    Advanced AI analysis using AI Native Engine (Local/Internal).
    100% offline and independent - No external API dependencies.
    Credit: NEFZX
    """
    data = request.get_json(silent=True) or {}
    if "phone_number" not in data:
        return err("Parameter 'phone_number' wajib diisi")
    
    phone_number = data["phone_number"].strip()
    if not phone_number:
        return err("Nomor telepon tidak boleh kosong.")
    
    try:
        # Normalize phone number
        normalized = validate_phone_id(phone_number)
        if not normalized:
            return err("Format nomor tidak valid. Gunakan 08xx / 628xx.")
        
        # Gather raw data for analysis
        raw_data = {
            "timestamp": datetime.now().isoformat(),
            "phone_number": normalized
        }
        
        # Add available intelligence
        operator_info = detect_operator(normalized)
        raw_data.update(operator_info)
        
        raw_data["wa_status"] = check_whatsapp_status(normalized)
        raw_data["links"] = generate_dork_urls(normalized)
        
        # Get ML prediction if available
        ml_prediction = get_phone_risk_prediction(normalized)
        raw_data["ml_prediction"] = ml_prediction
        
        # Get AI analysis
        ai_result = get_ai_analysis(normalized, raw_data)
        
        return ok({
            "phone_number": normalized,
            "original_input": phone_number,
            "ai_analysis": ai_result,
            "ml_risk_prediction": ml_prediction,
            "analyzed_at": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"AI analysis error: {str(e)}")
        return err(f"Gagal menganalisis dengan AI: {str(e)}")

@app.route("/api/custom-ai/analyze", methods=["POST"])
@limiter.limit("10 per minute")
@require_api_key
def api_custom_ai_analyze():
    """
    Custom AI Engine - Analisis data kustom dengan heuristik dan pattern matching
    ---
    tags:
      - AI Analysis
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            data_type:
              type: string
              description: Tipe data (text, url, email, phone, generic)
              default: generic
            input_payload:
              type: object
              description: Dictionary data yang akan dianalisis
            custom_rules:
              type: object
              description: Aturan kustom opsional
    responses:
      200:
        description: Hasil analisis custom AI
    """
    data = request.get_json(silent=True) or {}
    
    # Validasi data_type
    data_type = data.get("data_type", "generic")
    if not data_type:
        return err("Parameter 'data_type' wajib diisi")
    
    # Validasi input_payload
    input_payload = data.get("input_payload")
    if not input_payload or not isinstance(input_payload, dict):
        return err("Parameter 'input_payload' wajib diisi dan harus berupa dictionary")
    
    if not input_payload:
        return err("Input payload tidak boleh kosong")
    
    # Get custom rules jika ada
    custom_rules = data.get("custom_rules")
    
    try:
        result = analyze_custom_data(data_type, input_payload, custom_rules)
        
        if result.get("status") == "error":
            return err(result.get("error", "Gagal menganalisis data"))
        
        return ok(result)
    except Exception as e:
        logger.error(f"Custom AI analysis error: {str(e)}")
        return err(f"Gagal menganalisis dengan Custom AI: {str(e)}")

@app.route("/api/ai-chatbot", methods=["POST"])
@limiter.limit("20 per minute")
def api_ai_chatbot():
    """
    AIZX Native Engine Chatbot - Universal AI Assistant for security analysis,
    code generation, and general Q&A.
    Credit: NEFZX
    """
    data = request.get_json(silent=True) or {}
    
    message = data.get("message", "").strip()
    if not message:
        return err("Parameter 'message' wajib diisi")
    
    analysis_context = data.get("analysis_context")

    # Per-session chat history so concurrent users never see each other's
    # conversation. Previously this was a single history list shared by the
    # whole process (one instance of AIChatbot for all users), so under
    # real traffic different people's chats would bleed into each other.
    sid = get_sid()
    chat_history = CHAT_SESSIONS.get(sid, [])

    try:
        response, chat_history = process_chat_message(message, analysis_context, chat_history)
        CHAT_SESSIONS[sid] = chat_history[-40:]  # cap length, keep recent context

        # Ensure response is not None or empty
        if not response:
            response = "Maaf, saya tidak dapat memproses permintaan tersebut. Silakan coba lagi."
        
        return ok({
            "response": response,
            "engine": "LynaeZx Chatbot",
            "credit": "NEFZX",
            "timestamp": datetime.now().isoformat(),
            "analysis_context": analysis_context  # Echo back context for frontend
        })
    except Exception as e:
        logger.error(f"AI Chatbot error: {str(e)}")
        # Return a user-friendly error message
        return ok({
            "response": f"Maaf, terjadi kesalahan saat memproses pesan Anda: {str(e)}",
            "engine": "LynaeZx Chatbot",
            "credit": "NEFZX",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        })

@app.route("/api/export-apk", methods=["GET"])
@limiter.limit("3 per minute")
def api_export_apk():
    """
    Export PhoneGG as Android APK (WebView wrapper).
    Generates a downloadable APK configuration file.
    Credit: NEFZX
    """
    try:
        # Get current server URL
        server_url = request.host_url.rstrip('/')
        
        # Generate APK configuration
        apk_config = {
            "app_name": "PhoneGG",
            "package_name": "com.phonegg.osint",
            "version": "2.0.0",
            "version_code": "2",
            "min_sdk": 21,
            "target_sdk": 33,
            "permissions": [
                "INTERNET",
                "ACCESS_NETWORK_STATE",
                "READ_EXTERNAL_STORAGE",
                "WRITE_EXTERNAL_STORAGE"
            ],
            "webview_config": {
                "url": server_url,
                "enable_javascript": True,
                "dom_storage_enabled": True,
                "cache_enabled": True
            },
            "app_info": {
                "title": "PhoneGG - OSINT Toolkit",
                "description": "All-in-one OSINT toolkit for phone, email, username, domain & web reconnaissance",
                "engine": "AI Native Engine (Credit: NEFZX)",
                "author": "NEFZX"
            },
            "build_instructions": {
                "note": "This is a configuration file for building APK. Use a service like 'Website 2 APK Builder' or build with Android Studio.",
                "webview_url": server_url,
                "manifest_permissions": "INTERNET, ACCESS_NETWORK_STATE",
                "recommended_builder": "https://www.website2apk.com/ or Android Studio WebView template"
            }
        }
        
        # Create downloadable JSON file
        import tempfile
        import os
        
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(apk_config, temp_file, indent=2)
        temp_file.close()
        
        # Send file and cleanup
        def remove_file(response):
            try:
                os.unlink(temp_file.name)
            except Exception as e:
                logger.error(f"Error removing temp file: {e}")
            return response
        
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name="phonegg_apk_config.json",
            mimetype="application/json"
        )
        
        return remove_file(response)
        
    except Exception as e:
        logger.error(f"APK export error: {str(e)}")
        return err(f"Gagal mengekspor konfigurasi APK: {str(e)}")

# ── Enhanced Error Handlers ──

@app.errorhandler(404)
def not_found(e):
    """Handle 404 - Resource not found errors."""
    logger.warning(f"404 Not Found: {request.path}")
    if request.path.startswith("/api/"):
        return err("Endpoint tidak ditemukan", 404)
    return render_template("error.html", code=404, message="Halaman tidak ditemukan", **history_ctx()), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 - Internal server errors with detailed logging."""
    logger.error(f"500 Server Error: {str(e)}", exc_info=True)
    if request.path.startswith("/api/"):
        return err("Internal server error", 500)
    return render_template("error.html", code=500, message="Terjadi kesalahan server", **history_ctx()), 500

@app.errorhandler(429)
def rate_limit(e):
    """Handle 429 - Rate limit exceeded errors."""
    logger.warning(f"429 Rate Limit: {request.path}")
    if request.path.startswith("/api/"):
        return err("Rate limit tercapai. Coba lagi nanti.", 429)
    return render_template("error.html", code=429, message="Terlalu banyak request. Coba lagi nanti.", **history_ctx()), 429

@app.errorhandler(400)
def bad_request(e):
    """Handle 400 - Bad request errors."""
    logger.warning(f"400 Bad Request: {request.path}")
    if request.path.startswith("/api/"):
        return err("Bad request - invalid input", 400)
    return render_template("error.html", code=400, message="Request tidak valid", **history_ctx()), 400

@app.errorhandler(405)
def method_not_allowed(e):
    """Handle 405 - Method not allowed errors."""
    logger.warning(f"405 Method Not Allowed: {request.path} - {request.method}")
    if request.path.startswith("/api/"):
        return err("Method tidak diizinkan untuk endpoint ini", 405)
    return render_template("error.html", code=405, message="Method tidak diizinkan", **history_ctx()), 405

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all uncaught exceptions with detailed logging."""
    logger.error(f"Unhandled Exception: {str(e)}", exc_info=True)
    if request.path.startswith("/api/"):
        return err("Internal server error", 500)
    return render_template("error.html", code=500, message="Terjadi kesalahan tidak terduga", **history_ctx()), 500

# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")