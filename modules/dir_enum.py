"""
Directory / path enumeration — scan path umum yang sering terekspos.
Support: custom wordlist, soft-404 detection, retry, risk categorization,
concurrent scanning, extended aggressive wordlist.
"""
from __future__ import annotations
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional
from urllib.parse import urljoin, urlparse
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

HIGH_RISK_PATHS = {
    ".env", ".git", ".git/config", ".git/HEAD", ".git/index", ".svn", ".svn/entries",
    ".htpasswd", ".htaccess", "wp-config.php", "config.php", "configuration.php",
    "database.yml", "settings.py", "local_settings.py", ".aws", ".aws/credentials",
    "id_rsa", "id_dsa", ".ssh/id_rsa", "dump.sql", "backup.zip", "backup.sql",
    "backup.tar.gz", "backup.tar", "backup.tar.bz2", "credentials.json",
    "secrets.json", "secret.key", ".npmrc", ".pypirc", "docker-compose.yml",
    "docker-compose.override.yml", ".env.production", ".env.staging",
    ".env.local", ".env.development", "google-services.json",
    "GoogleService-Info.plist", "firebase-adminsdk.json",
}

COMMON_PATHS = sorted(set([
    # panel admin & auth
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "wp-login",
    "phpmyadmin", "adminer", "manager", "console", "cpanel", "webadmin",
    "admin panel", "controlpanel", "admin_area", "adminlogin", "admin/index",
    "admin/admin", "admincp", "admin1", "admin2", "admin3", "administrator/login",
    "superadmin", "siteadmin", "adminpanel", "panel", "panel/admin",
    # backup & temp
    "backup", "backups", "backup.zip", "backup.sql", "backup.tar.gz", "backup.tar",
    "backup.tar.bz2", "backup.tar.xz", "backup.bak", "backup.db",
    "tmp", "temp", "logs", "log", "old", "old_site", "new", "dev", "staging",
    "test", "beta", "debug", "archive", "archives",
    # vcs & config
    ".git", ".git/config", ".git/HEAD", ".git/index", ".git/info/refs",
    ".svn", ".svn/entries", ".svn/wc.db", ".hg", ".bzr",
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".env.backup", ".htaccess", ".htpasswd",
    "config", "config.php", "config.json", "config.yml", "config.yaml",
    "config.ini", "config.xml", "configuration.php", "settings.php",
    "settings.py", "settings.json", "local_settings.py",
    "wp-config.php", "wp-config-sample.php", "database.yml",
    "credentials.json", "secrets.json", "secret.key",
    "id_rsa", "id_dsa", ".ssh/id_rsa", ".ssh/id_dsa", ".ssh/authorized_keys",
    ".aws", ".aws/credentials", ".aws/config",
    "dump.sql", "db.sql", "database.sql", "data.sql",
    ".npmrc", ".pypirc", ".netrc", ".my.cnf",
    # framework-specific
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
    "Pipfile", "Pipfile.lock", "pom.xml", "build.gradle", "Cargo.toml",
    "go.mod", "go.sum", "tsconfig.json", "webpack.config.js",
    "next.config.js", "nuxt.config.js", "vue.config.js",
    "angular.json", "react-native.config.js",
    # API & docs
    "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "graphql", "graphiql",
    "swagger", "swagger-ui", "swagger.json", "swagger-ui.html",
    "openapi.json", "openapi.yaml", "docs", "documentation",
    "rest", "webhook", "webhooks", "callback", "callbacks",
    "health", "healthz", "status", "ready", "live",
    # devops artifacts
    "install", "setup", "migration", "migrations", "update", "upgrade",
    "cgi-bin", "server-status", "server-info", "actuator", "actuator/health",
    "actuator/env", "actuator/heapdump", "actuator/mappings",
    ".well-known", ".well-known/security.txt", ".DS_Store",
    ".idea", ".idea/workspace.xml", ".vscode", ".vscode/settings.json",
    "node_modules", "vendor", "bower_components",
    "docker-compose.yml", "docker-compose.override.yml",
    "Dockerfile", ".dockerignore", "nginx.conf", "httpd.conf",
    "google-services.json", "GoogleService-Info.plist",
    "firebase-adminsdk.json", ".firebase",
    "Jenkinsfile", ".gitlab-ci.yml", ".github", ".github/workflows",
    "Makefile", "Procfile", "vercel.json", "netlify.toml",
    "terraform.tfvars", "terraform.tfstate",
    # informational
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "crossdomain.xml",
    "humans.txt", "security.txt", "CHANGELOG", "CHANGELOG.md",
    "LICENSE", "README", "README.md", "readme.txt", "changelog.md",
    "license.txt", "version.txt", "VERSION",
    # debug/test scripts
    "phpinfo.php", "info.php", "test.php", "debug.php", "shell.php",
    "cmd.php", "eval.php", "phpinfo", "info", "test",
    # storage & uploads
    "upload", "uploads", "files", "images", "media", "static", "assets",
    "download", "downloads", "public", "private", "storage",
    "bucket", "buckets", "s3", "cdn",
    # misc
    "private", "secret", "confidential", "hidden", "database", "db", "sql", "data",
    "cron", "cron.php", "cron.sh", "scheduler", "queue",
    "mail", "mail.php", "contact", "contact.php",
    "error", "errors", "exception", "exceptions",
    "trace", "debug", "debug.log", "error.log", "access.log",
    "app.log", "application.log", "out.log",
    # CMS-specific
    "wp-content", "wp-content/uploads", "wp-content/plugins",
    "wp-content/themes", "wp-content/backup", "wp-content/uploads/backup",
    "wp-includes", "wp-json", "wp-json/wp/v2/users",
    "xmlrpc.php", "wp-cron.php", "wp-trackback.php", "wp-blog-header.php",
    "joomla", "administrator/index.php", "sites/default/settings.php",
    "sites/all/modules", "misc",
    "user/login", "user/register", "user/password",
    # common file extensions
    "backup", "backup.rar", "backup.7z", "db_backup", "db_backup.sql",
    "site.zip", "site.tar.gz", "web.zip", "web.tar.gz",
    "www.zip", "www.tar.gz", "html.zip",
]))


def extract_root_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return f"{parsed.scheme}://{parsed.netloc}/"


def is_fake_404(content: str) -> bool:
    lower = content.lower()
    indicators = ["404", "not found", "tidak ditemukan", "notfound",
                  "halaman tidak ada", "page not found", "doesn't exist",
                  "no such page", "page unavailable", "page tidak tersedia"]
    return any(ind in lower for ind in indicators)


def _risk_level(path: str, status: int) -> str:
    if path.strip("/").lower() in HIGH_RISK_PATHS:
        return "high"
    if status in (401, 403):
        return "low"
    return "medium"


def check_path(base_url: str, path: str, timeout: int = 2, retries: int = 1) -> Optional[dict]:
    url = urljoin(base_url, path)
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    }
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            status = resp.status_code
            content = resp.text
            final_url = resp.url
            fake = status == 200 and is_fake_404(content)
            if status in (200, 301, 302, 403, 401):
                return {
                    "path": path,
                    "url": url,
                    "final_url": final_url,
                    "status": status,
                    "fake_404": fake,
                    "size": len(content),
                    "risk": _risk_level(path, status) if not fake else "info",
                }
            return None
        except requests.RequestException:
            time.sleep(0.2)
            continue
    return None


def scan_directories(target_url: str, timeout: int = 5, max_workers: int = 20,
                     wordlist: Optional[List[str]] = None, retries: int = 1) -> list:
    root = extract_root_url(target_url)
    paths = wordlist if wordlist else COMMON_PATHS

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_path, root, p, timeout, retries): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    risk_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    results.sort(key=lambda r: risk_order.get(r.get("risk", "medium"), 1))
    return results
