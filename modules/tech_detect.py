"""
Technology stack detector — deteksi teknologi web dari headers, HTML, dan fingerprint.
Mendeteksi: CMS, framework, web server, language, CDN, analytics, JS library, dll.
"""
from __future__ import annotations
import re
import requests

# Fingerprint rules
SIGNATURES = {
    "cms": {
        "WordPress": [r"wp-content", r"wp-includes", r"/wp-json/", r"wp-meta"],
        "Joomla": [r"/components/com_", r"joomla", r"\.joomla", r"index\.php\?option="],
        "Drupal": [r"Drupal\.settings", r"drupal\.js", r"/sites/default/files/", r"X-Generator: Drupal"],
        "Magento": [r"Mage\.cookies", r"skin/frontend", r"Magento_"],
        "Ghost": [r"ghost-url", r"/ghost/", r"content/themes/"],
        "Shopify": [r"cdn\.shopify\.com", r"shopify\.theme"],
        "TYPO3": [r"typo3conf", r"typo3temp"],
    },
    "web_server": {
        "Nginx": [r"nginx"],
        "Apache": [r"apache"],
        "IIS": [r"microsoft-iis", r"IIS"],
        "LiteSpeed": [r"litespeed"],
        "Caddy": [r"caddy"],
    },
    "language": {
        "PHP": [r"\.php", r"X-Powered-By: PHP", r"PHPSESSID"],
        "Python": [r"\.py", r"X-Powered-By: Python"],
        "Node.js": [r"X-Powered-By: Express", r"node\.js", r"__next"],
        "Ruby": [r"X-Powered-By: Ruby", r"rack\.session"],
        "Java": [r"JSESSIONID", r"X-Powered-By: Servlet"],
        "ASP.NET": [r"X-Powered-By: ASP\.NET", r"__VIEWSTATE", r"asp\.net"],
        "Go": [r"X-Powered-By: Go"],
    },
    "framework": {
        "React": [r"_next/static", r"__next_data__", r"react\.js", r"react-dom"],
        "Vue.js": [r"__nuxt", r"vue\.js", r"vue\.runtime", r"data-v-"],
        "Angular": [r"ng-version", r"angular\.js", r"angular\.min\.js"],
        "Next.js": [r"_next/", r"__NEXT_DATA__", r"__next"],
        "Nuxt.js": [r"_nuxt/", r"__NUXT__"],
        "Svelte": [r"svelte-", r"\.svelte\."],
        "Laravel": [r"laravel_session", r"laravel\.js"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "Flask": [r"flask", r"X-Powered-By: Werkzeug"],
        "Rails": [r"rails", r"csrf-token.*rails", r"X-CSRF-Token"],
        "Spring Boot": [r"X-Application-Context", r"spring"],
        "Express": [r"X-Powered-By: Express", r"express"],
        "Gin": [r"X-Powered-By: Gin"],
        "FastAPI": [r"X-Powered-By: FastAPI"],
    },
    "cdn": {
        "Cloudflare": [r"cloudflare", r"cf-ray", r"__cf_bm"],
        "CloudFront": [r"cloudfront", r"X-Amz-Cf-Id"],
        "Akamai": [r"akamai", r"X-Akamai"],
        "Fastly": [r"fastly", r"X-Served-By: cache"],
        "Vercel": [r"vercel", r"x-vercel-id", r"x-vercel-cache"],
        "Netlify": [r"netlify", r"X-Netlify"],
        "jsDelivr": [r"cdn\.jsdelivr\.net"],
        "unpkg": [r"unpkg\.com"],
    },
    "analytics": {
        "Google Analytics": [r"google-analytics\.com", r"gtag\(", r"google_analytics", r"UA-\d+"],
        "Google Tag Manager": [r"googletagmanager\.com", r"GTM-"],
        "Plausible": [r"plausible\.io"],
        "Matomo": [r"matomo", r"piwik\.js"],
        "Hotjar": [r"hotjar\.com", r"hjSession"],
        "Mixpanel": [r"mixpanel\.com", r"mixpanel"],
        "Segment": [r"analytics\.segment\.com", r"segment\.io"],
        "Facebook Pixel": [r"connect\.facebook\.net.*fbevents", r"fbq\("],
    },
    "js_library": {
        "jQuery": [r"jquery", r"jQuery v", r"jquery\.js", r"jquery\.min\.js"],
        "Bootstrap": [r"bootstrap\.css", r"bootstrap\.js", r"bootstrap\.min\.js"],
        "Tailwind CSS": [r"tailwind", r"tw-"],
        "Bulma": [r"bulma\.css", r"bulma\.min\.css"],
        "Material-UI": [r"mui-", r"material-ui"],
        "Ant Design": [r"ant-design", r"antd"],
        "Lodash": [r"lodash\.js", r"lodash\.min\.js"],
        "Moment.js": [r"moment\.js", r"moment\.min\.js"],
        "D3.js": [r"d3\.js", r"d3\.min\.js"],
        "Chart.js": [r"chart\.js", r"Chart\.js"],
        "Three.js": [r"three\.js", r"three\.min\.js"],
        "GSAP": [r"gsap", r"GreenSock"],
        "Font Awesome": [r"font-awesome", r"fontawesome"],
        "Sentry": [r"sentry\.io", r"raven\.js", r"@sentry"],
    },
    "security": {
        "reCAPTCHA": [r"recaptcha", r"grecaptcha"],
        "hCaptcha": [r"hcaptcha"],
        "Cloudflare WAF": [r"cf-mitigated", r"__cf_chl"],
        "Imperva": [r"incapsula", r"visid_incap"],
    },
}


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def detect_technologies(url: str, timeout: int = 2) -> dict:
    target = _normalize_url(url)
    try:
        resp = requests.get(target, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
        final_url = resp.url
        content = resp.text
        headers_raw = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        combined = f"{headers_raw}\n{content[:50000]}"

        technologies = {}
        total = 0

        for category, sigs in SIGNATURES.items():
            techs = []
            for name, patterns in sigs.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        techs.append(name)
                        total += 1
                        break
            if techs:
                technologies[category] = techs

        # Server header
        server = resp.headers.get("Server", "")
        if server:
            technologies["server_header"] = server

        # X-Powered-By
        xpb = resp.headers.get("X-Powered-By", "")
        if xpb:
            technologies["x_powered_by"] = xpb

        return {
            "url": target,
            "final_url": final_url,
            "total_detected": total,
            "technologies": technologies,
        }
    except requests.RequestException as e:
        return {"url": target, "error": str(e)}
    except Exception as e:
        return {"url": target, "error": str(e)}
