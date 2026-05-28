from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse
import asyncio
import httpx
from bs4 import BeautifulSoup
from datetime import datetime
import os
import json
import random
import socket

app = FastAPI(title="Hamer Hunter Ultra")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("logs", exist_ok=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
]

# Великий словник для brute force
COMMON_PATHS = [
    "admin", "wp-admin", "administrator", "login", "dashboard", "phpmyadmin", "api", "backup",
    "test", "dev", "staging", "old", "new", "config", "debug", "logs", "server-status",
    "wp-json", "xmlrpc.php", "vendor", ".git", ".env", "phpinfo.php", "info.php", "admin.php",
    "cpanel", "webmail", "mysql", "database", "assets", "uploads", "files", "backup.sql"
]

async def make_request(url: str, proxy: str = None):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    timeout = httpx.Timeout(12.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, proxy=proxy, headers=headers) as client:
        return await client.get(url)

@app.get("/", response_class=HTMLResponse)
async def home():
    with open(os.path.join(BASE_DIR, "templates", "index.html"), "r", encoding="utf-8") as f:
        return f.read()

@app.post("/scan")
async def scan(target_url: str = Form(...), scan_type: str = Form(...), proxy: str = Form(None)):
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    results = {
        "target": target_url,
        "scan_type": scan_type,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "proxy": proxy or "Без проксі",
        "findings": [],
        "title": "No title"
    }

    try:
        resp = await make_request(target_url, proxy)
        results["status_code"] = resp.status_code
        soup = BeautifulSoup(resp.text, 'html.parser')
        results["title"] = soup.title.string.strip() if soup.title else "No title"
    except Exception as e:
        return JSONResponse({"error": f"Не вдалося підключитися: {str(e)}"}, status_code=400)

    # Паралельні перевірки
    tasks = [
        check_security_headers(target_url, proxy),
        check_sensitive_files(target_url, proxy),
        basic_xss_test(target_url, proxy),
        advanced_sqli_test(target_url, proxy),
        ultra_directory_brute(target_url, proxy),
        port_scan(target_url),
        waf_detection(target_url, proxy),
        open_redirect_test(target_url, proxy),
        tech_detection(target_url, proxy)
    ]

    header_check, sensitive, xss, sqli, directories, ports, waf, redirect, tech = await asyncio.gather(*tasks)

    # === РЕЗУЛЬТАТИ З РЕКОМЕНДАЦІЯМИ ===
    if header_check.get("missing"):
        results["findings"].append({
            "type": "Security Headers",
            "severity": "Medium",
            "description": f"Відсутні: {', '.join(header_check['missing'])}",
            "fix": "Додати HSTS, CSP, X-Frame-Options у конфігурацію сервера (Nginx/Apache)."
        })

    if sensitive:
        results["findings"].append({
            "type": "Sensitive / Dangerous Files",
            "severity": "Critical",
            "description": f"Знайдено: {', '.join(sensitive)}",
            "fix": "Видалити файли або заблокувати доступ через .htaccess / nginx."
        })

    if xss:
        results["findings"].append({
            "type": "Reflected XSS",
            "severity": "High",
            "description": f"Виявлено {len(xss)} вразливих payload'ів",
            "fix": "Екранувати всі виводи даних (htmlspecialchars, autoescape)."
        })

    if sqli:
        results["findings"].append({
            "type": "SQL Injection",
            "severity": "Critical",
            "description": f"Виявлено можливу SQL-ін'єкцію ({sqli})",
            "fix": "Перейти на Prepared Statements / Parameterized Queries."
        })

    if directories:
        results["findings"].append({
            "type": "Open Directories / Panels",
            "severity": "High",
            "description": f"Знайдено {len(directories)} відкритих шляхів",
            "fix": "Закрити доступ (403 Forbidden) до адмін-панелей."
        })

    if ports:
        results["findings"].append({
            "type": "Open Ports",
            "severity": "Medium",
            "description": f"Відкриті порти: {', '.join(map(str, ports))}",
            "fix": "Закрити непотрібні порти в firewall."
        })

    if redirect:
        results["findings"].append({
            "type": "Open Redirect",
            "severity": "Medium",
            "description": "Виявлено вразливість Open Redirect",
            "fix": "Валідувати та фільтрувати всі редиректи."
        })

    if tech:
        results["findings"].append({
            "type": "Technology Detected",
            "severity": "Info",
            "description": f"Виявлено: {tech}",
            "fix": "Оновити до останньої версії та перевірити відомі вразливості."
        })

    if waf:
        results["findings"].append({
            "type": "WAF Protection",
            "severity": "Info",
            "description": f"Захист: {waf}",
            "fix": "Перевірити правила WAF."
        })

    # Логування
    try:
        with open("logs/scans.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(results, ensure_ascii=False) + "\n")
    except:
        pass

    return results


# ====================== ULTRA МОДУЛІ ======================

async def check_security_headers(url: str, proxy=None):
    try:
        resp = await make_request(url, proxy)
        h = resp.headers
        checks = {
            "HSTS": "strict-transport-security" in h,
            "CSP": "content-security-policy" in h,
            "X-Frame": "x-frame-options" in h,
            "X-Content": "x-content-type-options" in h,
            "Referrer": "referrer-policy" in h
        }
        return {"missing": [k for k, v in checks.items() if not v]}
    except:
        return {"missing": []}

async def check_sensitive_files(url: str, proxy=None):
    base = url.rstrip("/")
    files = [".env", "wp-config.php", ".git/HEAD", "config.php", "backup.sql", "phpinfo.php", "info.php"]
    found = []
    async with httpx.AsyncClient(proxy=proxy, timeout=7.0) as client:
        for f in files:
            try:
                r = await client.get(f"{base}/{f}")
                if r.status_code == 200 and len(r.text) > 30:
                    found.append(f)
            except:
                pass
    return found

async def basic_xss_test(url: str, proxy=None):
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>", "javascript:alert(1)"]
    results = []
    for p in payloads:
        try:
            test_url = f"{url}?q={p}" if "?" not in url else f"{url}&q={p}"
            resp = await make_request(test_url, proxy)
            if p in resp.text.lower():
                results.append(p)
        except:
            pass
    return results

async def advanced_sqli_test(url: str, proxy=None):
    payloads = ["' OR 1=1 --", "' UNION SELECT 1,2,3 --", "1' OR '1'='1"]
    for p in payloads:
        try:
            test_url = f"{url}?id={p}" if "?" not in url else f"{url}&id={p}"
            resp = await make_request(test_url, proxy)
            text = resp.text.lower()
            if any(x in text for x in ["syntax error", "mysql", "sql", "unclosed", "warning"]):
                return "Possible SQLi"
        except:
            pass
    return None

async def ultra_directory_brute(url: str, proxy=None):
    base = url.rstrip("/")
    found = []
    async with httpx.AsyncClient(proxy=proxy, timeout=6.0) as client:
        for path in COMMON_PATHS:
            try:
                r = await client.get(f"{base}/{path}")
                if r.status_code in (200, 301, 403):
                    found.append(path)
            except:
                pass
    return found

async def port_scan(url: str):
    try:
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        open_ports = []
        for port in [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.2)
                if sock.connect_ex((hostname, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports
    except:
        return []

async def waf_detection(url: str, proxy=None):
    try:
        resp = await make_request(url, proxy)
        h = resp.headers
        if "cloudflare" in str(h).lower() or "cf-ray" in h:
            return "Cloudflare"
        if "akamai" in str(h).lower():
            return "Akamai"
        if "server" in h and "nginx" in h.get("server", "").lower():
            return "Nginx (можливо з ModSecurity)"
        return "Не виявлено"
    except:
        return "Не виявлено"

async def open_redirect_test(url: str, proxy=None):
    payloads = ["//google.com", "https://google.com", "/\\/google.com"]
    for p in payloads:
        try:
            test_url = f"{url}?url={p}" if "?" not in url else f"{url}&url={p}"
            resp = await make_request(test_url, proxy)
            if resp.history and any("google.com" in str(r.url) for r in resp.history):
                return True
        except:
            pass
    return False

async def tech_detection(url: str, proxy=None):
    try:
        resp = await make_request(url, proxy)
        text = resp.text.lower()
        if "wp-content" in text or "wordpress" in text: return "WordPress"
        if "laravel" in text: return "Laravel"
        if "drupal" in text: return "Drupal"
        if "shopify" in text: return "Shopify"
        return None
    except:
        return None
