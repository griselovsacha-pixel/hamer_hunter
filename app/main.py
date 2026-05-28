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

app = FastAPI(title="Hamer Hunter")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("logs", exist_ok=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, 8443, 8888, 27017]

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
        "title": "No title",
        "status_code": None
    }

    try:
        resp = await make_request(target_url, proxy)
        results["status_code"] = resp.status_code
        soup = BeautifulSoup(resp.text, 'html.parser')
        results["title"] = soup.title.string.strip() if soup.title else "No title"
    except Exception as e:
        return JSONResponse({"error": f"Не вдалося підключитися: {str(e)}"}, status_code=400)

    # Паралельні завдання
    tasks = [
        check_security_headers(target_url, proxy),
        check_sensitive_files(target_url, proxy),
        basic_xss_test(target_url, proxy),
        advanced_sqli_test(target_url, proxy),
        directory_brute(target_url, proxy),
        tech_detection(target_url, proxy),
        port_scan(target_url, proxy),
        waf_detection(target_url, proxy)
    ]

    header_check, sensitive, xss, sqli, directories, tech, ports, waf = await asyncio.gather(*tasks)

    # === ОБРОБКА ЗНАХІДОК З РЕКОМЕНДАЦІЯМИ ===
    if header_check.get("missing"):
        results["findings"].append({
            "type": "Security Headers", "severity": "Medium",
            "description": f"Відсутні: {', '.join(header_check['missing'])}",
            "fix": "Додати HSTS, CSP, X-Frame-Options у конфігурацію сервера."
        })

    if sensitive:
        results["findings"].append({
            "type": "Sensitive Files", "severity": "Critical",
            "description": f"Знайдено: {', '.join(sensitive)}",
            "fix": "Заблокувати доступ через .htaccess / nginx config + видалити файли."
        })

    if xss:
        results["findings"].append({
            "type": "Reflected XSS", "severity": "High",
            "description": f"Виявлено {len(xss)} вразливих payload'ів",
            "fix": "Екранувати всі виводи (htmlspecialchars, шаблонизатори з autoescape)."
        })

    if sqli:
        results["findings"].append({
            "type": "SQL Injection", "severity": "Critical",
            "description": f"Тип: {sqli['type']} в параметрі",
            "fix": "Використовувати Prepared Statements / ORM. Ніколи не конкатенувати SQL."
        })

    if directories:
        results["findings"].append({
            "type": "Open Directories", "severity": "Medium",
            "description": f"Відкриті папки: {', '.join(directories[:6])}",
            "fix": "Налаштувати 403 Forbidden для всіх непотрібних директорій."
        })

    if tech:
        results["findings"].append({
            "type": "Technologies", "severity": "Info",
            "description": f"Виявлено: {tech}",
            "fix": "Оновити до останньої версії + перевірити відомі CVE."
        })

    if ports:
        open_ports = [f"{p}/tcp" for p in ports]
        results["findings"].append({
            "type": "Open Ports", "severity": "Medium",
            "description": f"Відкриті порти: {', '.join(open_ports)}",
            "fix": "Закрити непотрібні порти в firewall (ufw/firewalld)."
        })

    if waf:
        results["findings"].append({
            "type": "WAF Protection", "severity": "Info",
            "description": f"Виявлено захист: {waf}",
            "fix": "Перевірити правила WAF на пропуск вразливостей."
        })

    # Логування
    try:
        with open("logs/scans.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(results, ensure_ascii=False) + "\n")
    except:
        pass

    return results


# ====================== МОДУЛІ ======================

async def check_security_headers(url: str, proxy=None):
    try:
        resp = await make_request(url, proxy)
        h = resp.headers
        checks = {
            "HSTS": "strict-transport-security" in h,
            "CSP": "content-security-policy" in h,
            "X-Frame": "x-frame-options" in h,
            "X-Content": "x-content-type-options" in h,
            "Referrer-Policy": "referrer-policy" in h
        }
        return {"missing": [k for k, v in checks.items() if not v]}
    except:
        return {"missing": []}

async def check_sensitive_files(url: str, proxy=None):
    base = url.rstrip("/")
    files = [".env", "wp-config.php", ".git/HEAD", "config.php", "backup.sql", ".DS_Store"]
    found = []
    async with httpx.AsyncClient(proxy=proxy, timeout=7.0) as client:
        for f in files:
            try:
                r = await client.get(f"{base}/{f}")
                if r.status_code == 200 and len(r.text) > 25:
                    found.append(f)
            except:
                pass
    return found

async def basic_xss_test(url: str, proxy=None):
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
    results = []
    for p in payloads:
        try:
            test_url = f"{url}?q={p}"
            resp = await make_request(test_url, proxy)
            if p in resp.text:
                results.append(p)
        except:
            pass
    return results

async def advanced_sqli_test(url: str, proxy=None):
    for payload, ptype in [(" ' OR 1=1 --", "Classic"), ("' UNION SELECT 1,2 --", "Union")]:
        try:
            test_url = f"{url}?id={payload}" if "?" not in url else f"{url}&id={payload}"
            resp = await make_request(test_url, proxy)
            text = resp.text.lower()
            if any(err in text for err in ["syntax error", "mysql", "sql", "unclosed", "warning"]):
                return {"type": ptype, "param": "id"}
        except:
            pass
    return None

async def directory_brute(url: str, proxy=None):
    base = url.rstrip("/")
    dirs = ["admin", "wp-admin", "administrator", "login", "phpmyadmin", "backup", "test", "api"]
    found = []
    async with httpx.AsyncClient(proxy=proxy, timeout=6.0) as client:
        for d in dirs:
            try:
                r = await client.get(f"{base}/{d}")
                if r.status_code in (200, 301, 403):
                    found.append(d)
            except:
                pass
    return found

async def tech_detection(url: str, proxy=None):
    try:
        resp = await make_request(url, proxy)
        text = resp.text.lower()
        headers = resp.headers
        if "wp-content" in text or "wordpress" in text:
            return "WordPress"
        if "laravel" in text:
            return "Laravel"
        if "x-powered-by" in headers:
            return f"PHP ({headers.get('x-powered-by')})"
        return "Інше"
    except:
        return None

async def port_scan(url: str, proxy=None):   # Обмежений порт-скан
    try:
        hostname = url.split("//")[-1].split("/")[0].split(":")[0]
        open_ports = []
        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((hostname, port))
                if result == 0:
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
        headers = resp.headers
        server = headers.get("server", "").lower()
        if "cloudflare" in server or "cf-ray" in headers:
            return "Cloudflare"
        if "mod_security" in server or "owasp" in str(resp.text).lower():
            return "ModSecurity / OWASP"
        if "akamai" in server:
            return "Akamai"
        return "Не виявлено або інший"
    except:
        return "Не виявлено"
