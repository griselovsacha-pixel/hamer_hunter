from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import asyncio
import httpx
from bs4 import BeautifulSoup
from datetime import datetime
import os
import json
import random

app = FastAPI(title="Hamer Hunter")

# === Виправлення шляху для Render ===
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

# Створюємо папки
os.makedirs("logs", exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# Виправлений Jinja2Templates
templates = Jinja2Templates(directory=TEMPLATES_DIR)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
]

SQLI_PAYLOADS = ["' OR 1=1 --", "' UNION SELECT 1,2,3 --", "1' OR '1'='1"]

async def make_request(url: str, proxy: str = None):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    timeout = httpx.Timeout(15.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, proxy=proxy, headers=headers) as client:
        return await client.get(url)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# === SCAN ENDPOINT ===
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
        results["title"] = (soup.title.string.strip() if soup.title else "No title")
    except Exception as e:
        return JSONResponse({"error": f"Не вдалося підключитися: {str(e)}"}, status_code=400)

    # Паралельні задачі
    tasks = [
        check_security_headers(target_url, proxy),
        check_sensitive_files(target_url, proxy),
        basic_xss_test(target_url, proxy),
        basic_sqli_test(target_url, proxy)
    ]

    header_check, sensitive, xss, sqli = await asyncio.gather(*tasks)

    if header_check.get("missing"):
        results["findings"].append({"type": "Security Headers", "severity": "Medium", "description": f"Відсутні: {', '.join(header_check['missing'])}"})

    if sensitive:
        results["findings"].append({"type": "Sensitive Files", "severity": "High", "description": f"Знайдено {len(sensitive)} файлів"})

    if xss:
        results["findings"].append({"type": "Reflected XSS", "severity": "High", "description": f"Виявлено {len(xss)} payload'ів"})

    if sqli:
        results["findings"].append({"type": "SQL Injection", "severity": "Critical", "description": "Можлива SQL-ін'єкція виявлена!"})

    if scan_type == "full":
        results["findings"].append({"type": "Розширений режим", "severity": "Info", "description": "Проксі + розширені тести"})

    # Логування
    try:
        with open("logs/scans.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(results, ensure_ascii=False) + "\n")
    except:
        pass

    return results


# ==================== МОДУЛІ ====================
async def check_security_headers(url: str, proxy: str = None):
    try:
        resp = await make_request(url, proxy)
        h = resp.headers
        checks = {"HSTS": "strict-transport-security" in h, "CSP": "content-security-policy" in h,
                  "X-Frame": "x-frame-options" in h, "X-Content": "x-content-type-options" in h}
        return {"missing": [k for k, v in checks.items() if not v]}
    except:
        return {"missing": []}

async def check_sensitive_files(url: str, proxy: str = None):
    base = url.rstrip("/")
    files = [".env", ".git/HEAD", "wp-config.php", "config.php", "backup.sql", "administrator"]
    found = []
    async with httpx.AsyncClient(proxy=proxy, timeout=8.0) as client:
        for file in files:
            try:
                r = await client.get(f"{base}/{file}")
                if r.status_code == 200 and len(r.text) > 30:
                    found.append(file)
            except:
                pass
    return found

async def basic_xss_test(url: str, proxy: str = None):
    results = []
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
    for p in payloads:
        try:
            test_url = f"{url}?test={p}"
            resp = await make_request(test_url, proxy)
            if p in resp.text:
                results.append(p)
        except:
            pass
    return results

async def basic_sqli_test(url: str, proxy: str = None):
    for p in SQLI_PAYLOADS:
        try:
            test_url = f"{url}?id={p}" if "?" not in url else f"{url}&id={p}"
            resp = await make_request(test_url, proxy)
            lower_text = resp.text.lower()
            if any(x in lower_text for x in ["syntax error", "mysql", "sql", "unclosed quotation"]):
                return True
        except:
            pass
    return False

@app.get("/logs")
async def get_logs():
    try:
        with open("logs/scans.log", "r", encoding="utf-8") as f:
            return {"logs": f.readlines()[-30:]}
    except:
        return {"logs": ["Логів ще немає."]}

@app.post("/clear-logs")
async def clear_logs():
    open("logs/scans.log", "w").close()
    return {"status": "ok"}
