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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("logs", exist_ok=True)

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

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

    # Паралельні перевірки
    tasks = [
        check_security_headers(target_url, proxy),
        check_sensitive_files(target_url, proxy),
        basic_xss_test(target_url, proxy),
        basic_sqli_test(target_url, proxy)
    ]

    header_check, sensitive, xss, sqli = await asyncio.gather(*tasks)

    # Обробка результатів
    if header_check.get("missing"):
        results["findings"].append({"type": "Security Headers", "severity": "Medium", "description": f"Відсутні: {', '.join(header_check['missing'])}"})

    if sensitive:
        results["findings"].append({"type": "Sensitive Files", "severity": "High", "description": f"Знайдено {len(sensitive)} чутливих файлів"})

    if xss:
        results["findings"].append({"type": "Reflected XSS", "severity": "High", "description": f"Виявлено {len(xss)} вразливих payload'ів"})

    if sqli:
        results["findings"].append({"type": "SQL Injection", "severity": "Critical", "description": "Виявлено можливу SQL-ін'єкцію!"})

    if scan_type == "full":
        results["findings"].append({"type": "Розширений режим", "severity": "Info", "description": "Використовується проксі + розширені тести"})

    # Логування
    with open("logs/scans.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(results, ensure_ascii=False) + "\n")

    return results

# ==================== МОДУЛІ СКАНУВАННЯ ====================

async def check_security_headers(url: str, proxy: str = None):
    try:
        resp = await make_request(url, proxy)
        h = resp.headers
        checks = {
            "HSTS": "strict-transport-security" in h,
            "CSP": "content-security-policy" in h,
            "X-Frame": "x-frame-options" in h,
            "X-Content": "x-content-type-options" in h,
        }
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
    for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]:
        try:
            test_url = f"{url}?test={payload}"
            resp = await make_request(test_url, proxy)
            if payload in resp.text:
                results.append(payload)
        except:
            pass
    return results

async def basic_sqli_test(url: str, proxy: str = None):
    for payload in SQLI_PAYLOADS:
        try:
            test_url = f"{url}?id={payload}" if "?" not in url else f"{url}&id={payload}"
            resp = await make_request(test_url, proxy)
            if "syntax error" in resp.text.lower() or "mysql" in resp.text.lower() or "sql" in resp.text.lower():
                return True
        except:
            pass
    return False

@app.get("/logs")
async def get_logs():
    try:
        with open("logs/scans.log", "r", encoding="utf-8") as f:
            logs = f.readlines()[-50:]  # останні 50 записів
        return {"logs": logs}
    except:
        return {"logs": ["Логів ще немає."]}

@app.post("/clear-logs")
async def clear_logs():
    open("logs/scans.log", "w").close()
    return {"status": "Логи очищено"}
