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

app = FastAPI(title="Hamer Hunter Ultra v2.1")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("logs", exist_ok=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
]

async def make_request(url: str, proxy: str = None):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    timeout = httpx.Timeout(10.0)
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
        return JSONResponse({"error": str(e)}, status_code=400)

    tasks = [
        check_security_headers(target_url, proxy),
        check_sensitive_files(target_url, proxy),
        xss_test(target_url, proxy),
        sqli_test_detailed(target_url, proxy),
        command_injection_detailed(target_url, proxy),
        lfi_test_detailed(target_url, proxy),
        ultra_brute(target_url, proxy),
        port_scan(target_url),
        waf_detection(target_url, proxy),
        open_redirect_test(target_url, proxy)
    ]

    h, sens, xss, sqli, cmdi, lfi, dirs, ports, waf, redir = await asyncio.gather(*tasks)

    # === ДЕТАЛЬНА ОБРОБКА ===
    if h.get("missing"):
        results["findings"].append({"type": "Security Headers", "severity": "Medium", "description": f"Відсутні: {', '.join(h['missing'])}", "fix": "Додати HSTS, CSP, X-Frame-Options тощо."})

    if sens:
        results["findings"].append({"type": "Sensitive Files", "severity": "Critical", "description": f"Знайдено: {', '.join(sens)}", "fix": "Видалити або заблокувати доступ."})

    if xss:
        results["findings"].append({"type": "Reflected XSS", "severity": "High", "description": f"Виявлено {len(xss)} XSS", "fix": "Екранувати всі виводи."})

    if sqli:
        results["findings"].append({
            "type": "SQL Injection", 
            "severity": "Critical", 
            "description": f"Тип: {sqli['type']} | Payload: {sqli['payload']}",
            "fix": "Перейти на Prepared Statements / ORM."
        })

    if cmdi:
        results["findings"].append({
            "type": "Command Injection", 
            "severity": "Critical", 
            "description": f"Тип: {cmdi['type']} | Payload: {cmdi['payload']}",
            "fix": "Фільтрувати всі системні команди (os.system, exec тощо)."
        })

    if lfi:
        results["findings"].append({
            "type": "Local File Inclusion (LFI)", 
            "severity": "Critical", 
            "description": f"Payload: {lfi['payload']}",
            "fix": "Фільтрувати параметри файлів, заборонити '../'."
        })

    if dirs:
        results["findings"].append({"type": "Open Paths", "severity": "High", "description": f"Знайдено {len(dirs)} шляхів", "fix": "Закрити 403 Forbidden."})

    if ports:
        results["findings"].append({"type": "Open Ports", "severity": "Medium", "description": f"Відкриті: {ports}", "fix": "Закрити firewall."})

    if redir:
        results["findings"].append({"type": "Open Redirect", "severity": "Medium", "description": "Виявлено Open Redirect", "fix": "Валідувати редиректи."})

    if waf:
        results["findings"].append({"type": "WAF", "severity": "Info", "description": f"Захист: {waf}"})

    # Логування
    with open("logs/scans.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(results, ensure_ascii=False) + "\n")

    return results


# ====================== ДЕТАЛЬНІ ТЕСТИ ======================

async def check_security_headers(url, proxy):
    try:
        r = await make_request(url, proxy)
        h = r.headers
        missing = [k for k, v in {"HSTS":"strict-transport-security" in h,"CSP":"content-security-policy" in h,"X-Frame":"x-frame-options" in h,"X-Content":"x-content-type-options" in h}.items() if not v]
        return {"missing": missing}
    except: return {"missing": []}

async def check_sensitive_files(url, proxy):
    base = url.rstrip("/")
    files = [".env", "wp-config.php", ".git/HEAD", "phpinfo.php"]
    found = []
    async with httpx.AsyncClient(proxy=proxy, timeout=7) as c:
        for f in files:
            try:
                r = await c.get(f"{base}/{f}")
                if r.status_code == 200 and len(r.text) > 40:
                    found.append(f)
            except: pass
    return found

async def xss_test(url, proxy):
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    found = []
    for p in payloads:
        try:
            r = await make_request(f"{url}?q={p}", proxy)
            if p.lower() in r.text.lower():
                found.append(p)
        except: pass
    return found

async def sqli_test_detailed(url, proxy):
    tests = [("' OR 1=1 --", "Classic Boolean"), ("' UNION SELECT 1,2,3 --", "Union Based")]
    for payload, ptype in tests:
        try:
            r = await make_request(f"{url}?id={payload}", proxy)
            text = r.text.lower()
            if any(x in text for x in ["syntax error", "mysql", "sql", "unclosed quotation", "warning"]):
                return {"type": ptype, "payload": payload}
        except: pass
    return None

async def command_injection_detailed(url, proxy):
    tests = [
        ("; whoami", "Linux Command"),
        ("& id", "Windows/Linux Command"),
        ("| dir", "Directory Listing")
    ]
    for payload, ptype in tests:
        try:
            r = await make_request(f"{url}?cmd={payload}", proxy)
            text = r.text.lower()
            if any(x in text for x in ["root", "uid=", "bin/", "administrator", "users"]):
                return {"type": ptype, "payload": payload}
        except: pass
    return None

async def lfi_test_detailed(url, proxy):
    payloads = ["../../etc/passwd", "....//....//etc/passwd", "/etc/passwd"]
    for p in payloads:
        try:
            r = await make_request(f"{url}?file={p}", proxy)
            if "root:" in r.text or "daemon:" in r.text:
                return {"payload": p}
        except: pass
    return None

async def ultra_brute(url, proxy):
    base = url.rstrip("/")
    found = []
    async with httpx.AsyncClient(proxy=proxy, timeout=6) as c:
        for path in ["admin", "wp-admin", "administrator", "login", "phpmyadmin", "api", "backup", "config"]:
            try:
                r = await c.get(f"{base}/{path}")
                if r.status_code in (200, 301, 403):
                    found.append(path)
            except: pass
    return found

async def port_scan(url):
    try:
        host = url.split("//")[-1].split("/")[0].split(":")[0]
        open_p = []
        for port in [80, 443, 22, 21, 3306, 8080, 8443]:
            s = socket.socket()
            s.settimeout(1.2)
            if s.connect_ex((host, port)) == 0:
                open_p.append(port)
            s.close()
        return open_p
    except: return []

async def waf_detection(url, proxy):
    try:
        r = await make_request(url, proxy)
        if "cloudflare" in str(r.headers).lower() or "cf-ray" in r.headers:
            return "Cloudflare"
        return "Не виявлено"
    except: return "Не виявлено"

async def open_redirect_test(url, proxy):
    try:
        r = await make_request(f"{url}?redirect=//google.com", proxy)
        if r.history and "google.com" in str(r.url):
            return True
    except: pass
    return False
